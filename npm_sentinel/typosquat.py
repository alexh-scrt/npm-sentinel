"""Fuzzy-match typosquat detection engine for npm package names.

This module implements the typosquat detection logic for npm_sentinel. It uses
the rapidfuzz library to perform fuzzy string matching between scanned package
names and the curated trusted packages database. Packages whose names are
similar (but not identical) to a trusted package name are flagged as potential
typosquats.

The detection engine supports configurable similarity thresholds and uses a
combination of string distance metrics to reduce false positives:

- Levenshtein ratio: Catches character substitutions, insertions, deletions
- Jaro-Winkler similarity: Weighted toward prefix matches (common typosquat
  pattern where attackers rely on front-of-name similarity)
- Token sort ratio: Handles word reordering within scoped packages

Public API:
    TyposquatDetector: Main class implementing the detection engine
    TyposquatMatch: Dataclass representing a single fuzzy match result
    check_package: Convenience function to check a single package name
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rapidfuzz import fuzz, process, utils as rf_utils

from npm_sentinel.models import CheckResult, CheckType, Finding, Severity
from npm_sentinel.trusted_packages import get_trusted_packages

# Default similarity threshold (0-100).  Packages scoring at or above this
# value against any trusted package are flagged (unless they are an exact match).
DEFAULT_THRESHOLD: int = 80

# Scope prefix pattern: @scope/name
_SCOPED_RE = re.compile(r"^@([^/]+)/(.+)$")


@dataclass
class TyposquatMatch:
    """Represents a single fuzzy-match result for a package name.

    Attributes:
        candidate: The scanned package name being evaluated
        matched_package: The trusted package name it closely resembles
        score: Similarity score in the range 0-100
        is_exact: True when candidate == matched_package (not a typosquat)
    """

    candidate: str
    matched_package: str
    score: float
    is_exact: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize this match result to a JSON-serializable dictionary.

        Returns:
            Dict with candidate, matched_package, score, and is_exact keys.
        """
        return {
            "candidate": self.candidate,
            "matched_package": self.matched_package,
            "score": round(self.score, 2),
            "is_exact": self.is_exact,
        }


class TyposquatDetector:
    """Fuzzy-match typosquat detection engine.

    Uses rapidfuzz string similarity metrics to compare scanned npm package
    names against the curated trusted packages database. Packages that score
    at or above the configured threshold (but are NOT an exact match) are
    flagged as potential typosquats.

    Attributes:
        threshold: Minimum similarity score (0-100) to flag a package
        trusted_packages: The reference set of known-legitimate package names

    Example::

        detector = TyposquatDetector(threshold=80)
        result = detector.check_packages(["expresss", "lodahs", "react"])
        for finding in result.findings:
            print(finding.title, finding.severity)
    """

    def __init__(
        self,
        threshold: int = DEFAULT_THRESHOLD,
        trusted_packages: frozenset[str] | None = None,
    ) -> None:
        """Initialise the detector.

        Args:
            threshold: Similarity score (0-100) at or above which a package is
                flagged as a potential typosquat. Defaults to 80.
            trusted_packages: Override the default trusted package set. When
                None the built-in curated list is used.
        """
        if not (0 <= threshold <= 100):
            raise ValueError(f"threshold must be between 0 and 100, got {threshold}")
        self.threshold: int = threshold
        self.trusted_packages: frozenset[str] = (
            trusted_packages if trusted_packages is not None else get_trusted_packages()
        )
        # Pre-build sorted list for process.extractOne
        self._trusted_list: list[str] = sorted(self.trusted_packages)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def check_packages(
        self,
        package_names: list[str],
        source_file: Path | None = None,
    ) -> CheckResult:
        """Run typosquat checks on a list of package names.

        Iterates over each name, skips trusted packages that are an exact
        match in the database, and flags near-matches as findings.

        Args:
            package_names: List of npm package names to check (may include
                scoped packages like ``@scope/name``).
            source_file: Optional path to the file from which these names were
                extracted (e.g. ``package.json``). Stored on each finding.

        Returns:
            A CheckResult containing one Finding per detected typosquat.
        """
        result = CheckResult(
            check_type=CheckType.TYPOSQUAT,
            packages_scanned=len(package_names),
        )

        for name in package_names:
            if not name or not isinstance(name, str):
                continue
            match = self._check_single(name)
            if match is None:
                continue
            if match.is_exact:
                # Exact match – it IS a trusted package, not a typosquat
                continue
            finding = self._build_finding(match, source_file)
            result.findings.append(finding)

        return result

    def find_best_match(self, package_name: str) -> TyposquatMatch | None:
        """Find the closest matching trusted package for a given name.

        Args:
            package_name: The npm package name to look up.

        Returns:
            A TyposquatMatch if a match at or above the threshold is found,
            or None if no close enough match exists.
        """
        return self._check_single(package_name)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _normalise_name(self, name: str) -> str:
        """Normalise an npm package name for comparison.

        Strips scope prefix from scoped packages (``@scope/name`` → ``name``)
        and lower-cases the result to ensure case-insensitive comparison.

        Args:
            name: Raw npm package name, possibly scoped.

        Returns:
            Normalised name string.
        """
        name = name.strip().lower()
        m = _SCOPED_RE.match(name)
        if m:
            # Compare the un-scoped part against the trusted list
            return m.group(2)
        return name

    def _compute_composite_score(self, name_a: str, name_b: str) -> float:
        """Compute a composite similarity score between two package names.

        Combines three rapidfuzz metrics with fixed weights:
        - 50 % Levenshtein ratio  (general edit distance)
        - 30 % Jaro-Winkler       (prefix-sensitive; common typosquat pattern)
        - 20 % Token sort ratio   (handles reordering in compound names)

        Args:
            name_a: First package name (already normalised).
            name_b: Second package name (already normalised).

        Returns:
            Weighted composite score in the range 0-100.
        """
        ratio = fuzz.ratio(name_a, name_b)
        jaro = fuzz.WRatio(name_a, name_b)  # WRatio includes Jaro-Winkler internally
        token_sort = fuzz.token_sort_ratio(name_a, name_b)
        return 0.50 * ratio + 0.30 * jaro + 0.20 * token_sort

    def _check_single(self, package_name: str) -> TyposquatMatch | None:
        """Check a single package name against the trusted database.

        Uses rapidfuzz's ``process.extractOne`` for fast candidate retrieval,
        then verifies with the composite score. Returns None if no match at or
        above the threshold is found.

        Args:
            package_name: The npm package name to evaluate.

        Returns:
            A TyposquatMatch or None.
        """
        normalised = self._normalise_name(package_name)

        if not normalised:
            return None

        # Fast path: exact hit in the trusted set (check original first, then
        # normalised name, then the scoped form)
        if package_name.lower() in self.trusted_packages:
            return TyposquatMatch(
                candidate=package_name,
                matched_package=package_name.lower(),
                score=100.0,
                is_exact=True,
            )
        if normalised in self.trusted_packages:
            return TyposquatMatch(
                candidate=package_name,
                matched_package=normalised,
                score=100.0,
                is_exact=True,
            )

        # Use process.extractOne with Levenshtein for fast top-candidate
        best = process.extractOne(
            normalised,
            self._trusted_list,
            scorer=fuzz.ratio,
            score_cutoff=self.threshold - 15,  # slightly lower to allow composite re-scoring
            processor=rf_utils.default_process,
        )

        if best is None:
            return None

        best_name: str = best[0]
        best_score: float = best[1]

        # Re-score using composite metric for accuracy
        composite = self._compute_composite_score(normalised, best_name)

        # Use the higher of the two scores
        final_score = max(best_score, composite)

        if final_score < self.threshold:
            return None

        # Exact after normalisation?
        is_exact = normalised == best_name

        return TyposquatMatch(
            candidate=package_name,
            matched_package=best_name,
            score=final_score,
            is_exact=is_exact,
        )

    def _build_finding(self, match: TyposquatMatch, source_file: Path | None) -> Finding:
        """Construct a Finding from a TyposquatMatch.

        Determines severity based on the similarity score:
        - CRITICAL: score >= 95 (very high confidence typosquat)
        - HIGH:     score >= 85
        - MEDIUM:   score >= threshold (lower confidence)

        Args:
            match: The TyposquatMatch to convert.
            source_file: File path to embed in the finding.

        Returns:
            A Finding dataclass instance.
        """
        severity = self._score_to_severity(match.score)
        description = (
            f"Package '{match.candidate}' closely resembles the trusted package "
            f"'{match.matched_package}' with a similarity score of {match.score:.1f}/100. "
            f"This may indicate a typosquatting attack where an attacker has published "
            f"a malicious package with a name very similar to a popular legitimate package."
        )
        return Finding(
            check_type=CheckType.TYPOSQUAT,
            severity=severity,
            package_name=match.candidate,
            title=f"Potential typosquat: '{match.candidate}' resembles '{match.matched_package}'",
            description=description,
            evidence=match.candidate,
            source_file=source_file,
            metadata=match.to_dict(),
        )

    @staticmethod
    def _score_to_severity(score: float) -> Severity:
        """Map a similarity score to a Severity level.

        Args:
            score: Composite similarity score in 0-100 range.

        Returns:
            Severity.CRITICAL for score >= 95, HIGH for >= 85, MEDIUM otherwise.
        """
        if score >= 95:
            return Severity.CRITICAL
        if score >= 85:
            return Severity.HIGH
        return Severity.MEDIUM


def check_package(
    package_name: str,
    threshold: int = DEFAULT_THRESHOLD,
    trusted_packages: frozenset[str] | None = None,
) -> TyposquatMatch | None:
    """Convenience function to check a single package name for typosquatting.

    Creates a temporary TyposquatDetector instance and runs a single check.
    For bulk checks prefer creating a TyposquatDetector instance directly
    to avoid rebuilding the internal state on every call.

    Args:
        package_name: The npm package name to evaluate.
        threshold: Similarity threshold (0-100). Defaults to 80.
        trusted_packages: Optional override for the trusted package set.

    Returns:
        A TyposquatMatch if the package is a potential typosquat, else None.

    Example::

        >>> match = check_package('expresss')
        >>> match is not None
        True
        >>> match.matched_package
        'express'
    """
    detector = TyposquatDetector(threshold=threshold, trusted_packages=trusted_packages)
    return detector.find_best_match(package_name)
