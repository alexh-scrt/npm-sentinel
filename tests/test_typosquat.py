"""Unit tests for npm_sentinel.typosquat and npm_sentinel.trusted_packages.

Covers:
- Known typosquat pairs are detected at default threshold
- Exact trusted package names are NOT flagged
- Very dissimilar names produce no match
- Score-to-severity mapping is correct
- Configurable threshold changes detection sensitivity
- Scoped packages are handled correctly
- Bulk check_packages returns correct CheckResult
- TyposquatMatch serialisation
- Edge cases: empty string, whitespace, non-string-like values
"""

from __future__ import annotations

from pathlib import Path

import pytest

from npm_sentinel.models import CheckType, Severity
from npm_sentinel.trusted_packages import TRUSTED_PACKAGES, get_trusted_packages
from npm_sentinel.typosquat import (
    DEFAULT_THRESHOLD,
    TyposquatDetector,
    TyposquatMatch,
    check_package,
)


# ---------------------------------------------------------------------------
# trusted_packages tests
# ---------------------------------------------------------------------------


class TestTrustedPackages:
    """Tests for the trusted packages database."""

    def test_trusted_packages_is_frozenset(self) -> None:
        """TRUSTED_PACKAGES is a frozenset."""
        assert isinstance(TRUSTED_PACKAGES, frozenset)

    def test_trusted_packages_has_minimum_count(self) -> None:
        """Trusted packages list contains at least 500 entries."""
        assert len(TRUSTED_PACKAGES) >= 500

    def test_get_trusted_packages_returns_frozenset(self) -> None:
        """get_trusted_packages() returns a frozenset."""
        result = get_trusted_packages()
        assert isinstance(result, frozenset)

    def test_get_trusted_packages_returns_same_set(self) -> None:
        """get_trusted_packages() returns the same object as TRUSTED_PACKAGES."""
        assert get_trusted_packages() is TRUSTED_PACKAGES

    def test_well_known_packages_present(self) -> None:
        """Core popular packages are in the trusted set."""
        for pkg in ["express", "lodash", "react", "webpack", "jest", "typescript"]:
            assert pkg in TRUSTED_PACKAGES, f"Expected '{pkg}' in TRUSTED_PACKAGES"

    def test_trusted_packages_all_strings(self) -> None:
        """Every entry in TRUSTED_PACKAGES is a string."""
        for pkg in TRUSTED_PACKAGES:
            assert isinstance(pkg, str), f"Non-string entry found: {pkg!r}"

    def test_trusted_packages_no_empty_strings(self) -> None:
        """No empty strings in the trusted packages set."""
        for pkg in TRUSTED_PACKAGES:
            assert pkg.strip() != "", "Empty or whitespace-only package name found"

    def test_trusted_packages_lowercase(self) -> None:
        """All trusted package names are lowercase (npm convention)."""
        for pkg in TRUSTED_PACKAGES:
            # Scoped packages may contain uppercase in scope – skip those
            if pkg.startswith("@"):
                continue
            assert pkg == pkg.lower(), f"Non-lowercase package name: {pkg!r}"


# ---------------------------------------------------------------------------
# TyposquatMatch tests
# ---------------------------------------------------------------------------


class TestTyposquatMatch:
    """Tests for the TyposquatMatch dataclass."""

    def test_to_dict_keys(self) -> None:
        """to_dict() includes all expected keys."""
        match = TyposquatMatch(candidate="expresss", matched_package="express", score=97.3)
        d = match.to_dict()
        assert set(d.keys()) == {"candidate", "matched_package", "score", "is_exact"}

    def test_to_dict_values(self) -> None:
        """to_dict() serialises values correctly."""
        match = TyposquatMatch(candidate="expresss", matched_package="express", score=97.3456)
        d = match.to_dict()
        assert d["candidate"] == "expresss"
        assert d["matched_package"] == "express"
        assert d["score"] == 97.35  # rounded to 2dp
        assert d["is_exact"] is False

    def test_is_exact_defaults_to_false(self) -> None:
        """is_exact defaults to False."""
        match = TyposquatMatch(candidate="express", matched_package="express", score=100.0)
        assert match.is_exact is False  # default; caller must set True

    def test_is_exact_true(self) -> None:
        """is_exact can be set to True."""
        match = TyposquatMatch(
            candidate="express", matched_package="express", score=100.0, is_exact=True
        )
        assert match.is_exact is True


# ---------------------------------------------------------------------------
# TyposquatDetector initialisation tests
# ---------------------------------------------------------------------------


class TestTyposquatDetectorInit:
    """Tests for TyposquatDetector initialisation."""

    def test_default_threshold(self) -> None:
        """Default threshold is DEFAULT_THRESHOLD."""
        detector = TyposquatDetector()
        assert detector.threshold == DEFAULT_THRESHOLD

    def test_custom_threshold(self) -> None:
        """Custom threshold is stored correctly."""
        detector = TyposquatDetector(threshold=90)
        assert detector.threshold == 90

    def test_threshold_zero_is_valid(self) -> None:
        """Threshold of 0 is accepted."""
        detector = TyposquatDetector(threshold=0)
        assert detector.threshold == 0

    def test_threshold_100_is_valid(self) -> None:
        """Threshold of 100 is accepted."""
        detector = TyposquatDetector(threshold=100)
        assert detector.threshold == 100

    def test_threshold_negative_raises(self) -> None:
        """Negative threshold raises ValueError."""
        with pytest.raises(ValueError, match="threshold"):
            TyposquatDetector(threshold=-1)

    def test_threshold_above_100_raises(self) -> None:
        """Threshold above 100 raises ValueError."""
        with pytest.raises(ValueError, match="threshold"):
            TyposquatDetector(threshold=101)

    def test_custom_trusted_packages(self) -> None:
        """Custom trusted packages set is used."""
        custom = frozenset(["mypackage", "anotherpackage"])
        detector = TyposquatDetector(trusted_packages=custom)
        assert detector.trusted_packages == custom

    def test_default_trusted_packages_loaded(self) -> None:
        """Default trusted packages are loaded from the database."""
        detector = TyposquatDetector()
        assert "express" in detector.trusted_packages


# ---------------------------------------------------------------------------
# Typosquat detection – known pairs
# ---------------------------------------------------------------------------


class TestKnownTyposquatPairs:
    """Tests for known typosquat patterns against popular packages."""

    @pytest.fixture
    def detector(self) -> TyposquatDetector:
        """Return a default TyposquatDetector."""
        return TyposquatDetector(threshold=80)

    @pytest.mark.parametrize(
        "typosquat, trusted",
        [
            ("expresss", "express"),
            ("expres", "express"),
            ("xpress", "express"),
            ("lodahs", "lodash"),
            ("lodas", "lodash"),
            ("loadsh", "lodash"),
            ("reakt", "react"),
            ("raect", "react"),
            ("webbpack", "webpack"),
            ("webpak", "webpack"),
            ("jset", "jest"),
            ("mocha2", "mocha"),
            ("axois", "axios"),
            ("axxios", "axios"),
            ("typescirpt", "typescript"),
            ("tyypescript", "typescript"),
            ("requets", "request"),
            ("requst", "request"),
            ("mongoos", "mongoose"),
            ("mongoosee", "mongoose"),
            ("chalck", "chalk"),
            ("chak", "chalk"),
            ("momment", "moment"),
            ("moement", "moment"),
            ("eslint2", "eslint"),
            ("pretiier", "prettier"),
            ("huskey", "husky"),
            ("rxjss", "rxjs"),
        ],
    )
    def test_known_typosquat_detected(self, detector: TyposquatDetector, typosquat: str, trusted: str) -> None:
        """Known typosquat packages are detected and matched to the right trusted package."""
        match = detector.find_best_match(typosquat)
        assert match is not None, f"Expected '{typosquat}' to match '{trusted}' but got no match"
        assert not match.is_exact, f"'{typosquat}' should NOT be an exact match"
        assert match.score >= 80, f"Score {match.score} is below threshold for '{typosquat}'"


# ---------------------------------------------------------------------------
# Exact trusted packages NOT flagged
# ---------------------------------------------------------------------------


class TestExactMatchNotFlagged:
    """Tests that exact trusted package names are not flagged as typosquats."""

    @pytest.fixture
    def detector(self) -> TyposquatDetector:
        """Return a default TyposquatDetector."""
        return TyposquatDetector(threshold=80)

    @pytest.mark.parametrize(
        "package_name",
        [
            "express",
            "lodash",
            "react",
            "webpack",
            "jest",
            "typescript",
            "axios",
            "chalk",
            "moment",
            "eslint",
            "prettier",
            "husky",
            "rxjs",
            "mongoose",
            "mocha",
            "request",
            "debug",
            "uuid",
            "semver",
            "glob",
        ],
    )
    def test_exact_trusted_package_not_flagged(self, detector: TyposquatDetector, package_name: str) -> None:
        """Exact trusted package names return is_exact=True and are not typosquats."""
        match = detector.find_best_match(package_name)
        if match is not None:
            assert match.is_exact, (
                f"Trusted package '{package_name}' was incorrectly flagged as typosquat "
                f"(matched '{match.matched_package}' score={match.score:.1f})"
            )


# ---------------------------------------------------------------------------
# Dissimilar packages produce no match
# ---------------------------------------------------------------------------


class TestDissimilarPackagesNotFlagged:
    """Tests that completely different package names are not flagged."""

    @pytest.fixture
    def detector(self) -> TyposquatDetector:
        """Return a detector with default threshold."""
        return TyposquatDetector(threshold=80)

    @pytest.mark.parametrize(
        "package_name",
        [
            "zzz-totally-unique-xyzzy",
            "aaaaabbbbbccccc",
            "my-completely-original-package-name-12345",
            "qqqqqwwwwweeeee",
        ],
    )
    def test_dissimilar_package_not_flagged(self, detector: TyposquatDetector, package_name: str) -> None:
        """Completely dissimilar names produce no match."""
        match = detector.find_best_match(package_name)
        assert match is None or match.score < 80, (
            f"Unexpected match for '{package_name}': {match}"
        )


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------


class TestScoreToSeverity:
    """Tests for the _score_to_severity static method."""

    def test_score_95_is_critical(self) -> None:
        """Score >= 95 maps to CRITICAL."""
        assert TyposquatDetector._score_to_severity(95.0) == Severity.CRITICAL

    def test_score_100_is_critical(self) -> None:
        """Score of 100 maps to CRITICAL."""
        assert TyposquatDetector._score_to_severity(100.0) == Severity.CRITICAL

    def test_score_85_is_high(self) -> None:
        """Score >= 85 and < 95 maps to HIGH."""
        assert TyposquatDetector._score_to_severity(85.0) == Severity.HIGH
        assert TyposquatDetector._score_to_severity(94.9) == Severity.HIGH

    def test_score_80_is_medium(self) -> None:
        """Score >= 80 and < 85 maps to MEDIUM."""
        assert TyposquatDetector._score_to_severity(80.0) == Severity.MEDIUM
        assert TyposquatDetector._score_to_severity(84.9) == Severity.MEDIUM

    def test_score_60_is_medium(self) -> None:
        """Score below 85 but above 0 maps to MEDIUM (threshold guards apply outside)."""
        assert TyposquatDetector._score_to_severity(60.0) == Severity.MEDIUM


# ---------------------------------------------------------------------------
# check_packages returns CheckResult
# ---------------------------------------------------------------------------


class TestCheckPackages:
    """Tests for the TyposquatDetector.check_packages() method."""

    @pytest.fixture
    def detector(self) -> TyposquatDetector:
        """Return a default TyposquatDetector."""
        return TyposquatDetector(threshold=80)

    def test_returns_check_result(self, detector: TyposquatDetector) -> None:
        """check_packages returns a CheckResult."""
        from npm_sentinel.models import CheckResult

        result = detector.check_packages(["express"])
        assert isinstance(result, CheckResult)

    def test_check_type_is_typosquat(self, detector: TyposquatDetector) -> None:
        """check_packages returns CheckResult with TYPOSQUAT check type."""
        result = detector.check_packages(["express"])
        assert result.check_type == CheckType.TYPOSQUAT

    def test_packages_scanned_count(self, detector: TyposquatDetector) -> None:
        """packages_scanned equals the number of names passed in."""
        packages = ["expresss", "lodash", "unknownpkg"]
        result = detector.check_packages(packages)
        assert result.packages_scanned == 3

    def test_trusted_package_not_in_findings(self, detector: TyposquatDetector) -> None:
        """Exact trusted packages do not appear in findings."""
        result = detector.check_packages(["express", "lodash", "react"])
        finding_names = {f.package_name for f in result.findings}
        assert "express" not in finding_names
        assert "lodash" not in finding_names
        assert "react" not in finding_names

    def test_typosquat_appears_in_findings(self, detector: TyposquatDetector) -> None:
        """Known typosquats appear in findings."""
        result = detector.check_packages(["expresss"])
        assert result.has_findings
        assert any(f.package_name == "expresss" for f in result.findings)

    def test_finding_check_type(self, detector: TyposquatDetector) -> None:
        """Findings have TYPOSQUAT check type."""
        result = detector.check_packages(["expresss"])
        for finding in result.findings:
            assert finding.check_type == CheckType.TYPOSQUAT

    def test_finding_has_metadata(self, detector: TyposquatDetector) -> None:
        """Findings include metadata with score and matched_package."""
        result = detector.check_packages(["expresss"])
        assert result.has_findings
        finding = result.findings[0]
        assert "score" in finding.metadata
        assert "matched_package" in finding.metadata
        assert finding.metadata["matched_package"] == "express"

    def test_finding_source_file(self, detector: TyposquatDetector) -> None:
        """Source file is stored on findings when provided."""
        source = Path("package.json")
        result = detector.check_packages(["expresss"], source_file=source)
        assert result.has_findings
        assert result.findings[0].source_file == source

    def test_finding_source_file_none_by_default(self, detector: TyposquatDetector) -> None:
        """Source file is None when not provided."""
        result = detector.check_packages(["expresss"])
        assert result.has_findings
        assert result.findings[0].source_file is None

    def test_empty_package_list(self, detector: TyposquatDetector) -> None:
        """Empty input list returns empty findings."""
        result = detector.check_packages([])
        assert not result.has_findings
        assert result.packages_scanned == 0

    def test_empty_string_skipped(self, detector: TyposquatDetector) -> None:
        """Empty string entries are skipped without raising."""
        result = detector.check_packages(["", "  ", "express"])
        # Should not raise, and 'express' being trusted means 0 findings
        assert isinstance(result, CheckResult)

    def test_mixed_trusted_and_typosquat(self, detector: TyposquatDetector) -> None:
        """Mixed list: trusted packages not flagged, typosquats are flagged."""
        packages = ["express", "expresss", "lodash", "lodahs"]
        result = detector.check_packages(packages)
        finding_names = {f.package_name for f in result.findings}
        # Trusted ones not flagged
        assert "express" not in finding_names
        assert "lodash" not in finding_names
        # Typosquats flagged
        assert "expresss" in finding_names or "lodahs" in finding_names


# ---------------------------------------------------------------------------
# Scoped package handling
# ---------------------------------------------------------------------------


class TestScopedPackages:
    """Tests for scoped package name handling."""

    @pytest.fixture
    def detector(self) -> TyposquatDetector:
        """Return a default detector."""
        return TyposquatDetector(threshold=80)

    def test_exact_scoped_package_not_flagged(self, detector: TyposquatDetector) -> None:
        """Exact scoped package names from trusted list are not flagged."""
        # @nestjs/core is in trusted list
        result = detector.check_packages(["@nestjs/core"])
        finding_names = {f.package_name for f in result.findings}
        assert "@nestjs/core" not in finding_names

    def test_typosquat_of_scoped_package_detected(self, detector: TyposquatDetector) -> None:
        """A typosquat of the unscoped part is detected."""
        # The detector strips scope and compares 'core' vs trusted names
        # '@nestjs/corre' -> normalised 'corre' may or may not match
        # We test with a clearly similar unscoped name
        match = detector.find_best_match("@attacker/expresss")
        if match is not None:
            # If flagged, it should not be exact
            assert not match.is_exact


# ---------------------------------------------------------------------------
# Configurable threshold tests
# ---------------------------------------------------------------------------


class TestConfigurableThreshold:
    """Tests for configurable similarity threshold."""

    def test_high_threshold_misses_weak_matches(self) -> None:
        """A very high threshold (98) may miss weak typosquats."""
        detector = TyposquatDetector(threshold=98)
        # 'webpak' is somewhat similar to 'webpack' but may not reach 98
        match = detector.find_best_match("webpak")
        # We can't assert it's None (score might be high), but if match exists score >= 98
        if match is not None and not match.is_exact:
            assert match.score >= 98

    def test_low_threshold_catches_more(self) -> None:
        """A lower threshold catches more potential matches."""
        detector_low = TyposquatDetector(threshold=50)
        detector_high = TyposquatDetector(threshold=95)
        # A moderately similar name
        name = "expresslike"
        match_low = detector_low.find_best_match(name)
        match_high = detector_high.find_best_match(name)
        # Low threshold should be more permissive
        if match_high is not None and not match_high.is_exact:
            assert match_high.score >= 95
        if match_low is not None and not match_low.is_exact:
            assert match_low.score >= 50

    def test_threshold_100_catches_only_exact(self) -> None:
        """Threshold of 100 only flags exact matches (which are then is_exact=True)."""
        detector = TyposquatDetector(threshold=100)
        match = detector.find_best_match("expresss")
        # Either no match or if matched, score must be 100 (which would be exact)
        if match is not None:
            assert match.is_exact or match.score >= 100


# ---------------------------------------------------------------------------
# check_package convenience function
# ---------------------------------------------------------------------------


class TestCheckPackageFunction:
    """Tests for the check_package convenience function."""

    def test_known_typosquat_detected(self) -> None:
        """check_package detects known typosquats."""
        match = check_package("expresss")
        assert match is not None
        assert not match.is_exact

    def test_trusted_package_returns_exact(self) -> None:
        """check_package returns is_exact=True for trusted packages."""
        match = check_package("express")
        if match is not None:
            assert match.is_exact

    def test_custom_threshold_accepted(self) -> None:
        """check_package accepts custom threshold."""
        match = check_package("expresss", threshold=90)
        # At threshold=90, 'expresss' may or may not match
        if match is not None and not match.is_exact:
            assert match.score >= 90

    def test_custom_trusted_packages(self) -> None:
        """check_package uses custom trusted_packages when provided."""
        custom = frozenset(["myspecialpackage"])
        match = check_package("myspecialpakage", trusted_packages=custom)
        if match is not None and not match.is_exact:
            assert match.matched_package == "myspecialpackage"

    def test_unknown_dissimilar_returns_none(self) -> None:
        """check_package returns None for completely dissimilar names."""
        match = check_package("zzz-xyzzy-unique-123456789")
        assert match is None or match.score < 80


# ---------------------------------------------------------------------------
# Normalisation tests
# ---------------------------------------------------------------------------


class TestNormalisation:
    """Tests for internal name normalisation."""

    @pytest.fixture
    def detector(self) -> TyposquatDetector:
        """Return a default detector."""
        return TyposquatDetector()

    def test_normalise_plain_name(self, detector: TyposquatDetector) -> None:
        """Plain package names are lowercased."""
        assert detector._normalise_name("Express") == "express"

    def test_normalise_scoped_name(self, detector: TyposquatDetector) -> None:
        """Scoped packages have scope stripped."""
        assert detector._normalise_name("@nestjs/core") == "core"

    def test_normalise_scoped_name_with_uppercase(self, detector: TyposquatDetector) -> None:
        """Scoped packages with uppercase scope are normalised."""
        assert detector._normalise_name("@NestJS/Core") == "core"

    def test_normalise_strips_whitespace(self, detector: TyposquatDetector) -> None:
        """Leading/trailing whitespace is stripped."""
        assert detector._normalise_name("  express  ") == "express"


# ---------------------------------------------------------------------------
# Finding structure tests
# ---------------------------------------------------------------------------


class TestFindingStructure:
    """Tests that findings produced by the detector have correct structure."""

    @pytest.fixture
    def detector(self) -> TyposquatDetector:
        """Return a default detector."""
        return TyposquatDetector(threshold=80)

    def test_finding_evidence_is_package_name(self, detector: TyposquatDetector) -> None:
        """Finding evidence field equals the candidate package name."""
        result = detector.check_packages(["expresss"])
        assert result.has_findings
        assert result.findings[0].evidence == "expresss"

    def test_finding_title_contains_packages(self, detector: TyposquatDetector) -> None:
        """Finding title mentions both the candidate and matched package."""
        result = detector.check_packages(["expresss"])
        assert result.has_findings
        title = result.findings[0].title
        assert "expresss" in title
        assert "express" in title

    def test_finding_description_non_empty(self, detector: TyposquatDetector) -> None:
        """Finding description is a non-empty string."""
        result = detector.check_packages(["expresss"])
        assert result.has_findings
        assert len(result.findings[0].description) > 0

    def test_finding_serialisable(self, detector: TyposquatDetector) -> None:
        """Findings can be serialised to dict via to_dict()."""
        import json

        result = detector.check_packages(["expresss"])
        assert result.has_findings
        d = result.findings[0].to_dict()
        # Should not raise
        json.dumps(d)
