"""Data models for npm_sentinel scan findings and reports.

This module defines the core dataclasses and enumerations used throughout
the npm_sentinel package to represent scan findings, severity levels,
check results, and aggregated scan reports.

Classes:
    Severity: Enumeration of finding severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFO)
    CheckType: Enumeration of scanner check categories
    Finding: A single security finding discovered during a scan
    CheckResult: The result of running a single check category
    ScanReport: Aggregated report containing all findings from a full scan
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    """Severity levels for security findings.

    Levels follow a standard vulnerability severity scale:
    - CRITICAL: Immediate threat requiring urgent action
    - HIGH: Significant risk that should be addressed soon
    - MEDIUM: Moderate risk worth investigating
    - LOW: Minor concern or informational finding
    - INFO: Purely informational, no direct risk
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    def __lt__(self, other: object) -> bool:
        """Enable ordering of severity levels from most to least severe."""
        if not isinstance(other, Severity):
            return NotImplemented
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        return order.index(self) > order.index(other)

    def __le__(self, other: object) -> bool:
        """Enable ordering of severity levels."""
        if not isinstance(other, Severity):
            return NotImplemented
        return self == other or self < other

    def __gt__(self, other: object) -> bool:
        """Enable ordering of severity levels."""
        if not isinstance(other, Severity):
            return NotImplemented
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        return order.index(self) < order.index(other)

    def __ge__(self, other: object) -> bool:
        """Enable ordering of severity levels."""
        if not isinstance(other, Severity):
            return NotImplemented
        return self == other or self > other

    @property
    def rich_style(self) -> str:
        """Return a Rich markup style string for this severity level."""
        styles: dict[Severity, str] = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "dim",
        }
        return styles.get(self, "white")

    @property
    def exit_code_weight(self) -> int:
        """Return the numeric weight used to compute exit codes.

        Higher weight means more critical; used to determine if CI should fail.
        """
        weights: dict[Severity, int] = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        return weights.get(self, 0)


class CheckType(str, Enum):
    """Categories of security checks performed by npm_sentinel.

    - TYPOSQUAT: Package name fuzzy-match against known legitimate packages
    - HOOK: Lifecycle script (postinstall, preinstall, etc.) analysis
    - MCP: Model Context Protocol server injection detection
    """

    TYPOSQUAT = "typosquat"
    HOOK = "hook"
    MCP = "mcp"


@dataclass
class Finding:
    """A single security finding discovered during a scan.

    Attributes:
        check_type: The category of check that produced this finding
        severity: How severe the finding is assessed to be
        package_name: The npm package name that triggered the finding
        title: A short human-readable title for the finding
        description: Detailed explanation of the finding and its risk
        evidence: Optional raw evidence string (e.g., the suspicious script content)
        source_file: Optional path to the file where the finding was located
        metadata: Optional dict of additional structured information
    """

    check_type: CheckType
    severity: Severity
    package_name: str
    title: str
    description: str
    evidence: str | None = None
    source_file: Path | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize this finding to a JSON-serializable dictionary.

        Returns:
            A dict with all finding fields, suitable for JSON output.
        """
        return {
            "check_type": self.check_type.value,
            "severity": self.severity.value,
            "package_name": self.package_name,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "source_file": str(self.source_file) if self.source_file else None,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        """Deserialize a Finding from a dictionary.

        Args:
            data: A dict as produced by ``to_dict()``.

        Returns:
            A new Finding instance.

        Raises:
            KeyError: If required keys are missing from the dict.
            ValueError: If enum values are invalid.
        """
        return cls(
            check_type=CheckType(data["check_type"]),
            severity=Severity(data["severity"]),
            package_name=data["package_name"],
            title=data["title"],
            description=data["description"],
            evidence=data.get("evidence"),
            source_file=Path(data["source_file"]) if data.get("source_file") else None,
            metadata=data.get("metadata", {}),
        )


@dataclass
class CheckResult:
    """The aggregated result of running a single check category.

    Attributes:
        check_type: The category of check this result represents
        findings: List of individual findings produced by this check
        packages_scanned: Number of packages examined during this check
        error: Optional error message if the check encountered a failure
    """

    check_type: CheckType
    findings: list[Finding] = field(default_factory=list)
    packages_scanned: int = 0
    error: str | None = None

    @property
    def has_findings(self) -> bool:
        """Return True if this check produced any findings."""
        return len(self.findings) > 0

    @property
    def critical_count(self) -> int:
        """Return the number of CRITICAL severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Return the number of HIGH severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        """Return the number of MEDIUM severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        """Return the number of LOW severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    def to_dict(self) -> dict[str, Any]:
        """Serialize this check result to a JSON-serializable dictionary.

        Returns:
            A dict with all check result fields.
        """
        return {
            "check_type": self.check_type.value,
            "findings": [f.to_dict() for f in self.findings],
            "packages_scanned": self.packages_scanned,
            "error": self.error,
        }


@dataclass
class ScanReport:
    """Aggregated report containing all findings from a complete npm_sentinel scan.

    Attributes:
        target_path: The root path that was scanned (directory containing package.json)
        scan_timestamp: ISO 8601 timestamp when the scan was initiated
        check_results: List of per-check results aggregated from all scanners
        typosquat_threshold: The similarity threshold used for typosquat detection (0-100)
        scanned_transitive: Whether transitive (node_modules) dependencies were scanned
    """

    target_path: Path
    scan_timestamp: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    check_results: list[CheckResult] = field(default_factory=list)
    typosquat_threshold: int = 80
    scanned_transitive: bool = True

    @property
    def all_findings(self) -> list[Finding]:
        """Return a flat list of all findings across all check results.

        Returns:
            All findings sorted by severity (most severe first).
        """
        findings: list[Finding] = []
        for result in self.check_results:
            findings.extend(result.findings)
        return sorted(findings, key=lambda f: f.severity, reverse=True)

    @property
    def total_findings(self) -> int:
        """Return the total count of all findings."""
        return sum(len(r.findings) for r in self.check_results)

    @property
    def total_packages_scanned(self) -> int:
        """Return the total number of packages examined across all checks."""
        return max(
            (r.packages_scanned for r in self.check_results),
            default=0,
        )

    @property
    def has_critical_or_high(self) -> bool:
        """Return True if any finding is CRITICAL or HIGH severity."""
        return any(
            f.severity in (Severity.CRITICAL, Severity.HIGH)
            for f in self.all_findings
        )

    @property
    def exit_code(self) -> int:
        """Compute the appropriate process exit code for CI/CD integration.

        Returns:
            0 if no critical or high findings, 1 if any critical/high findings exist,
            2 if any check encountered a fatal error.
        """
        if any(r.error for r in self.check_results):
            return 2
        if self.has_critical_or_high:
            return 1
        return 0

    @property
    def severity_counts(self) -> dict[str, int]:
        """Return a mapping of severity label to count across all findings.

        Returns:
            Dict with keys CRITICAL, HIGH, MEDIUM, LOW, INFO mapping to int counts.
        """
        counts: dict[str, int] = {
            Severity.CRITICAL.value: 0,
            Severity.HIGH.value: 0,
            Severity.MEDIUM.value: 0,
            Severity.LOW.value: 0,
            Severity.INFO.value: 0,
        }
        for finding in self.all_findings:
            counts[finding.severity.value] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        """Serialize this scan report to a JSON-serializable dictionary.

        Returns:
            A dict representation suitable for ``json.dumps()``.
        """
        return {
            "target_path": str(self.target_path),
            "scan_timestamp": self.scan_timestamp,
            "typosquat_threshold": self.typosquat_threshold,
            "scanned_transitive": self.scanned_transitive,
            "total_packages_scanned": self.total_packages_scanned,
            "total_findings": self.total_findings,
            "severity_counts": self.severity_counts,
            "exit_code": self.exit_code,
            "check_results": [r.to_dict() for r in self.check_results],
        }
