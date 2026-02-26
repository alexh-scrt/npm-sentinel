"""Unit tests for npm_sentinel.models module.

Verifies that Finding, CheckResult, ScanReport, Severity, and CheckType
behave correctly including serialization, ordering, and computed properties.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from npm_sentinel.models import (
    CheckResult,
    CheckType,
    Finding,
    ScanReport,
    Severity,
)


class TestSeverity:
    """Tests for the Severity enumeration."""

    def test_severity_values(self) -> None:
        """All severity levels have expected string values."""
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"
        assert Severity.INFO.value == "INFO"

    def test_severity_ordering_critical_greater_than_high(self) -> None:
        """CRITICAL is more severe than HIGH."""
        assert Severity.CRITICAL > Severity.HIGH

    def test_severity_ordering_high_greater_than_medium(self) -> None:
        """HIGH is more severe than MEDIUM."""
        assert Severity.HIGH > Severity.MEDIUM

    def test_severity_ordering_medium_greater_than_low(self) -> None:
        """MEDIUM is more severe than LOW."""
        assert Severity.MEDIUM > Severity.LOW

    def test_severity_ordering_low_greater_than_info(self) -> None:
        """LOW is more severe than INFO."""
        assert Severity.LOW > Severity.INFO

    def test_severity_ordering_info_less_than_critical(self) -> None:
        """INFO is less severe than CRITICAL."""
        assert Severity.INFO < Severity.CRITICAL

    def test_severity_equality(self) -> None:
        """Same severity levels are equal."""
        assert Severity.HIGH == Severity.HIGH
        assert Severity.LOW == Severity.LOW

    def test_severity_less_than_or_equal(self) -> None:
        """Less-than-or-equal comparison works."""
        assert Severity.INFO <= Severity.CRITICAL
        assert Severity.HIGH <= Severity.HIGH

    def test_severity_greater_than_or_equal(self) -> None:
        """Greater-than-or-equal comparison works."""
        assert Severity.CRITICAL >= Severity.LOW
        assert Severity.MEDIUM >= Severity.MEDIUM

    def test_severity_rich_style_critical(self) -> None:
        """CRITICAL has a bold red Rich style."""
        assert Severity.CRITICAL.rich_style == "bold red"

    def test_severity_rich_style_info(self) -> None:
        """INFO has a dim Rich style."""
        assert Severity.INFO.rich_style == "dim"

    def test_severity_exit_code_weight_ordering(self) -> None:
        """Exit code weights decrease from CRITICAL to INFO."""
        assert Severity.CRITICAL.exit_code_weight > Severity.HIGH.exit_code_weight
        assert Severity.HIGH.exit_code_weight > Severity.MEDIUM.exit_code_weight
        assert Severity.MEDIUM.exit_code_weight > Severity.LOW.exit_code_weight
        assert Severity.LOW.exit_code_weight > Severity.INFO.exit_code_weight
        assert Severity.INFO.exit_code_weight == 0

    def test_severity_sort_descending(self) -> None:
        """Sorting a list of severities in descending order puts CRITICAL first."""
        severities = [Severity.LOW, Severity.CRITICAL, Severity.INFO, Severity.HIGH]
        sorted_sevs = sorted(severities, reverse=True)
        assert sorted_sevs[0] == Severity.CRITICAL
        assert sorted_sevs[-1] == Severity.INFO


class TestCheckType:
    """Tests for the CheckType enumeration."""

    def test_check_type_values(self) -> None:
        """All check types have expected string values."""
        assert CheckType.TYPOSQUAT.value == "typosquat"
        assert CheckType.HOOK.value == "hook"
        assert CheckType.MCP.value == "mcp"


class TestFinding:
    """Tests for the Finding dataclass."""

    def _make_finding(
        self,
        severity: Severity = Severity.HIGH,
        check_type: CheckType = CheckType.TYPOSQUAT,
        package_name: str = "expresss",
    ) -> Finding:
        return Finding(
            check_type=check_type,
            severity=severity,
            package_name=package_name,
            title="Potential typosquat",
            description="Package name closely resembles 'express'",
            evidence="expresss",
            source_file=Path("package.json"),
            metadata={"matched_package": "express", "similarity": 95},
        )

    def test_finding_to_dict_keys(self) -> None:
        """to_dict() returns all expected keys."""
        finding = self._make_finding()
        d = finding.to_dict()
        expected_keys = {
            "check_type",
            "severity",
            "package_name",
            "title",
            "description",
            "evidence",
            "source_file",
            "metadata",
        }
        assert set(d.keys()) == expected_keys

    def test_finding_to_dict_values(self) -> None:
        """to_dict() serializes values correctly."""
        finding = self._make_finding()
        d = finding.to_dict()
        assert d["check_type"] == "typosquat"
        assert d["severity"] == "HIGH"
        assert d["package_name"] == "expresss"
        assert d["source_file"] == "package.json"
        assert d["metadata"]["similarity"] == 95

    def test_finding_to_dict_null_source_file(self) -> None:
        """to_dict() serializes None source_file as None."""
        finding = Finding(
            check_type=CheckType.HOOK,
            severity=Severity.CRITICAL,
            package_name="evil-pkg",
            title="Malicious hook",
            description="curl pipe to bash detected",
        )
        d = finding.to_dict()
        assert d["source_file"] is None
        assert d["evidence"] is None

    def test_finding_roundtrip_serialization(self) -> None:
        """A Finding survives a to_dict -> from_dict round trip."""
        original = self._make_finding()
        reconstructed = Finding.from_dict(original.to_dict())
        assert reconstructed.check_type == original.check_type
        assert reconstructed.severity == original.severity
        assert reconstructed.package_name == original.package_name
        assert reconstructed.title == original.title
        assert reconstructed.description == original.description
        assert reconstructed.evidence == original.evidence
        assert reconstructed.source_file == original.source_file
        assert reconstructed.metadata == original.metadata

    def test_finding_from_dict_invalid_severity_raises(self) -> None:
        """from_dict() raises ValueError for unknown severity."""
        data = {
            "check_type": "typosquat",
            "severity": "UNKNOWN",
            "package_name": "test",
            "title": "test",
            "description": "test",
        }
        with pytest.raises(ValueError):
            Finding.from_dict(data)

    def test_finding_from_dict_missing_required_key_raises(self) -> None:
        """from_dict() raises KeyError if a required key is absent."""
        data = {
            "check_type": "typosquat",
            "severity": "HIGH",
            # 'package_name' missing
            "title": "test",
            "description": "test",
        }
        with pytest.raises(KeyError):
            Finding.from_dict(data)

    def test_finding_default_metadata_is_empty_dict(self) -> None:
        """Finding.metadata defaults to an empty dict."""
        finding = Finding(
            check_type=CheckType.MCP,
            severity=Severity.LOW,
            package_name="some-pkg",
            title="MCP detected",
            description="MCP registration found",
        )
        assert finding.metadata == {}


class TestCheckResult:
    """Tests for the CheckResult dataclass."""

    def _make_result(self, num_findings: int = 2) -> CheckResult:
        findings = [
            Finding(
                check_type=CheckType.HOOK,
                severity=Severity.CRITICAL,
                package_name=f"pkg-{i}",
                title="Bad hook",
                description="Suspicious script",
            )
            for i in range(num_findings)
        ]
        return CheckResult(
            check_type=CheckType.HOOK,
            findings=findings,
            packages_scanned=10,
        )

    def test_has_findings_true_when_findings_present(self) -> None:
        """has_findings returns True when there are findings."""
        result = self._make_result(2)
        assert result.has_findings is True

    def test_has_findings_false_when_no_findings(self) -> None:
        """has_findings returns False when there are no findings."""
        result = CheckResult(check_type=CheckType.TYPOSQUAT)
        assert result.has_findings is False

    def test_critical_count(self) -> None:
        """critical_count returns correct number of CRITICAL findings."""
        result = self._make_result(3)
        assert result.critical_count == 3

    def test_high_count_zero_when_no_high_findings(self) -> None:
        """high_count is 0 when there are no HIGH findings."""
        result = self._make_result(2)
        assert result.high_count == 0

    def test_medium_count_zero_when_no_medium_findings(self) -> None:
        """medium_count is 0 when there are no MEDIUM findings."""
        result = self._make_result(1)
        assert result.medium_count == 0

    def test_to_dict_structure(self) -> None:
        """to_dict() returns all expected keys."""
        result = self._make_result(1)
        d = result.to_dict()
        assert "check_type" in d
        assert "findings" in d
        assert "packages_scanned" in d
        assert "error" in d

    def test_to_dict_check_type_value(self) -> None:
        """to_dict() serializes check_type as its string value."""
        result = self._make_result(0)
        d = result.to_dict()
        assert d["check_type"] == "hook"

    def test_to_dict_findings_are_serialized(self) -> None:
        """to_dict() serializes findings as a list of dicts."""
        result = self._make_result(2)
        d = result.to_dict()
        assert isinstance(d["findings"], list)
        assert len(d["findings"]) == 2
        assert isinstance(d["findings"][0], dict)

    def test_default_error_is_none(self) -> None:
        """error defaults to None."""
        result = CheckResult(check_type=CheckType.MCP)
        assert result.error is None


class TestScanReport:
    """Tests for the ScanReport dataclass."""

    def _make_report(self) -> ScanReport:
        critical_finding = Finding(
            check_type=CheckType.TYPOSQUAT,
            severity=Severity.CRITICAL,
            package_name="lodahs",
            title="Potential typosquat",
            description="Resembles 'lodash'",
        )
        high_finding = Finding(
            check_type=CheckType.HOOK,
            severity=Severity.HIGH,
            package_name="evil-pkg",
            title="Suspicious hook",
            description="curl pipe detected",
        )
        medium_finding = Finding(
            check_type=CheckType.MCP,
            severity=Severity.MEDIUM,
            package_name="some-mcp",
            title="MCP server",
            description="Unauthorized MCP server",
        )
        check_results = [
            CheckResult(
                check_type=CheckType.TYPOSQUAT,
                findings=[critical_finding],
                packages_scanned=5,
            ),
            CheckResult(
                check_type=CheckType.HOOK,
                findings=[high_finding],
                packages_scanned=5,
            ),
            CheckResult(
                check_type=CheckType.MCP,
                findings=[medium_finding],
                packages_scanned=5,
            ),
        ]
        return ScanReport(
            target_path=Path("/project"),
            check_results=check_results,
        )

    def test_all_findings_contains_all(self) -> None:
        """all_findings returns all findings across check results."""
        report = self._make_report()
        assert len(report.all_findings) == 3

    def test_all_findings_sorted_by_severity(self) -> None:
        """all_findings returns findings sorted most severe first."""
        report = self._make_report()
        findings = report.all_findings
        assert findings[0].severity == Severity.CRITICAL
        assert findings[-1].severity == Severity.MEDIUM

    def test_total_findings(self) -> None:
        """total_findings returns correct total count."""
        report = self._make_report()
        assert report.total_findings == 3

    def test_total_packages_scanned(self) -> None:
        """total_packages_scanned returns the maximum across check results."""
        report = self._make_report()
        assert report.total_packages_scanned == 5

    def test_has_critical_or_high_true(self) -> None:
        """has_critical_or_high is True when CRITICAL or HIGH findings exist."""
        report = self._make_report()
        assert report.has_critical_or_high is True

    def test_has_critical_or_high_false_when_only_medium(self) -> None:
        """has_critical_or_high is False when only MEDIUM/LOW/INFO findings exist."""
        medium_finding = Finding(
            check_type=CheckType.MCP,
            severity=Severity.MEDIUM,
            package_name="some-pkg",
            title="Test",
            description="Test",
        )
        report = ScanReport(
            target_path=Path("/project"),
            check_results=[
                CheckResult(
                    check_type=CheckType.MCP,
                    findings=[medium_finding],
                    packages_scanned=1,
                )
            ],
        )
        assert report.has_critical_or_high is False

    def test_exit_code_one_when_critical_findings(self) -> None:
        """exit_code is 1 when critical or high findings exist."""
        report = self._make_report()
        assert report.exit_code == 1

    def test_exit_code_zero_when_no_findings(self) -> None:
        """exit_code is 0 when no findings exist."""
        report = ScanReport(
            target_path=Path("/project"),
            check_results=[
                CheckResult(check_type=CheckType.TYPOSQUAT, packages_scanned=3)
            ],
        )
        assert report.exit_code == 0

    def test_exit_code_two_when_check_error(self) -> None:
        """exit_code is 2 when a check result has an error."""
        report = ScanReport(
            target_path=Path("/project"),
            check_results=[
                CheckResult(
                    check_type=CheckType.TYPOSQUAT,
                    packages_scanned=0,
                    error="Failed to read package.json",
                )
            ],
        )
        assert report.exit_code == 2

    def test_severity_counts_all_present(self) -> None:
        """severity_counts includes all five severity levels."""
        report = self._make_report()
        counts = report.severity_counts
        assert set(counts.keys()) == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

    def test_severity_counts_correct_values(self) -> None:
        """severity_counts has correct counts per severity level."""
        report = self._make_report()
        counts = report.severity_counts
        assert counts["CRITICAL"] == 1
        assert counts["HIGH"] == 1
        assert counts["MEDIUM"] == 1
        assert counts["LOW"] == 0
        assert counts["INFO"] == 0

    def test_to_dict_keys(self) -> None:
        """to_dict() returns all expected top-level keys."""
        report = self._make_report()
        d = report.to_dict()
        expected_keys = {
            "target_path",
            "scan_timestamp",
            "typosquat_threshold",
            "scanned_transitive",
            "total_packages_scanned",
            "total_findings",
            "severity_counts",
            "exit_code",
            "check_results",
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_target_path_is_string(self) -> None:
        """to_dict() serializes target_path as a string."""
        report = ScanReport(target_path=Path("/some/project"))
        d = report.to_dict()
        assert isinstance(d["target_path"], str)
        assert d["target_path"] == "/some/project"

    def test_to_dict_scan_timestamp_is_iso(self) -> None:
        """to_dict() includes an ISO timestamp string."""
        report = ScanReport(target_path=Path("/project"))
        d = report.to_dict()
        # Should be parseable as ISO 8601
        dt = datetime.datetime.fromisoformat(d["scan_timestamp"])
        assert dt is not None

    def test_default_typosquat_threshold(self) -> None:
        """Default typosquat_threshold is 80."""
        report = ScanReport(target_path=Path("/project"))
        assert report.typosquat_threshold == 80

    def test_default_scanned_transitive(self) -> None:
        """Default scanned_transitive is True."""
        report = ScanReport(target_path=Path("/project"))
        assert report.scanned_transitive is True

    def test_empty_report_total_packages_zero(self) -> None:
        """total_packages_scanned is 0 when check_results is empty."""
        report = ScanReport(target_path=Path("/project"))
        assert report.total_packages_scanned == 0


import datetime  # noqa: E402 - imported at bottom to avoid circular at top level
