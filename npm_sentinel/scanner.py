"""Scanner orchestrator that aggregates all checks into a structured ScanReport.

This module is the central orchestrator for npm_sentinel. It wires together
the typosquat detector, hook inspector, and MCP detector, runs them against
a target project directory, and returns a unified ScanReport containing all
findings from every check category.

The scanner supports:
- Scanning the root package.json for all three check types
- Recursively scanning node_modules for transitive dependency threats
- Configurable similarity threshold for typosquat detection
- Graceful error handling so a failure in one checker does not abort others
- Extracting dependency names from package.json (dependencies,
  devDependencies, peerDependencies, optionalDependencies)

Public API:
    Scanner: Main orchestrator class
    scan_directory: Convenience function to run a full scan on a directory
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from npm_sentinel.hook_inspector import HookInspector
from npm_sentinel.mcp_detector import MCPDetector
from npm_sentinel.models import CheckResult, CheckType, Severity, ScanReport
from npm_sentinel.typosquat import TyposquatDetector

# Dependency key names in package.json that contain package names
_DEPENDENCY_KEYS: tuple[str, ...] = (
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
    "bundledDependencies",
    "bundleDependencies",
)


class Scanner:
    """Orchestrates all npm_sentinel checks against a project directory.

    Runs the typosquat detector, hook inspector, and MCP detector and
    aggregates their results into a single ScanReport. Each checker runs
    independently so a failure in one does not prevent others from running.

    Attributes:
        typosquat_threshold: Similarity score threshold for typosquat detection
        scan_transitive: Whether to recursively scan node_modules

    Example::

        scanner = Scanner(typosquat_threshold=80, scan_transitive=True)
        report = scanner.scan(Path("./my-project"))
        print(f"Found {report.total_findings} findings")
        print(f"Exit code: {report.exit_code}")
    """

    def __init__(
        self,
        typosquat_threshold: int = 80,
        scan_transitive: bool = True,
    ) -> None:
        """Initialise the Scanner.

        Args:
            typosquat_threshold: Similarity score (0-100) at or above which a
                package name is flagged as a potential typosquat. Defaults to 80.
            scan_transitive: When True, recursively scans node_modules for
                transitive dependency threats. Defaults to True.

        Raises:
            ValueError: If typosquat_threshold is not in the range 0-100.
        """
        if not (0 <= typosquat_threshold <= 100):
            raise ValueError(
                f"typosquat_threshold must be between 0 and 100, "
                f"got {typosquat_threshold}"
            )
        self.typosquat_threshold: int = typosquat_threshold
        self.scan_transitive: bool = scan_transitive

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def scan(self, project_root: Path) -> ScanReport:
        """Run all checks against the given project directory.

        Executes the typosquat, hook, and MCP checks and returns an
        aggregated ScanReport. Each checker is run independently; errors
        in individual checkers are captured in the CheckResult.error field
        and do not interrupt the overall scan.

        Args:
            project_root: Path to the project root directory. This directory
                should contain a package.json file. node_modules (if present)
                will be scanned for transitive dependencies when
                scan_transitive is True.

        Returns:
            A ScanReport containing findings from all check categories.

        Raises:
            FileNotFoundError: If project_root does not exist.
            NotADirectoryError: If project_root is not a directory.
        """
        project_root = project_root.resolve()

        if not project_root.exists():
            raise FileNotFoundError(
                f"Project root does not exist: {project_root}"
            )
        if not project_root.is_dir():
            raise NotADirectoryError(
                f"Project root is not a directory: {project_root}"
            )

        report = ScanReport(
            target_path=project_root,
            typosquat_threshold=self.typosquat_threshold,
            scanned_transitive=self.scan_transitive,
        )

        # Run each check independently and collect results
        typosquat_result = self._run_typosquat_check(project_root)
        hook_result = self._run_hook_check(project_root)
        mcp_result = self._run_mcp_check(project_root)

        report.check_results = [typosquat_result, hook_result, mcp_result]
        return report

    # ------------------------------------------------------------------
    # Individual check runners
    # ------------------------------------------------------------------

    def _run_typosquat_check(self, project_root: Path) -> CheckResult:
        """Run the typosquat check against the project.

        Extracts package names from the root package.json and, if
        scan_transitive is True, from all package.json files in node_modules.
        Then runs the TyposquatDetector against the collected names.

        Args:
            project_root: Path to the project root directory.

        Returns:
            A CheckResult with typosquat findings.
        """
        try:
            detector = TyposquatDetector(threshold=self.typosquat_threshold)

            # Gather all package names and their source files
            name_source_pairs: list[tuple[str, Path]] = []

            # Extract from root package.json
            root_pkg = project_root / "package.json"
            if root_pkg.is_file():
                root_names = self._extract_dependency_names(root_pkg)
                for name in root_names:
                    name_source_pairs.append((name, root_pkg))

            # Extract from node_modules if scanning transitively
            if self.scan_transitive:
                node_modules = project_root / "node_modules"
                if node_modules.is_dir():
                    for pkg_json in self._iter_package_jsons(node_modules):
                        try:
                            names = self._extract_dependency_names(pkg_json)
                            for name in names:
                                name_source_pairs.append((name, pkg_json))
                        except Exception:  # noqa: BLE001
                            continue

            # Group by source file for efficient checking
            from collections import defaultdict
            by_source: dict[Path, list[str]] = defaultdict(list)
            for name, source in name_source_pairs:
                by_source[source].append(name)

            # Run detector per source file and aggregate results
            combined_result = CheckResult(
                check_type=CheckType.TYPOSQUAT,
                packages_scanned=0,
            )

            total_unique_names: set[str] = set()
            for source_file, names in by_source.items():
                unique_names = list(dict.fromkeys(names))  # preserve order, deduplicate
                total_unique_names.update(unique_names)
                partial = detector.check_packages(
                    unique_names, source_file=source_file
                )
                combined_result.findings.extend(partial.findings)

            # Also scan the package names declared in node_modules (the package
            # names themselves, not just their dependencies)
            if self.scan_transitive:
                node_modules = project_root / "node_modules"
                if node_modules.is_dir():
                    transitive_names_with_source: list[tuple[str, Path]] = []
                    for pkg_json in self._iter_package_jsons(node_modules):
                        try:
                            pkg_name = self._read_package_name(pkg_json)
                            if pkg_name:
                                transitive_names_with_source.append(
                                    (pkg_name, pkg_json)
                                )
                        except Exception:  # noqa: BLE001
                            continue

                    by_pkg_source: dict[Path, list[str]] = defaultdict(list)
                    for name, source in transitive_names_with_source:
                        if name not in total_unique_names:
                            by_pkg_source[source].append(name)
                            total_unique_names.add(name)

                    for source_file, names in by_pkg_source.items():
                        partial = detector.check_packages(
                            names, source_file=source_file
                        )
                        combined_result.findings.extend(partial.findings)

            combined_result.packages_scanned = len(total_unique_names)
            return combined_result

        except Exception as exc:  # noqa: BLE001
            return CheckResult(
                check_type=CheckType.TYPOSQUAT,
                packages_scanned=0,
                error=f"Typosquat check failed: {exc}",
            )

    def _run_hook_check(self, project_root: Path) -> CheckResult:
        """Run the hook inspection check against the project.

        Uses HookInspector to scan the root package.json and, optionally,
        all package.json files found under node_modules.

        Args:
            project_root: Path to the project root directory.

        Returns:
            A CheckResult with hook-related findings.
        """
        try:
            inspector = HookInspector(scan_transitive=self.scan_transitive)
            return inspector.inspect_directory(project_root)
        except Exception as exc:  # noqa: BLE001
            return CheckResult(
                check_type=CheckType.HOOK,
                packages_scanned=0,
                error=f"Hook inspection failed: {exc}",
            )

    def _run_mcp_check(self, project_root: Path) -> CheckResult:
        """Run the MCP detector check against the project.

        Uses MCPDetector to scan the root package.json and, optionally,
        all package.json files found under node_modules.

        Args:
            project_root: Path to the project root directory.

        Returns:
            A CheckResult with MCP-related findings.
        """
        try:
            detector = MCPDetector(scan_transitive=self.scan_transitive)
            return detector.inspect_directory(project_root)
        except Exception as exc:  # noqa: BLE001
            return CheckResult(
                check_type=CheckType.MCP,
                packages_scanned=0,
                error=f"MCP detection failed: {exc}",
            )

    # ------------------------------------------------------------------
    # Filesystem / parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_dependency_names(package_json_path: Path) -> list[str]:
        """Extract all dependency package names from a package.json file.

        Reads the file and collects names from all standard dependency fields:
        dependencies, devDependencies, peerDependencies, optionalDependencies,
        bundledDependencies, and bundleDependencies.

        Args:
            package_json_path: Path to the package.json file to read.

        Returns:
            Deduplicated list of package name strings.

        Raises:
            json.JSONDecodeError: If the file is not valid JSON.
            OSError: If the file cannot be read.
        """
        text = package_json_path.read_text(encoding="utf-8", errors="replace")
        data: Any = json.loads(text)
        if not isinstance(data, dict):
            return []

        names: list[str] = []
        seen: set[str] = set()

        for key in _DEPENDENCY_KEYS:
            deps: Any = data.get(key)
            if isinstance(deps, dict):
                for name in deps.keys():
                    if isinstance(name, str) and name and name not in seen:
                        names.append(name)
                        seen.add(name)
            elif isinstance(deps, list):
                # bundledDependencies can be a list of strings
                for name in deps:
                    if isinstance(name, str) and name and name not in seen:
                        names.append(name)
                        seen.add(name)

        return names

    @staticmethod
    def _read_package_name(package_json_path: Path) -> str | None:
        """Read the 'name' field from a package.json file.

        Args:
            package_json_path: Path to the package.json file.

        Returns:
            The package name string, or None if it cannot be determined.
        """
        try:
            text = package_json_path.read_text(encoding="utf-8", errors="replace")
            data: Any = json.loads(text)
            if isinstance(data, dict):
                name = data.get("name")
                if isinstance(name, str) and name:
                    return name
        except Exception:  # noqa: BLE001
            pass
        return None

    @staticmethod
    def _iter_package_jsons(node_modules: Path) -> list[Path]:
        """Iterate over all package.json files in a node_modules directory.

        Skips nested node_modules to avoid exponential traversal and
        double-counting transitive packages.

        Args:
            node_modules: Path to the node_modules directory.

        Returns:
            Sorted list of Path objects for each discovered package.json.
        """
        results: list[Path] = []
        try:
            for pkg_json in node_modules.rglob("package.json"):
                relative = pkg_json.relative_to(node_modules)
                parts = relative.parts
                # Skip if there is another 'node_modules' in the path parts
                # (excluding the filename itself at parts[-1])
                if "node_modules" in parts[:-1]:
                    continue
                results.append(pkg_json)
        except OSError:
            pass
        return sorted(results)


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------


def scan_directory(
    project_root: Path,
    typosquat_threshold: int = 80,
    scan_transitive: bool = True,
) -> ScanReport:
    """Convenience function to run a full npm_sentinel scan on a directory.

    Creates a Scanner instance with the given options and runs the scan.
    Equivalent to::

        Scanner(typosquat_threshold, scan_transitive).scan(project_root)

    Args:
        project_root: Path to the project root directory containing package.json.
        typosquat_threshold: Similarity score threshold for typosquat detection
            (0-100). Defaults to 80.
        scan_transitive: When True, recursively scans node_modules for
            transitive dependency threats. Defaults to True.

    Returns:
        A ScanReport containing all findings from all check categories.

    Raises:
        FileNotFoundError: If project_root does not exist.
        NotADirectoryError: If project_root is not a directory.
        ValueError: If typosquat_threshold is out of range.

    Example::

        from pathlib import Path
        from npm_sentinel.scanner import scan_directory

        report = scan_directory(Path("."), typosquat_threshold=85)
        print(f"{report.total_findings} finding(s) detected")
        if report.exit_code != 0:
            print("Security risks detected!")
    """
    scanner = Scanner(
        typosquat_threshold=typosquat_threshold,
        scan_transitive=scan_transitive,
    )
    return scanner.scan(project_root)
