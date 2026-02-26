"""MCP server injection detection for npm packages.

This module implements detection of rogue Model Context Protocol (MCP) server
registrations that may be injected via package metadata or post-install scripts.
MCP servers are a mechanism used by AI tooling (e.g., Claude Desktop, Cursor,
Copilot extensions) to extend capabilities, and attackers have begun targeting
these registrations as a supply chain vector.

The detector scans:
- The 'mcp' or 'mcpServers' keys in package.json metadata
- Post-install / install lifecycle scripts for MCP server registration patterns
- The 'bin' field for executables that match known MCP server entry-point patterns
- Package description, keywords, and main fields for MCP-related indicators
- Well-known MCP configuration file locations written during install

Severity heuristics:
- CRITICAL: Hardcoded remote MCP server URL in metadata or script
- CRITICAL: MCP registration combined with obfuscated / encoded payload
- HIGH:     MCP-related bin entry or keyword that doesn't match the package scope
- HIGH:     Auto-executed lifecycle script that registers an MCP server
- MEDIUM:   Suspicious MCP keyword/description without corroborating evidence
- LOW:      Package that declares itself as an MCP server without other indicators

Public API:
    MCPDetector: Main class implementing the detection engine
    MCPFinding: Dataclass representing a raw MCP-specific detection before
                it is converted to a Finding
    detect_mcp: Convenience function to check a single package.json dict

References:
    https://modelcontextprotocol.io/
    https://github.com/modelcontextprotocol/
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from npm_sentinel.models import CheckResult, CheckType, Finding, Severity

# ---------------------------------------------------------------------------
# Regex patterns for MCP detection
# ---------------------------------------------------------------------------

# Matches explicit MCP-related terminology
_MCP_KEYWORD_RE = re.compile(
    r"\b(?:mcp[_-]?server|model[_-]context[_-]protocol|modelcontextprotocol"
    r"|@modelcontextprotocol|mcp[_-]tool|mcp[_-]host|mcp[_-]client)",
    re.IGNORECASE,
)

# Matches MCP server registration in scripts (both JSON-based and CLI-based)
_MCP_REGISTER_RE = re.compile(
    r"(?:"
    r"mcp[_-]?(?:register|install|add|inject|serve|start|run|connect|bind|setup|init)"
    r"|register[_-]?mcp"
    r"|add[_-]?mcp[_-]?server"
    r"|modelcontextprotocol"
    r"|@modelcontextprotocol"
    r"|mcp[_-]server[_-]?(?:url|host|port|endpoint|address)"
    r")",
    re.IGNORECASE,
)

# Matches remote URLs that look like MCP server endpoints
_MCP_REMOTE_URL_RE = re.compile(
    r"(?:https?://|wss?://|tcp://)[^\s'\"]{5,}(?:mcp|model.context|/mcp/|:(?:8080|8443|3000|5000|9000))",
    re.IGNORECASE,
)

# Matches configuration file paths where MCP servers are commonly registered
_MCP_CONFIG_PATH_RE = re.compile(
    r"(?:"
    r"claude[_-]?desktop[_-]?config"
    r"|[~.]config/claude"
    r"|[~.]cursor/mcp"
    r"|[~.]vscode/mcp"
    r"|[~.]config/mcp"
    r"|mcp[_-]?config\.json"
    r"|mcp[_-]?servers?\.json"
    r"|mcp\.json"
    r")",
    re.IGNORECASE,
)

# Matches JSON manipulation utilities writing MCP config files
_MCP_CONFIG_WRITE_RE = re.compile(
    r"(?:jq|python3?|node)\s+.*(?:mcpServers|mcp_servers|claude_desktop_config"
    r"|cursor.*mcp|mcp.*cursor|mcp.*vscode|vscode.*mcp)",
    re.IGNORECASE,
)

# Matches stdio/sse transport mentions that are MCP-specific
_MCP_TRANSPORT_RE = re.compile(
    r"(?:"
    r"StdioServerTransport"
    r"|StdioClientTransport"
    r"|SSEServerTransport"
    r"|SSEClientTransport"
    r"|McpServer"
    r"|MCP_SERVER_URL"
    r"|MCP_SERVER_PORT"
    r"|MCP_HOST"
    r")",
    re.IGNORECASE,
)

# Lifecycle hooks that execute automatically during npm install
_AUTO_HOOKS: frozenset[str] = frozenset([
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "prepublish",
    "prepublishOnly",
])

# Keywords in the npm 'keywords' array that strongly suggest an MCP server
_MCP_STRONG_KEYWORDS: frozenset[str] = frozenset([
    "mcp",
    "mcp-server",
    "mcp_server",
    "model-context-protocol",
    "modelcontextprotocol",
    "mcp-tool",
    "mcp-host",
    "mcp-client",
    "claude-mcp",
    "cursor-mcp",
])


# ---------------------------------------------------------------------------
# Dataclass for raw MCP detection results (pre-Finding)
# ---------------------------------------------------------------------------


@dataclass
class MCPFinding:
    """A single raw MCP detection result before it is converted to a Finding.

    Attributes:
        detector_rule: Short identifier for the detection rule that triggered
        source_field: Which field / area of package.json the detection came from
            (e.g. 'scripts.postinstall', 'keywords', 'mcp', 'bin')
        matched_text: The text fragment that triggered the detection
        severity: Assessed severity level for this detection
        description: Human-readable explanation of the risk
        metadata: Additional structured data about the detection
    """

    detector_rule: str
    source_field: str
    matched_text: str
    severity: Severity
    description: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize this MCP finding to a JSON-serializable dictionary.

        Returns:
            Dict with all MCPFinding fields serialized.
        """
        return {
            "detector_rule": self.detector_rule,
            "source_field": self.source_field,
            "matched_text": self.matched_text,
            "severity": self.severity.value,
            "description": self.description,
            "metadata": self.metadata,
        }


# ---------------------------------------------------------------------------
# Main detector class
# ---------------------------------------------------------------------------


class MCPDetector:
    """Detects rogue MCP server registrations in npm package metadata.

    Scans package.json data for signs of unauthorized MCP server injection
    including explicit metadata fields, lifecycle script patterns, binary
    entry points, and keyword/description indicators.

    Attributes:
        scan_transitive: Whether to recursively scan node_modules
        max_script_length: Maximum script length to analyse (prevents DoS)

    Example::

        detector = MCPDetector(scan_transitive=True)
        result = detector.inspect_directory(Path("./my-project"))
        for finding in result.findings:
            print(finding.severity, finding.title)
    """

    def __init__(
        self,
        scan_transitive: bool = True,
        max_script_length: int = 65_536,
    ) -> None:
        """Initialise the MCPDetector.

        Args:
            scan_transitive: When True, recursively scan node_modules for
                package.json files. Defaults to True.
            max_script_length: Maximum characters to analyse per script.
                Defaults to 65536.
        """
        self.scan_transitive: bool = scan_transitive
        self.max_script_length: int = max_script_length

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def inspect_directory(self, project_root: Path) -> CheckResult:
        """Inspect all relevant package.json files in a project directory.

        Scans the root package.json and, if scan_transitive is True, all
        package.json files found recursively under ``node_modules``.

        Args:
            project_root: Path to the project root directory.

        Returns:
            A CheckResult with all MCP-related findings.
        """
        result = CheckResult(check_type=CheckType.MCP)
        packages_scanned = 0

        # Inspect root package.json
        root_pkg = project_root / "package.json"
        if root_pkg.is_file():
            pkg_findings = self._inspect_file(root_pkg)
            result.findings.extend(pkg_findings)
            packages_scanned += 1

        # Optionally inspect transitive dependencies
        if self.scan_transitive:
            node_modules = project_root / "node_modules"
            if node_modules.is_dir():
                for pkg_json in self._iter_package_jsons(node_modules):
                    try:
                        pkg_findings = self._inspect_file(pkg_json)
                        result.findings.extend(pkg_findings)
                        packages_scanned += 1
                    except Exception as exc:  # noqa: BLE001
                        result.error = (
                            (result.error or "")
                            + f"\nError reading {pkg_json}: {exc}"
                        ).strip()

        result.packages_scanned = packages_scanned
        return result

    def inspect_package_data(
        self,
        package_data: dict[str, Any],
        package_name: str = "<unknown>",
        source_file: Path | None = None,
    ) -> list[Finding]:
        """Inspect parsed package.json data for MCP server injection indicators.

        This is the core analysis method. It accepts already-parsed JSON data
        so it can be used without touching the filesystem (useful for testing).

        Args:
            package_data: Parsed contents of a package.json file as a dict.
            package_name: The name of the package. Falls back to the 'name' key
                in package_data if not provided.
            source_file: Optional path to the source file for findings.

        Returns:
            A list of Finding instances, one per detected MCP indicator.
        """
        resolved_name: str = (
            package_data.get("name", package_name)
            if package_name == "<unknown>"
            else package_name
        )
        if not resolved_name:
            resolved_name = "<unknown>"

        raw_findings: list[MCPFinding] = []

        # Run all detection sub-checks
        raw_findings.extend(self._check_mcp_metadata_field(package_data))
        raw_findings.extend(self._check_lifecycle_scripts(package_data))
        raw_findings.extend(self._check_bin_field(package_data, resolved_name))
        raw_findings.extend(self._check_keywords_and_description(package_data))
        raw_findings.extend(self._check_main_and_module(package_data))

        # Deduplicate: if the same rule fires on the same source_field, keep highest severity
        deduplicated = self._deduplicate(raw_findings)

        # Convert to Finding objects
        findings: list[Finding] = [
            self._build_finding(mf, resolved_name, source_file)
            for mf in deduplicated
        ]

        return findings

    # ------------------------------------------------------------------
    # Detection sub-checks
    # ------------------------------------------------------------------

    def _check_mcp_metadata_field(
        self, package_data: dict[str, Any]
    ) -> list[MCPFinding]:
        """Check for explicit MCP server metadata fields in package.json.

        Looks for top-level 'mcp', 'mcpServers', 'mcp-servers', or nested
        equivalents that explicitly declare MCP server registrations.

        Args:
            package_data: Parsed package.json data.

        Returns:
            List of MCPFinding instances.
        """
        findings: list[MCPFinding] = []

        # Check for dedicated MCP metadata keys
        mcp_keys = ["mcp", "mcpServers", "mcp-servers", "mcp_servers", "mcpServer"]
        for key in mcp_keys:
            value = package_data.get(key)
            if value is None:
                continue

            serialized = json.dumps(value) if not isinstance(value, str) else value

            # Check if the value contains a remote URL (most severe)
            if _MCP_REMOTE_URL_RE.search(serialized):
                findings.append(MCPFinding(
                    detector_rule="mcp_remote_server_url",
                    source_field=key,
                    matched_text=_truncate(serialized, 256),
                    severity=Severity.CRITICAL,
                    description=(
                        f"Package.json contains an explicit '{key}' metadata field "
                        f"with a remote MCP server URL. This is a strong indicator of "
                        f"an unauthorized MCP server registration that could allow "
                        f"an attacker to inject a rogue AI tool server."
                    ),
                    metadata={"field": key, "value_preview": _truncate(serialized, 128)},
                ))
            else:
                # Explicit MCP field without remote URL – still suspicious
                findings.append(MCPFinding(
                    detector_rule="mcp_metadata_field",
                    source_field=key,
                    matched_text=_truncate(serialized, 256),
                    severity=Severity.HIGH,
                    description=(
                        f"Package.json declares an explicit '{key}' metadata field. "
                        f"This may indicate the package is registering itself as an MCP "
                        f"server. Verify this is expected and from a trusted source."
                    ),
                    metadata={"field": key, "value_preview": _truncate(serialized, 128)},
                ))

        return findings

    def _check_lifecycle_scripts(
        self, package_data: dict[str, Any]
    ) -> list[MCPFinding]:
        """Check lifecycle scripts for MCP server registration patterns.

        Analyses npm lifecycle scripts for patterns that register MCP servers,
        modify AI tool configuration files, or reference MCP-related endpoints.

        Args:
            package_data: Parsed package.json data.

        Returns:
            List of MCPFinding instances.
        """
        findings: list[MCPFinding] = []
        scripts: Any = package_data.get("scripts", {})
        if not isinstance(scripts, dict):
            return findings

        for hook_name, script_value in scripts.items():
            if not isinstance(script_value, str):
                continue

            script_text = script_value[: self.max_script_length]
            is_auto = hook_name in _AUTO_HOOKS
            source_field = f"scripts.{hook_name}"

            # Check for MCP config file modification
            config_match = _MCP_CONFIG_PATH_RE.search(script_text)
            if config_match:
                severity = Severity.CRITICAL if is_auto else Severity.HIGH
                # Escalate further if it also contains a remote URL
                if _MCP_REMOTE_URL_RE.search(script_text):
                    severity = Severity.CRITICAL
                findings.append(MCPFinding(
                    detector_rule="mcp_config_file_write",
                    source_field=source_field,
                    matched_text=_truncate(script_text, 256),
                    severity=severity,
                    description=(
                        f"The '{hook_name}' script modifies a known MCP configuration "
                        f"file path ('{config_match.group(0)}'). "
                        f"{'This hook executes automatically during npm install, ' if is_auto else ''}"
                        f"making this a potential rogue MCP server injection vector."
                    ),
                    metadata={
                        "hook_name": hook_name,
                        "is_auto_hook": is_auto,
                        "config_path": config_match.group(0),
                    },
                ))

            # Check for explicit MCP registration commands
            register_match = _MCP_REGISTER_RE.search(script_text)
            if register_match:
                severity = Severity.CRITICAL if is_auto else Severity.HIGH
                findings.append(MCPFinding(
                    detector_rule="mcp_register_command",
                    source_field=source_field,
                    matched_text=_truncate(script_text, 256),
                    severity=severity,
                    description=(
                        f"The '{hook_name}' script contains an MCP server registration "
                        f"command ('{register_match.group(0)}'). "
                        f"{'This hook executes automatically during npm install. ' if is_auto else ''}"
                        f"Unauthorized MCP server registration can silently add rogue AI "
                        f"tool servers to developer workstations."
                    ),
                    metadata={
                        "hook_name": hook_name,
                        "is_auto_hook": is_auto,
                        "matched_command": register_match.group(0),
                    },
                ))

            # Check for remote MCP URL in scripts
            url_match = _MCP_REMOTE_URL_RE.search(script_text)
            if url_match and not register_match and not config_match:
                severity = Severity.CRITICAL if is_auto else Severity.HIGH
                findings.append(MCPFinding(
                    detector_rule="mcp_remote_url_in_script",
                    source_field=source_field,
                    matched_text=_truncate(script_text, 256),
                    severity=severity,
                    description=(
                        f"The '{hook_name}' script contains a remote URL that matches "
                        f"MCP server endpoint patterns ('{url_match.group(0)}'). "
                        f"This may indicate a covert connection to an attacker-controlled "
                        f"MCP server."
                    ),
                    metadata={
                        "hook_name": hook_name,
                        "is_auto_hook": is_auto,
                        "remote_url": url_match.group(0),
                    },
                ))

            # Check for MCP transport primitives in scripts
            transport_match = _MCP_TRANSPORT_RE.search(script_text)
            if transport_match and not register_match and not config_match:
                severity = Severity.MEDIUM if not is_auto else Severity.HIGH
                findings.append(MCPFinding(
                    detector_rule="mcp_transport_in_script",
                    source_field=source_field,
                    matched_text=_truncate(script_text, 256),
                    severity=severity,
                    description=(
                        f"The '{hook_name}' script references MCP transport primitives "
                        f"('{transport_match.group(0)}'). This may indicate the script "
                        f"is starting or connecting to an MCP server."
                    ),
                    metadata={
                        "hook_name": hook_name,
                        "is_auto_hook": is_auto,
                        "transport_primitive": transport_match.group(0),
                    },
                ))

            # Check for jq/python writing MCP config
            config_write_match = _MCP_CONFIG_WRITE_RE.search(script_text)
            if config_write_match and not config_match:
                severity = Severity.CRITICAL if is_auto else Severity.HIGH
                findings.append(MCPFinding(
                    detector_rule="mcp_config_programmatic_write",
                    source_field=source_field,
                    matched_text=_truncate(script_text, 256),
                    severity=severity,
                    description=(
                        f"The '{hook_name}' script uses a scripting utility "
                        f"(jq, python, node) to programmatically write MCP server "
                        f"configuration. This is a common technique for stealthily "
                        f"registering rogue MCP servers in AI tool configurations."
                    ),
                    metadata={
                        "hook_name": hook_name,
                        "is_auto_hook": is_auto,
                        "matched_command": config_write_match.group(0),
                    },
                ))

        return findings

    def _check_bin_field(
        self, package_data: dict[str, Any], package_name: str
    ) -> list[MCPFinding]:
        """Check the 'bin' field for MCP-related executable names.

        Args:
            package_data: Parsed package.json data.
            package_name: Resolved package name.

        Returns:
            List of MCPFinding instances.
        """
        findings: list[MCPFinding] = []
        bin_field: Any = package_data.get("bin")
        if not bin_field:
            return findings

        # Normalize bin to a dict
        if isinstance(bin_field, str):
            bin_dict: dict[str, str] = {package_name: bin_field}
        elif isinstance(bin_field, dict):
            bin_dict = bin_field
        else:
            return findings

        for bin_name, bin_path in bin_dict.items():
            if not isinstance(bin_name, str) or not isinstance(bin_path, str):
                continue
            combined = f"{bin_name} {bin_path}"
            if _MCP_KEYWORD_RE.search(combined) or _MCP_REGISTER_RE.search(combined):
                findings.append(MCPFinding(
                    detector_rule="mcp_bin_entry",
                    source_field="bin",
                    matched_text=combined[:256],
                    severity=Severity.HIGH,
                    description=(
                        f"Package exposes a binary entry point named '{bin_name}' "
                        f"pointing to '{bin_path}' that references MCP terminology. "
                        f"This may indicate the package installs an MCP server "
                        f"executable into PATH, enabling persistent server access."
                    ),
                    metadata={"bin_name": bin_name, "bin_path": bin_path},
                ))

        return findings

    def _check_keywords_and_description(
        self, package_data: dict[str, Any]
    ) -> list[MCPFinding]:
        """Check the 'keywords' and 'description' fields for MCP indicators.

        Args:
            package_data: Parsed package.json data.

        Returns:
            List of MCPFinding instances.
        """
        findings: list[MCPFinding] = []

        # Check keywords array
        keywords: Any = package_data.get("keywords", [])
        if isinstance(keywords, list):
            matched_kw = [
                str(kw).lower()
                for kw in keywords
                if isinstance(kw, str) and str(kw).lower() in _MCP_STRONG_KEYWORDS
            ]
            if matched_kw:
                findings.append(MCPFinding(
                    detector_rule="mcp_keyword_declared",
                    source_field="keywords",
                    matched_text=", ".join(matched_kw),
                    severity=Severity.LOW,
                    description=(
                        f"Package declares MCP-related keywords: {matched_kw}. "
                        f"While not inherently malicious, this indicates the package "
                        f"self-identifies as an MCP server or tool. Combined with other "
                        f"indicators this warrants review."
                    ),
                    metadata={"matched_keywords": matched_kw},
                ))

        # Check description
        description: Any = package_data.get("description", "")
        if isinstance(description, str) and description:
            kw_match = _MCP_KEYWORD_RE.search(description)
            if kw_match:
                findings.append(MCPFinding(
                    detector_rule="mcp_description_mention",
                    source_field="description",
                    matched_text=_truncate(description, 256),
                    severity=Severity.LOW,
                    description=(
                        f"Package description mentions MCP-related terminology "
                        f"('{kw_match.group(0)}'). Review the package to confirm "
                        f"it is a legitimate MCP integration."
                    ),
                    metadata={"matched_term": kw_match.group(0)},
                ))

        return findings

    def _check_main_and_module(
        self, package_data: dict[str, Any]
    ) -> list[MCPFinding]:
        """Check 'main', 'module', and 'exports' fields for MCP transport references.

        Args:
            package_data: Parsed package.json data.

        Returns:
            List of MCPFinding instances.
        """
        findings: list[MCPFinding] = []

        for field_name in ("main", "module"):
            value: Any = package_data.get(field_name)
            if not isinstance(value, str) or not value:
                continue
            if _MCP_KEYWORD_RE.search(value) or _MCP_TRANSPORT_RE.search(value):
                findings.append(MCPFinding(
                    detector_rule="mcp_main_entry_reference",
                    source_field=field_name,
                    matched_text=_truncate(value, 256),
                    severity=Severity.MEDIUM,
                    description=(
                        f"The '{field_name}' entry point ('{value}') references MCP "
                        f"terminology. This may indicate the package's primary export "
                        f"is an MCP server implementation."
                    ),
                    metadata={"field": field_name, "entry_point": value},
                ))

        # Check exports field (can be dict or string)
        exports: Any = package_data.get("exports")
        if isinstance(exports, dict):
            exports_str = json.dumps(exports)
        elif isinstance(exports, str):
            exports_str = exports
        else:
            exports_str = ""

        if exports_str:
            transport_match = _MCP_TRANSPORT_RE.search(exports_str)
            if transport_match:
                findings.append(MCPFinding(
                    detector_rule="mcp_exports_transport_reference",
                    source_field="exports",
                    matched_text=_truncate(exports_str, 256),
                    severity=Severity.MEDIUM,
                    description=(
                        f"The 'exports' field references MCP transport primitives "
                        f"('{transport_match.group(0)}'). The package may be "
                        f"exporting MCP server functionality."
                    ),
                    metadata={"transport_primitive": transport_match.group(0)},
                ))

        return findings

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    @staticmethod
    def _deduplicate(findings: list[MCPFinding]) -> list[MCPFinding]:
        """Remove duplicate MCPFinding entries by (detector_rule, source_field).

        When multiple instances of the same rule fire on the same source field,
        keeps only the one with the highest severity.

        Args:
            findings: Raw list of MCPFinding instances (may contain duplicates).

        Returns:
            Deduplicated list of MCPFinding instances.
        """
        seen: dict[tuple[str, str], MCPFinding] = {}
        severity_order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]
        for mf in findings:
            key = (mf.detector_rule, mf.source_field)
            if key not in seen:
                seen[key] = mf
            else:
                # Keep the higher severity entry
                existing = seen[key]
                if severity_order.index(mf.severity) < severity_order.index(existing.severity):
                    seen[key] = mf
        return list(seen.values())

    # ------------------------------------------------------------------
    # Finding construction
    # ------------------------------------------------------------------

    @staticmethod
    def _build_finding(
        mcp_finding: MCPFinding,
        package_name: str,
        source_file: Path | None,
    ) -> Finding:
        """Convert an MCPFinding to a Finding dataclass.

        Args:
            mcp_finding: The raw MCPFinding to convert.
            package_name: The npm package name this finding belongs to.
            source_file: Optional path to the source package.json file.

        Returns:
            A Finding instance suitable for inclusion in a CheckResult.
        """
        title = (
            f"MCP server injection detected in '{package_name}': "
            f"{mcp_finding.detector_rule} in '{mcp_finding.source_field}'"
        )

        return Finding(
            check_type=CheckType.MCP,
            severity=mcp_finding.severity,
            package_name=package_name,
            title=title,
            description=mcp_finding.description,
            evidence=mcp_finding.matched_text,
            source_file=source_file,
            metadata={
                "detector_rule": mcp_finding.detector_rule,
                "source_field": mcp_finding.source_field,
                **mcp_finding.metadata,
            },
        )

    # ------------------------------------------------------------------
    # Filesystem helpers
    # ------------------------------------------------------------------

    def _inspect_file(self, package_json_path: Path) -> list[Finding]:
        """Read and inspect a single package.json file.

        Args:
            package_json_path: Path to the package.json file.

        Returns:
            List of Finding instances.

        Raises:
            json.JSONDecodeError: If the file is not valid JSON.
            OSError: If the file cannot be read.
        """
        try:
            text = package_json_path.read_text(encoding="utf-8", errors="replace")
            package_data: dict[str, Any] = json.loads(text)
        except json.JSONDecodeError as exc:
            raise json.JSONDecodeError(
                f"Invalid JSON in {package_json_path}: {exc.msg}",
                exc.doc,
                exc.pos,
            ) from exc
        except OSError as exc:
            raise OSError(f"Cannot read {package_json_path}: {exc}") from exc

        if not isinstance(package_data, dict):
            return []

        return self.inspect_package_data(
            package_data=package_data,
            package_name=package_data.get("name", "<unknown>"),
            source_file=package_json_path,
        )

    @staticmethod
    def _iter_package_jsons(node_modules: Path) -> list[Path]:
        """Yield all package.json files found under a node_modules directory.

        Skips nested node_modules directories within packages to avoid
        double-counting and exponential traversal.

        Args:
            node_modules: Path to the node_modules directory.

        Returns:
            Sorted list of Path objects pointing to package.json files.
        """
        results: list[Path] = []
        try:
            for pkg_json in node_modules.rglob("package.json"):
                relative = pkg_json.relative_to(node_modules)
                parts = relative.parts
                if "node_modules" in parts[:-1]:
                    continue
                results.append(pkg_json)
        except OSError:
            pass
        return sorted(results)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------


def _truncate(text: str, max_chars: int = 256) -> str:
    """Truncate a string to a maximum number of characters.

    Args:
        text: The string to truncate.
        max_chars: Maximum number of characters to keep.

    Returns:
        Truncated string with '...[truncated]' appended if truncation occurred.
    """
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "...[truncated]"


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------


def detect_mcp(
    package_data: dict[str, Any],
    package_name: str = "<unknown>",
    source_file: Path | None = None,
) -> list[Finding]:
    """Convenience function to check a single package.json dict for MCP injection.

    Creates a temporary MCPDetector and runs the analysis on the provided data.
    For scanning an entire project directory prefer creating an MCPDetector
    instance and calling ``inspect_directory()``.

    Args:
        package_data: Parsed package.json data as a dict.
        package_name: Optional package name override.
        source_file: Optional path to the source file for findings.

    Returns:
        A list of Finding instances describing MCP injection indicators.

    Example::

        data = json.loads(Path("package.json").read_text())
        findings = detect_mcp(data)
        for f in findings:
            print(f.severity, f.title)
    """
    detector = MCPDetector(scan_transitive=False)
    return detector.inspect_package_data(
        package_data=package_data,
        package_name=package_name,
        source_file=source_file,
    )
