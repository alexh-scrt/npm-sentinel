"""Lifecycle script auditing for suspicious shell patterns and post-install hooks.

This module implements the hook inspection logic for npm_sentinel. It parses
package.json lifecycle scripts and node_modules package.json files for
dangerous shell patterns commonly used in supply chain attacks:

- curl/wget pipes to bash/sh (remote code execution)
- base64-encoded payloads (obfuscation of malicious commands)
- Environment variable exfiltration (credential theft)
- Dynamic eval patterns in scripts (code injection)
- Suspicious network calls in lifecycle hooks
- Encoded/obfuscated commands using xxd, openssl, python -c, etc.
- Process spawning to unexpected interpreters

The inspector scans both the root package.json and, optionally, all
package.json files found recursively under node_modules.

Public API:
    HookInspector: Main class that performs lifecycle script analysis
    SuspiciousPattern: Dataclass representing a detected shell pattern
    inspect_package_json: Convenience function to inspect a single package.json

Lifecycle hooks inspected:
    preinstall, install, postinstall, preuninstall, uninstall, postuninstall,
    prepare, prepublish, prepublishOnly, prepack, postpack, pretest, test,
    posttest, prestop, stop, poststop, prestart, start, poststart,
    prerestart, restart, postrestart
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from npm_sentinel.models import CheckResult, CheckType, Finding, Severity

# ---------------------------------------------------------------------------
# Lifecycle hook names that npm executes automatically
# ---------------------------------------------------------------------------

LIFECYCLE_HOOKS: frozenset[str] = frozenset([
    "preinstall",
    "install",
    "postinstall",
    "preuninstall",
    "uninstall",
    "postuninstall",
    "prepare",
    "prepublish",
    "prepublishOnly",
    "prepack",
    "postpack",
    "pretest",
    "test",
    "posttest",
    "prestop",
    "stop",
    "poststop",
    "prestart",
    "start",
    "poststart",
    "prerestart",
    "restart",
    "postrestart",
])

# ---------------------------------------------------------------------------
# Suspicious pattern definitions
# ---------------------------------------------------------------------------

@dataclass
class PatternRule:
    """A single suspicious pattern rule.

    Attributes:
        name: Short identifier for the pattern category
        pattern: Compiled regular expression to match against script text
        severity: Severity level assigned when this pattern is detected
        description: Human-readable explanation of the risk
    """

    name: str
    pattern: re.Pattern[str]
    severity: Severity
    description: str


# Compiled pattern rules ordered roughly by severity (most severe first)
PATTERN_RULES: list[PatternRule] = [
    PatternRule(
        name="curl_pipe_shell",
        pattern=re.compile(
            r"curl\b[^|\n]*\|\s*(?:bash|sh|zsh|ksh|csh|fish|dash)",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        description=(
            "Detected 'curl | shell' pattern: downloads and immediately executes "
            "remote code. This is a classic supply chain attack vector that allows "
            "an attacker to run arbitrary code on the target system."
        ),
    ),
    PatternRule(
        name="wget_pipe_shell",
        pattern=re.compile(
            r"wget\b[^|\n]*\|\s*(?:bash|sh|zsh|ksh|csh|fish|dash)",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        description=(
            "Detected 'wget | shell' pattern: downloads and immediately executes "
            "remote code. This is a classic supply chain attack vector."
        ),
    ),
    PatternRule(
        name="curl_exec_redirect",
        pattern=re.compile(
            r"curl\b.*-o\s+[^\s]+.*(?:sh|bash|exec)",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        description=(
            "Detected curl downloading a file that is then executed. "
            "This pattern is used to stage and run remote payloads."
        ),
    ),
    PatternRule(
        name="base64_decode_exec",
        pattern=re.compile(
            r"base64\s+(?:-d|--decode|-D).*(?:\|\s*(?:bash|sh|eval)|>\s*[^\s]+\.sh)"
            r"|echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64"
            r"|base64\s+(?:-d|--decode)\s*<<<",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        description=(
            "Detected base64-encoded payload being decoded and executed. "
            "Attackers use base64 encoding to obfuscate malicious commands "
            "and evade naive pattern-matching defences."
        ),
    ),
    PatternRule(
        name="base64_encoded_payload",
        pattern=re.compile(
            r"(?:atob|Buffer\.from)\s*\(\s*['\"][A-Za-z0-9+/=]{32,}['\"]",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        description=(
            "Detected long base64-encoded string being decoded at runtime. "
            "This may indicate obfuscated code that hides its true purpose."
        ),
    ),
    PatternRule(
        name="eval_dynamic_code",
        pattern=re.compile(
            r"\beval\s*\([^)]{0,300}(?:require|fetch|http|https|Buffer|exec|spawn)",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        description=(
            "Detected eval() with dynamic network or execution primitives. "
            "Using eval() to execute dynamically fetched or constructed code "
            "is a critical injection risk."
        ),
    ),
    PatternRule(
        name="eval_simple",
        pattern=re.compile(
            r"\beval\s*\(",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        description=(
            "Detected eval() call in lifecycle script. "
            "eval() can execute arbitrary code and is a common attack primitive."
        ),
    ),
    PatternRule(
        name="env_exfiltration_curl",
        pattern=re.compile(
            r"curl\b[^\n]*(?:\$(?:HOME|PATH|USER|AWS_|SECRET|TOKEN|PASSWORD|API_KEY|GITHUB_|NPM_)[\w]*"
            r"|\$\{?(?:HOME|PATH|USER|AWS_|SECRET|TOKEN|PASSWORD|API_KEY|GITHUB_|NPM_)[\w]*\}?)",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        description=(
            "Detected curl command transmitting environment variables. "
            "This pattern is used to exfiltrate secrets, credentials, or "
            "cloud provider tokens to attacker-controlled servers."
        ),
    ),
    PatternRule(
        name="env_exfiltration_wget",
        pattern=re.compile(
            r"wget\b[^\n]*(?:\$(?:HOME|PATH|USER|AWS_|SECRET|TOKEN|PASSWORD|API_KEY|GITHUB_|NPM_)[\w]*"
            r"|\$\{?(?:HOME|PATH|USER|AWS_|SECRET|TOKEN|PASSWORD|API_KEY|GITHUB_|NPM_)[\w]*\}?)",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        description=(
            "Detected wget command transmitting environment variables. "
            "This pattern is used to exfiltrate secrets to attacker-controlled servers."
        ),
    ),
    PatternRule(
        name="env_exfiltration_env_dump",
        pattern=re.compile(
            r"(?:printenv|env|set)\s*(?:\|\s*(?:curl|wget|nc|ncat|netcat|socat)|>\s*[^\s]+\.txt)",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        description=(
            "Detected dumping all environment variables and piping them to a network "
            "utility or file. This is a high-confidence credential exfiltration indicator."
        ),
    ),
    PatternRule(
        name="netcat_reverse_shell",
        pattern=re.compile(
            r"\b(?:nc|ncat|netcat|socat)\b.*(?:-e\s+(?:\/bin\/(?:bash|sh)|cmd)"
            r"|-c\s+(?:bash|sh)|exec.*\$\(|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        description=(
            "Detected netcat/socat with reverse shell flags (-e, -c) or IP address. "
            "This is a classic indicator of a backdoor or reverse shell payload."
        ),
    ),
    PatternRule(
        name="python_exec_remote",
        pattern=re.compile(
            r"python[23]?\s+-c\s+['\"].*(?:urllib|urllib2|requests|http\.client|socket|import os)",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        description=(
            "Detected Python one-liner with network or OS execution primitives. "
            "Attackers use python -c '...' to download and execute payloads."
        ),
    ),
    PatternRule(
        name="node_exec_remote",
        pattern=re.compile(
            r"node\s+-e\s+['\"].*(?:require\s*\(\s*['\"](?:http|https|child_process|fs)['\"])",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        description=(
            "Detected Node.js one-liner with network or child_process primitives. "
            "This may be used to download and execute remote code."
        ),
    ),
    PatternRule(
        name="openssl_decode_exec",
        pattern=re.compile(
            r"openssl\s+(?:enc|base64).*(?:-d|-decode).*(?:\|\s*(?:bash|sh)|>\s*[^\s]+\.sh)",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        description=(
            "Detected openssl decode piped to a shell. "
            "Attackers use openssl as an alternative to base64 for payload deobfuscation."
        ),
    ),
    PatternRule(
        name="chmod_exec",
        pattern=re.compile(
            r"chmod\s+[+]?x\b[^\n]*&&[^\n]*\.\s*\.\.\/|chmod\s+[+]?x\b[^\n]*&&[^\n]*exec",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        description=(
            "Detected chmod +x followed by execution. "
            "Setting a file executable and immediately running it is suspicious "
            "in a lifecycle script context."
        ),
    ),
    PatternRule(
        name="curl_silent_background",
        pattern=re.compile(
            r"curl\b.*(?:-s\s+|-sS\s+|-sSL\s+).*(?:&\s*$|&\s*;|>\s*/dev/null)",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        description=(
            "Detected silent curl running in the background or with suppressed output. "
            "This pattern is used to hide network activity during package installation."
        ),
    ),
    PatternRule(
        name="dns_exfiltration",
        pattern=re.compile(
            r"(?:nslookup|dig|host)\s+.*\$(?:HOME|USER|HOSTNAME|AWS_|SECRET|TOKEN|PASSWORD)",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        description=(
            "Detected DNS lookup with environment variables as the query target. "
            "This is a known DNS exfiltration technique for leaking secrets covertly."
        ),
    ),
    PatternRule(
        name="crontab_persistence",
        pattern=re.compile(
            r"crontab\s+(?:-l|-e|\|)|echo\s+.*>>\s*/etc/cron",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        description=(
            "Detected crontab modification or /etc/cron file append. "
            "Establishing cron persistence is a common post-exploitation technique."
        ),
    ),
    PatternRule(
        name="ssh_authorized_keys",
        pattern=re.compile(
            r">>\s*[~\/].*authorized_keys|cat\s+.*>>\s*.*\.ssh.*authorized_keys",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        description=(
            "Detected append to SSH authorized_keys file. "
            "This is a critical persistence mechanism that allows "
            "permanent remote access to the compromised host."
        ),
    ),
    PatternRule(
        name="reverse_shell_bash",
        pattern=re.compile(
            r"bash\s+-[iI]\s*>\s*&\s*\/dev\/tcp\/|exec\s+\d+<>\/dev\/tcp\/",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        description=(
            "Detected Bash TCP reverse shell pattern (/dev/tcp). "
            "This is a textbook reverse shell technique using Bash built-ins."
        ),
    ),
    PatternRule(
        name="xxd_decode_exec",
        pattern=re.compile(
            r"xxd\s+-(?:r|revert).*\|\s*(?:bash|sh)",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        description=(
            "Detected xxd hex decode piped to a shell. "
            "xxd -r is used as an alternative obfuscation for malicious payloads."
        ),
    ),
    PatternRule(
        name="suspicious_download_tool",
        pattern=re.compile(
            r"\b(?:fetch|aria2c|axel|lwp-request|lynx|links)\b[^\n]*(?:https?|ftp)://",
            re.IGNORECASE,
        ),
        severity=Severity.MEDIUM,
        description=(
            "Detected network download utility (aria2c, axel, lwp-request, etc.) "
            "fetching from a remote URL in a lifecycle script. "
            "Downloads during install should be scrutinised."
        ),
    ),
    PatternRule(
        name="sensitive_file_access",
        pattern=re.compile(
            r"cat\s+(?:~\/\.(?:ssh|aws|gnupg|netrc|npmrc|gitconfig|bash_history|zsh_history)"
            r"|\/etc\/(?:passwd|shadow|hosts?|sudoers))",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        description=(
            "Detected access to sensitive system files (SSH keys, AWS credentials, "
            "/etc/passwd, etc.) in a lifecycle script. This is a strong indicator "
            "of credential harvesting."
        ),
    ),
    PatternRule(
        name="process_env_send",
        pattern=re.compile(
            r"process\.env\b[^\n]*(?:require\s*\(['\"](?:https?|http|child_process)|"
            r"fetch\s*\(|axios|got|superagent|request\s*\()",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        description=(
            "Detected process.env access combined with a network call in a lifecycle script. "
            "This pattern is used to exfiltrate Node.js environment variables "
            "including npm tokens and cloud credentials."
        ),
    ),
    PatternRule(
        name="obfuscated_hex_string",
        pattern=re.compile(
            r"(?:\\x[0-9a-fA-F]{2}){8,}",
            re.IGNORECASE,
        ),
        severity=Severity.MEDIUM,
        description=(
            "Detected long hex-encoded string in lifecycle script. "
            "Hex encoding is used to obfuscate malicious commands or URLs."
        ),
    ),
    PatternRule(
        name="shell_injection_subshell",
        pattern=re.compile(
            r"\$\(curl|\$\(wget|`curl|`wget",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        description=(
            "Detected command substitution wrapping curl or wget. "
            "This injects the output of a remote download directly into a command "
            "for execution, a critical code execution pattern."
        ),
    ),
]


@dataclass
class SuspiciousPattern:
    """A detected suspicious pattern within a lifecycle script.

    Attributes:
        rule_name: Identifier of the pattern rule that matched
        hook_name: The npm lifecycle hook name (e.g. 'postinstall')
        matched_text: The portion of the script text that matched
        severity: Severity level for this match
        description: Human-readable explanation of the risk
        line_number: Approximate line number within the script (1-indexed)
    """

    rule_name: str
    hook_name: str
    matched_text: str
    severity: Severity
    description: str
    line_number: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize this pattern match to a JSON-serializable dictionary.

        Returns:
            Dict with rule_name, hook_name, matched_text, severity, description,
            and line_number keys.
        """
        return {
            "rule_name": self.rule_name,
            "hook_name": self.hook_name,
            "matched_text": self.matched_text,
            "severity": self.severity.value,
            "description": self.description,
            "line_number": self.line_number,
        }


class HookInspector:
    """Lifecycle script auditor that detects suspicious shell patterns.

    Parses package.json files and inspects npm lifecycle scripts for patterns
    commonly associated with supply chain attacks. Supports scanning a single
    package.json file or recursively scanning all package.json files under a
    node_modules directory.

    Attributes:
        scan_transitive: Whether to recursively scan node_modules
        max_script_length: Maximum script length to analyse (prevents DoS)

    Example::

        inspector = HookInspector(scan_transitive=True)
        result = inspector.inspect_directory(Path("./my-project"))
        for finding in result.findings:
            print(finding.severity, finding.title)
    """

    def __init__(
        self,
        scan_transitive: bool = True,
        max_script_length: int = 65_536,
    ) -> None:
        """Initialise the HookInspector.

        Args:
            scan_transitive: When True, recursively scan node_modules for
                package.json files in addition to the root package.json.
                Defaults to True.
            max_script_length: Maximum number of characters to analyse in a
                single script value. Scripts longer than this are truncated
                before analysis. Defaults to 65536.
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
            project_root: Path to the project root directory (the directory
                containing the top-level package.json).

        Returns:
            A CheckResult with all hook-related findings.
        """
        result = CheckResult(check_type=CheckType.HOOK)
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
                        # Log as a non-fatal error and continue
                        result.error = (
                            (result.error or "") +
                            f"\nError reading {pkg_json}: {exc}"
                        ).strip()

        result.packages_scanned = packages_scanned
        return result

    def inspect_package_data(
        self,
        package_data: dict[str, Any],
        package_name: str = "<unknown>",
        source_file: Path | None = None,
    ) -> list[Finding]:
        """Inspect parsed package.json data for suspicious lifecycle scripts.

        This is the core analysis method. It accepts already-parsed JSON data
        so it can be used without touching the filesystem (useful for testing).

        Args:
            package_data: Parsed contents of a package.json file as a dict.
            package_name: The name of the package (used in finding messages).
                Falls back to the 'name' key in package_data if not provided.
            source_file: Optional path to the source file for findings.

        Returns:
            A list of Finding instances, one per suspicious pattern detected.
        """
        # Resolve package name
        resolved_name: str = (
            package_data.get("name", package_name)
            if package_name == "<unknown>"
            else package_name
        )
        if not resolved_name:
            resolved_name = "<unknown>"

        scripts: Any = package_data.get("scripts", {})
        if not isinstance(scripts, dict):
            return []

        findings: list[Finding] = []

        for hook_name, script_value in scripts.items():
            if not isinstance(script_value, str):
                continue
            # Truncate overly long scripts
            script_text = script_value[: self.max_script_length]

            detected = self._scan_script(hook_name, script_text)
            for pattern_match in detected:
                finding = self._build_finding(
                    pattern_match=pattern_match,
                    package_name=resolved_name,
                    hook_name=hook_name,
                    script_text=script_text,
                    source_file=source_file,
                    is_lifecycle_hook=hook_name in LIFECYCLE_HOOKS,
                )
                findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _inspect_file(self, package_json_path: Path) -> list[Finding]:
        """Read and inspect a single package.json file.

        Args:
            package_json_path: Absolute or relative path to the package.json file.

        Returns:
            A list of Finding instances.

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

    def _scan_script(
        self,
        hook_name: str,
        script_text: str,
    ) -> list[SuspiciousPattern]:
        """Apply all pattern rules to a single script string.

        Iterates over all PatternRule definitions and returns a list of
        SuspiciousPattern instances for each rule that matches.

        Args:
            hook_name: The name of the npm lifecycle hook (e.g. 'postinstall').
            script_text: The raw script string to analyse.

        Returns:
            List of SuspiciousPattern instances, one per matching rule.
        """
        matches: list[SuspiciousPattern] = []
        for rule in PATTERN_RULES:
            for regex_match in rule.pattern.finditer(script_text):
                matched_text = regex_match.group(0)
                # Compute approximate line number
                line_number = script_text[: regex_match.start()].count("\n") + 1
                matches.append(
                    SuspiciousPattern(
                        rule_name=rule.name,
                        hook_name=hook_name,
                        matched_text=matched_text,
                        severity=rule.severity,
                        description=rule.description,
                        line_number=line_number,
                    )
                )
        return matches

    def _build_finding(
        self,
        pattern_match: SuspiciousPattern,
        package_name: str,
        hook_name: str,
        script_text: str,
        source_file: Path | None,
        is_lifecycle_hook: bool,
    ) -> Finding:
        """Construct a Finding from a SuspiciousPattern match.

        Promotes severity by one level when the pattern appears in a
        lifecycle hook that npm executes automatically (e.g. postinstall),
        because those run without any user interaction.

        Args:
            pattern_match: The SuspiciousPattern that was detected.
            package_name: The npm package name this finding belongs to.
            hook_name: The npm hook name where the pattern was found.
            script_text: The full script text (truncated to max_script_length).
            source_file: Optional path to the package.json file.
            is_lifecycle_hook: Whether the hook is a standard npm lifecycle hook.

        Returns:
            A Finding dataclass instance.
        """
        severity = pattern_match.severity

        # Escalate severity for auto-executed lifecycle hooks
        if is_lifecycle_hook and severity == Severity.MEDIUM:
            severity = Severity.HIGH

        hook_label = "auto-executed lifecycle" if is_lifecycle_hook else "custom"
        title = (
            f"Suspicious {hook_label} hook in '{package_name}': "
            f"{pattern_match.rule_name} detected in '{hook_name}'"
        )

        description = (
            f"Package '{package_name}' contains a suspicious pattern in its "
            f"'{hook_name}' script ({hook_label} hook).\n\n"
            f"Pattern: {pattern_match.rule_name}\n"
            f"Risk: {pattern_match.description}\n"
            f"Location: line {pattern_match.line_number} of the '{hook_name}' script"
        )

        # Truncate evidence to avoid enormous output
        evidence = _truncate_evidence(script_text, max_chars=512)

        return Finding(
            check_type=CheckType.HOOK,
            severity=severity,
            package_name=package_name,
            title=title,
            description=description,
            evidence=evidence,
            source_file=source_file,
            metadata={
                "hook_name": hook_name,
                "is_lifecycle_hook": is_lifecycle_hook,
                "pattern": pattern_match.to_dict(),
            },
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
                # Skip nested node_modules (e.g. node_modules/foo/node_modules/bar)
                # by checking if any parent part between node_modules root and this
                # file contains another 'node_modules' component.
                relative = pkg_json.relative_to(node_modules)
                parts = relative.parts
                # If 'node_modules' appears among the intermediate parts, skip
                if "node_modules" in parts[:-1]:  # exclude the filename itself
                    continue
                results.append(pkg_json)
        except OSError:
            pass
        return sorted(results)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------


def _truncate_evidence(text: str, max_chars: int = 512) -> str:
    """Truncate evidence text to a maximum character length.

    Args:
        text: The text to truncate.
        max_chars: Maximum number of characters to keep.

    Returns:
        Truncated string, with '...[truncated]' appended if truncation occurred.
    """
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "...[truncated]"


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------


def inspect_package_json(
    package_json_path: Path,
    scan_transitive: bool = False,
) -> CheckResult:
    """Convenience function to inspect a single package.json file for suspicious hooks.

    Creates a temporary HookInspector and runs an inspection on the specified
    package.json file. For scanning an entire project directory (including
    node_modules) prefer creating a HookInspector instance and calling
    ``inspect_directory()`` directly.

    Args:
        package_json_path: Path to the package.json file to inspect.
        scan_transitive: If True, also scan node_modules in the same directory.
            Defaults to False for single-file inspection.

    Returns:
        A CheckResult containing all hook-related findings.

    Raises:
        FileNotFoundError: If the specified file does not exist.

    Example::

        result = inspect_package_json(Path("./package.json"))
        for finding in result.findings:
            print(finding.severity.value, finding.title)
    """
    if not package_json_path.exists():
        raise FileNotFoundError(f"package.json not found: {package_json_path}")

    inspector = HookInspector(scan_transitive=scan_transitive)
    project_root = package_json_path.parent

    result = CheckResult(check_type=CheckType.HOOK)
    try:
        findings = inspector._inspect_file(package_json_path)
        result.findings.extend(findings)
        result.packages_scanned = 1
    except (json.JSONDecodeError, OSError) as exc:
        result.error = str(exc)
        result.packages_scanned = 0

    if scan_transitive:
        node_modules = project_root / "node_modules"
        if node_modules.is_dir():
            for pkg_json in HookInspector._iter_package_jsons(node_modules):
                try:
                    findings = inspector._inspect_file(pkg_json)
                    result.findings.extend(findings)
                    result.packages_scanned += 1
                except Exception as exc:  # noqa: BLE001
                    result.error = (
                        (result.error or "") + f"\nError reading {pkg_json}: {exc}"
                    ).strip()

    return result
