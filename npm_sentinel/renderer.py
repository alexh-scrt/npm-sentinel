"""Rich-based terminal output renderer for npm_sentinel scan results.

This module provides a Rich-powered renderer that formats ScanReport findings
as styled tables, summary panels, and progress indicators for interactive
terminal use. It also supports plain-text and JSON output modes for CI/CD
pipeline consumption.

The renderer produces:
- A header panel showing the target path and scan metadata
- Per-check-category tables listing each finding with severity, package name,
  and a truncated description
- A summary panel with total counts per severity level, exit code, and
  overall scan status (PASS / FAIL)
- Optionally, a compact single-line summary for CI environments

Public API:
    Renderer: Main class implementing all rendering modes
    render_report: Convenience function to render a ScanReport to the console
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from npm_sentinel.models import CheckResult, CheckType, Finding, ScanReport, Severity

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maximum description length shown in the findings table
_DESC_TRUNCATE = 120

# Severity badge styles (foreground colour / style for Rich markup)
_SEVERITY_BADGE: dict[Severity, tuple[str, str]] = {
    Severity.CRITICAL: ("bold white on red", "CRITICAL"),
    Severity.HIGH: ("bold red", "HIGH    "),
    Severity.MEDIUM: ("bold yellow", "MEDIUM  "),
    Severity.LOW: ("bold blue", "LOW     "),
    Severity.INFO: ("dim", "INFO    "),
}

# Check type display names
_CHECK_TYPE_LABEL: dict[CheckType, str] = {
    CheckType.TYPOSQUAT: "Typosquat Detection",
    CheckType.HOOK: "Lifecycle Hook Inspection",
    CheckType.MCP: "MCP Server Injection Detection",
}

# Check type icons
_CHECK_TYPE_ICON: dict[CheckType, str] = {
    CheckType.TYPOSQUAT: "🔍",
    CheckType.HOOK: "🪝",
    CheckType.MCP: "🤖",
}


class Renderer:
    """Rich-based renderer for npm_sentinel ScanReport output.

    Formats scan results as richly styled terminal output including tables,
    panels, and severity-coloured badges. Also supports JSON output mode
    for downstream CI/CD consumption.

    Attributes:
        console: The Rich Console instance used for output
        show_evidence: Whether to include raw evidence snippets in output

    Example::

        renderer = Renderer()
        renderer.render(report)
        # Or for JSON output:
        renderer.render_json(report)
    """

    def __init__(
        self,
        console: Console | None = None,
        show_evidence: bool = False,
        no_color: bool = False,
    ) -> None:
        """Initialise the Renderer.

        Args:
            console: Optional Rich Console instance. When None, a new Console
                is created writing to stdout. Pass Console(stderr=True) to
                write to stderr.
            show_evidence: When True, include the raw evidence snippet (e.g.
                the suspicious script text) in the findings table.
                Defaults to False.
            no_color: When True, disable Rich colour and styling (useful for
                log files or CI environments without ANSI support).
        """
        self.console: Console = console or Console(
            highlight=False,
            no_color=no_color,
        )
        self.show_evidence: bool = show_evidence

    # ------------------------------------------------------------------
    # Primary rendering entry points
    # ------------------------------------------------------------------

    def render(self, report: ScanReport) -> None:
        """Render a full ScanReport to the console with Rich formatting.

        Outputs:
        1. A header panel with scan metadata
        2. Per-check-category finding tables
        3. A summary panel with severity counts and overall status

        Args:
            report: The ScanReport to render.
        """
        self._render_header(report)
        self._render_check_results(report)
        self._render_summary(report)

    def render_json(self, report: ScanReport) -> None:
        """Render a ScanReport as pretty-printed JSON to the console.

        Outputs the report's to_dict() representation as indented JSON.
        No Rich styling is applied so the output is suitable for piping
        to downstream tools.

        Args:
            report: The ScanReport to render.
        """
        output = json.dumps(report.to_dict(), indent=2, default=str)
        self.console.print(output, highlight=False, markup=False)

    def render_compact(self, report: ScanReport) -> None:
        """Render a one-line summary suitable for CI log output.

        Outputs a single line like:
            [PASS] npm-sentinel: 0 findings in 42 packages scanned
        or:
            [FAIL] npm-sentinel: 3 findings (1 CRITICAL, 2 HIGH) in 42 packages

        Args:
            report: The ScanReport to render.
        """
        status = "FAIL" if report.exit_code != 0 else "PASS"
        style = "bold red" if report.exit_code != 0 else "bold green"
        counts = report.severity_counts
        non_zero = [
            f"{v} {k}"
            for k, v in counts.items()
            if v > 0
        ]
        counts_str = f" ({', '.join(non_zero)})" if non_zero else ""
        line = (
            f"[{style}][{status}][/{style}] npm-sentinel: "
            f"{report.total_findings} finding(s){counts_str} "
            f"in {report.total_packages_scanned} package(s) scanned "
            f"\u2014 target: {report.target_path}"
        )
        self.console.print(line)

    # ------------------------------------------------------------------
    # Header
    # ------------------------------------------------------------------

    def _render_header(self, report: ScanReport) -> None:
        """Render the scan header panel.

        Shows the target path, scan timestamp, configuration options,
        and total package count.

        Args:
            report: The ScanReport being rendered.
        """
        from npm_sentinel import __version__

        lines: list[str] = [
            f"[bold]npm-sentinel[/bold] v{__version__} \u2014 Supply Chain Security Audit",
            "",
            f"[dim]Target:[/dim]       [cyan]{report.target_path}[/cyan]",
            f"[dim]Scanned:[/dim]      {report.scan_timestamp}",
            f"[dim]Threshold:[/dim]    {report.typosquat_threshold}% similarity",
            f"[dim]Transitive:[/dim]   {'Yes' if report.scanned_transitive else 'No'}",
            f"[dim]Packages:[/dim]     {report.total_packages_scanned} package(s) examined",
        ]
        content = "\n".join(lines)
        panel = Panel(
            content,
            title="[bold blue]\U0001f6e1\ufe0f  npm-sentinel scan[/bold blue]",
            border_style="blue",
            padding=(1, 2),
        )
        self.console.print()
        self.console.print(panel)
        self.console.print()

    # ------------------------------------------------------------------
    # Per-check tables
    # ------------------------------------------------------------------

    def _render_check_results(self, report: ScanReport) -> None:
        """Render one findings table per check category.

        For checks with no findings a brief \u2705 clean notice is shown.
        For checks with an error a warning panel is shown.

        Args:
            report: The ScanReport being rendered.
        """
        for check_result in report.check_results:
            self._render_single_check(check_result)

    def _render_single_check(
        self,
        result: CheckResult,
    ) -> None:
        """Render the findings for a single check category.

        Args:
            result: The CheckResult to render.
        """
        label = _CHECK_TYPE_LABEL.get(result.check_type, result.check_type.value)
        icon = _CHECK_TYPE_ICON.get(result.check_type, "")
        section_title = f"{icon}  {label}"

        self.console.rule(f"[bold]{section_title}[/bold]", style="blue")
        self.console.print()

        # Show error if the check encountered a problem
        if result.error:
            error_panel = Panel(
                f"[bold red]Check error:[/bold red] {result.error}",
                border_style="red",
                title="[bold red]Error[/bold red]",
            )
            self.console.print(error_panel)
            self.console.print()

        if not result.has_findings:
            self.console.print(
                f"  [bold green]\u2705  No {label.lower()} findings.[/bold green]  "
                f"[dim]({result.packages_scanned} package(s) scanned)[/dim]"
            )
            self.console.print()
            return

        # Build and print the findings table
        table = self._build_findings_table(result)
        self.console.print(table)
        self.console.print(
            f"  [dim]{result.packages_scanned} package(s) scanned — "
            f"{len(result.findings)} finding(s)[/dim]"
        )
        self.console.print()

    def _build_findings_table(self, result: CheckResult) -> Table:
        """Build a Rich Table for the findings in a CheckResult.

        Args:
            result: The CheckResult whose findings will populate the table.

        Returns:
            A Rich Table instance ready for printing.
        """
        table = Table(
            box=box.ROUNDED,
            show_header=True,
            header_style="bold dim",
            border_style="dim",
            expand=True,
            padding=(0, 1),
        )

        table.add_column("Severity", width=10, no_wrap=True)
        table.add_column("Package", min_width=20, no_wrap=True)
        table.add_column("Title", min_width=30)
        table.add_column("Description", min_width=40)

        if self.show_evidence:
            table.add_column("Evidence", min_width=20)

        # Sort findings most-severe first
        sorted_findings = sorted(result.findings, key=lambda f: f.severity, reverse=True)

        for finding in sorted_findings:
            severity_cell = self._severity_badge(finding.severity)
            package_cell = Text(finding.package_name, style="cyan", no_wrap=True)
            title_cell = Text(finding.title, no_wrap=False)
            desc_cell = Text(
                _truncate(finding.description, _DESC_TRUNCATE),
                style="dim",
                no_wrap=False,
            )

            row: list[Any] = [
                severity_cell,
                package_cell,
                title_cell,
                desc_cell,
            ]

            if self.show_evidence:
                evidence = finding.evidence or ""
                evidence_cell = Text(
                    _truncate(evidence, 80),
                    style="italic dim",
                    no_wrap=False,
                )
                row.append(evidence_cell)

            table.add_row(*row)

        return table

    # ------------------------------------------------------------------
    # Summary panel
    # ------------------------------------------------------------------

    def _render_summary(self, report: ScanReport) -> None:
        """Render the final summary panel.

        Shows:
        - Severity breakdown (count per level)
        - Overall status (PASS / FAIL)
        - Exit code
        - Actionable advice when findings exist

        Args:
            report: The ScanReport being rendered.
        """
        self.console.rule("[bold]Scan Summary[/bold]", style="blue")
        self.console.print()

        counts = report.severity_counts
        severity_lines: list[str] = []
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = counts.get(sev.value, 0)
            style, label = _SEVERITY_BADGE[sev]
            marker = "\u25cf" if count > 0 else "\u25cb"
            severity_lines.append(
                f"  [{style}]{marker} {label.strip():<8}[/{style}]  {count}"
            )

        severity_block = "\n".join(severity_lines)

        # Determine overall pass/fail
        if report.exit_code == 0:
            status_text = "[bold green]\u2705  PASS[/bold green]"
            border_style = "green"
            advice = "[dim]No critical or high severity findings detected.[/dim]"
        elif report.exit_code == 2:
            status_text = "[bold yellow]\u26a0\ufe0f  ERROR[/bold yellow]"
            border_style = "yellow"
            advice = (
                "[dim]One or more checks encountered errors. "
                "Review the error messages above.[/dim]"
            )
        else:
            status_text = "[bold red]\u274c  FAIL[/bold red]"
            border_style = "red"
            advice = (
                "[dim]Critical or high severity findings were detected. "
                "Review the findings above and remediate before deploying.[/dim]"
            )

        summary_content = (
            f"{severity_block}\n\n"
            f"  [dim]Total findings:[/dim]  {report.total_findings}\n"
            f"  [dim]Packages scanned:[/dim] {report.total_packages_scanned}\n"
            f"  [dim]Exit code:[/dim]       {report.exit_code}\n\n"
            f"  Status: {status_text}\n\n"
            f"  {advice}"
        )

        panel = Panel(
            summary_content,
            title="[bold]Results[/bold]",
            border_style=border_style,
            padding=(1, 2),
        )
        self.console.print(panel)
        self.console.print()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _severity_badge(severity: Severity) -> Text:
        """Build a Rich Text cell for a severity badge.

        Args:
            severity: The severity level to render.

        Returns:
            A Rich Text instance with appropriate styling.
        """
        style, label = _SEVERITY_BADGE.get(
            severity,
            ("white", severity.value),
        )
        return Text(label.strip(), style=style, no_wrap=True)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------


def _truncate(text: str, max_chars: int) -> str:
    """Truncate a string to a maximum length, appending '\u2026' if truncated.

    Args:
        text: The string to truncate.
        max_chars: Maximum number of characters to keep.

    Returns:
        The original string if short enough, or a truncated version ending
        with '\u2026'.
    """
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rstrip() + "\u2026"


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------


def render_report(
    report: ScanReport,
    output_format: str = "text",
    show_evidence: bool = False,
    console: Console | None = None,
    no_color: bool = False,
) -> None:
    """Convenience function to render a ScanReport to the terminal.

    Creates a Renderer instance and dispatches to the appropriate rendering
    method based on ``output_format``.

    Args:
        report: The ScanReport to render.
        output_format: One of 'text', 'json', or 'compact'. Defaults to 'text'.
            - 'text': Full Rich-formatted output with tables and panels
            - 'json': Machine-readable JSON output
            - 'compact': Single-line CI-friendly summary
        show_evidence: When True and output_format is 'text', include raw
            evidence snippets in the findings table. Defaults to False.
        console: Optional Rich Console instance to use. When None a new
            Console is created writing to stdout.
        no_color: When True, disable Rich styling. Defaults to False.

    Raises:
        ValueError: If output_format is not one of the accepted values.

    Example::

        from pathlib import Path
        from npm_sentinel.scanner import scan_directory
        from npm_sentinel.renderer import render_report

        report = scan_directory(Path("."))
        render_report(report, output_format="text")
    """
    accepted_formats = {"text", "json", "compact"}
    if output_format not in accepted_formats:
        raise ValueError(
            f"output_format must be one of {accepted_formats}, "
            f"got '{output_format}'"
        )

    renderer = Renderer(
        console=console,
        show_evidence=show_evidence,
        no_color=no_color,
    )

    if output_format == "json":
        renderer.render_json(report)
    elif output_format == "compact":
        renderer.render_compact(report)
    else:
        renderer.render(report)
