# npm-sentinel 🛡️

> Stop supply chain attacks before they reach production.

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI Ready](https://img.shields.io/badge/CI-ready-brightgreen.svg)](#cicd-integration)

**npm-sentinel** is a command-line security tool that audits `package.json` and `node_modules` directories for supply chain attack vectors — including typosquatting, suspicious post-install hooks, and rogue MCP server injections. Drop it into your CI pipeline as a pre-install gate and automatically block compromised dependency trees before they reach production.

---

## Quick Start

```bash
# Install
pip install npm-sentinel

# Scan the current directory
npm-sentinel scan .

# Scan a specific project
npm-sentinel scan /path/to/your/node-project

# Output JSON for pipeline consumption
npm-sentinel scan . --format json
```

That's it. If threats are detected, the process exits with a non-zero status code.

---

## Features

- **Typosquat detection** — Fuzzy string matching (Levenshtein + Jaro-Winkler) against 500+ top npm packages with a configurable similarity threshold.
- **Post-install hook auditing** — Flags `curl`/`wget` pipes, base64-encoded payloads, environment variable exfiltration, and dynamic `eval` patterns in lifecycle scripts.
- **MCP server injection detection** — Scans package metadata and install scripts for unauthorized Model Context Protocol server registrations targeting AI tooling (Claude Desktop, Cursor, etc.).
- **Transitive dependency scanning** — Recursively inspects `node_modules` to catch threats in indirect dependencies, not just direct ones.
- **CI/CD-ready exit codes** — Exits `0` (clean), `1` (warnings), or `2` (critical/high findings), with `--format json` for downstream pipeline consumption.

---

## Usage

### Basic Scan

```bash
# Scan with default settings (threshold 80, text output)
npm-sentinel scan .

# Show raw evidence snippets inline
npm-sentinel scan . --evidence

# Skip transitive dependency scanning (faster, direct deps only)
npm-sentinel scan . --no-transitive
```

### Adjusting Typosquat Sensitivity

```bash
# Stricter matching (fewer false positives)
npm-sentinel scan . --threshold 90

# More aggressive matching (catch more potential typosquats)
npm-sentinel scan . --threshold 70
```

### Output Formats

```bash
# Rich terminal table (default)
npm-sentinel scan .

# JSON report — ideal for CI artifacts or downstream tooling
npm-sentinel scan . --format json

# Compact single-line summary for CI logs
npm-sentinel scan . --format compact

# Write output to a file
npm-sentinel scan . --format json --output report.json

# Disable color (for non-TTY environments)
npm-sentinel scan . --no-color
```

### Filtering by Severity

```bash
# Only report CRITICAL and HIGH findings
npm-sentinel scan . --min-severity HIGH

# Report everything including informational findings
npm-sentinel scan . --min-severity INFO
```

### Version

```bash
npm-sentinel version
```

---

## CI/CD Integration

npm-sentinel is designed to be a pre-install gate. Use it before `npm install` to block compromised dependency trees.

### GitHub Actions

```yaml
jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install npm-sentinel
        run: pip install npm-sentinel

      - name: Audit dependencies
        run: npm-sentinel scan . --min-severity HIGH --format json --output sentinel-report.json

      - name: Upload audit report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: sentinel-report
          path: sentinel-report.json
```

### Pre-install Hook (package.json)

```json
{
  "scripts": {
    "preinstall": "npm-sentinel scan . --min-severity HIGH"
  }
}
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | No findings at or above the minimum severity threshold |
| `1`  | Medium or Low findings detected |
| `2`  | Critical or High findings detected — pipeline should fail |

---

## Project Structure

```
npm_sentinel/
├── pyproject.toml              # Project metadata, dependencies, CLI entry point
├── README.md
├── npm_sentinel/
│   ├── __init__.py             # Package version and public API
│   ├── cli.py                  # Click CLI entry point, flag wiring
│   ├── scanner.py              # Orchestrator: runs all checks, builds ScanReport
│   ├── typosquat.py            # Fuzzy-match engine against trusted package list
│   ├── hook_inspector.py       # Lifecycle script auditing for shell injection
│   ├── mcp_detector.py         # MCP server injection detection
│   ├── trusted_packages.py     # 500+ curated top npm packages (reference DB)
│   ├── models.py               # Finding, Severity, ScanReport dataclasses
│   └── renderer.py             # Rich terminal renderer (tables, panels, JSON)
└── tests/
    ├── __init__.py
    ├── test_typosquat.py
    ├── test_hook_inspector.py
    ├── test_mcp_detector.py
    ├── test_scanner.py
    ├── test_models.py
    └── fixtures/
        └── malicious_package.json  # Fixture with suspicious hooks + typosquats
```

---

## Configuration

npm-sentinel is configured entirely via CLI flags — no config file required.

| Flag | Default | Description |
|------|---------|-------------|
| `--threshold INT` | `80` | Fuzzy match similarity threshold (0–100). Higher = stricter, fewer false positives. |
| `--no-transitive` | `false` | Skip recursive `node_modules` scanning. Faster, but misses transitive threats. |
| `--format TEXT` | `text` | Output format: `text`, `json`, or `compact`. |
| `--evidence` | `false` | Include raw evidence snippets in the findings output. |
| `--no-color` | `false` | Disable Rich color and styling (auto-detected in non-TTY environments). |
| `--output FILE` | stdout | Write output to a file instead of stdout. |
| `--min-severity TEXT` | `LOW` | Minimum severity to report: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`. |

### Tuning the Typosquat Threshold

The default threshold of `80` balances detection coverage against false positives. In practice:

- **90+** — Very strict. Only catches near-identical names (e.g., `lodash` vs `1odash`). Recommended for projects with many unusual internal package names.
- **80** (default) — Catches most real typosquats with low noise.
- **70** — Aggressive. May flag scoped packages or legitimate similarly-named packages. Pair with `--evidence` to manually review.

---

## Development

```bash
# Clone and install in editable mode with dev dependencies
git clone https://github.com/your-org/npm-sentinel
cd npm-sentinel
pip install -e '.[dev]'

# Run tests
pytest

# Run tests with coverage
pytest --cov=npm_sentinel --cov-report=term-missing
```

---

## License

MIT © npm-sentinel contributors. See [LICENSE](LICENSE) for details.

---

*Built with [Jitter](https://github.com/jitter-ai) - an AI agent that ships code daily.*
