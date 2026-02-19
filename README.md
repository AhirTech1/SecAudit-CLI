# 🔒 SecAudit

> A security scanner for JavaScript / Node.js projects that detects common security misconfigurations, insecure patterns, and secret leaks.

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## Features

- 🔑 **Secret Detection** — AWS keys, JWT tokens, generic API keys, high-entropy strings
- ⚠️ **Insecure Pattern Scanner** — `eval()`, `new Function()`, `child_process.exec/spawn`, missing Helmet/rate-limiting, potential IDOR
- 📦 **Dependency Scanner** *(coming soon)* — Outdated & risky packages in `package.json`
- 🤖 **AI Explainer** *(optional, coming soon)* — LLM-powered vulnerability explanations
- 📊 **Rich CLI Output** — Color-coded tables, severity breakdown, scan summary
- 🔧 **CI-Friendly** — `--json` output and `--fail-on` severity gating

## Installation

```bash
pip install -e .
```

## Usage

```bash
# Scan the current directory
secaudit scan .

# Scan a specific project
secaudit scan /path/to/your/project

# JSON output (for CI pipelines)
secaudit scan . --json

# Fail if HIGH severity issues found (exit code 1)
secaudit scan . --fail-on HIGH

# Combine options
secaudit scan . --json --fail-on MEDIUM

# Show version
secaudit --version
```

## What It Detects

### Secrets (HIGH / MEDIUM)

| Pattern | Severity |
|---------|----------|
| AWS Access Keys (`AKIA...`) | HIGH |
| JWT Tokens (3-segment base64) | HIGH |
| Generic API keys/tokens/secrets | MEDIUM |
| High entropy strings (Shannon entropy > 4.0) | MEDIUM |

### Insecure Patterns (HIGH / MEDIUM)

| Pattern | Severity |
|---------|----------|
| `eval()`, `new Function()` | HIGH |
| `child_process.exec()`, `.spawn()` | HIGH |
| Express app without `helmet()` | MEDIUM |
| Express app without rate limiting | MEDIUM |
| Route params used without validation (IDOR) | MEDIUM |

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v
```

## Architecture

```
secaudit/
├── core/
│   └── pipeline.py      # Unified scan pipeline (single file walk)
├── scanners/
│   ├── secrets.py       # Regex + entropy-based secret detection
│   ├── patterns.py      # Insecure code pattern detection
│   └── dependencies.py  # (coming soon)
├── ai/
│   └── explainer.py     # (coming soon)
├── models.py            # Issue, ScanResult data models
├── config.py            # Scan config (extensions, ignored dirs)
├── utils.py             # Shared file walker, path validation
└── cli.py               # Typer CLI with Rich output
```

## License

MIT
