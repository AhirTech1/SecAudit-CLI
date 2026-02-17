# 🔒 SecAudit

> A security scanner for JavaScript / Node.js projects that detects common security misconfigurations, insecure patterns, and secret leaks.

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## Features

- 🔑 **Secret Detection** — API keys, AWS credentials, JWT secrets, high-entropy strings
- ⚠️ **Insecure Pattern Scanner** — `eval()`, `child_process.exec`, missing security middleware
- 📦 **Dependency Scanner** — Outdated & risky packages in `package.json`
- 🤖 **AI Explainer** *(optional)* — LLM-powered vulnerability explanations

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

# Show version
secaudit --version
```

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest
```

## License

MIT
