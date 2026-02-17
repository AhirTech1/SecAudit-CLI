"""Secret detection scanner.

Detects API keys, AWS credentials, JWT secrets, and high-entropy strings
in JavaScript/Node.js projects using regex rules and Shannon entropy.
"""

import math
import re
from pathlib import Path

from secaudit.models import HIGH, MEDIUM, Issue
from secaudit.utils import walk_project_files

# ---------------------------------------------------------------------------
# Regex rules — each tuple is (compiled_pattern, issue_type, severity, msg)
# ---------------------------------------------------------------------------

_RULES: list[tuple[re.Pattern[str], str, str, str]] = [
    (
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "AWS Access Key",
        HIGH,
        "Hardcoded AWS access key detected",
    ),
    (
        re.compile(
            r"[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}"
        ),
        "JWT Token",
        HIGH,
        "Possible JWT token detected",
    ),
    (
        re.compile(
            r"""(?i)(api|key|token|secret)["'\s:=]+["']?[A-Za-z0-9\-_]{16,}"""
        ),
        "Generic API Key",
        MEDIUM,
        "Possible hardcoded API key or secret",
    ),
]

# ---------------------------------------------------------------------------
# Entropy helpers
# ---------------------------------------------------------------------------

# Common tokens that look high-entropy but are harmless
_ENTROPY_SKIP_WORDS: set[str] = {
    "node_modules",
    "package-lock",
    "function",
    "constructor",
    "prototype",
    "undefined",
    "application",
    "description",
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
    "configuration",
    "implementation",
    "documentation",
    "Authorization",
    "authentication",
    "Content-Type",
}


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of *text*.

    Uses the standard formula::

        H = -Σ (p_i × log₂(p_i))

    where *p_i* is the frequency of each unique character.

    Args:
        text: The input string.

    Returns:
        Entropy value in bits.  Higher values indicate more randomness.
    """
    if not text:
        return 0.0

    length = len(text)
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1

    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


# ---------------------------------------------------------------------------
# Internal scanning helpers
# ---------------------------------------------------------------------------


def _check_regex_rules(
    line: str,
    line_num: int,
    file_path: str,
) -> list[Issue]:
    """Apply all regex rules to a single line and return any matches."""
    issues: list[Issue] = []
    for pattern, issue_type, severity, message in _RULES:
        if pattern.search(line):
            issues.append(
                Issue(
                    file_path=file_path,
                    line_number=line_num,
                    issue_type=issue_type,
                    severity=severity,
                    message=message,
                    snippet=line.strip()[:120],
                )
            )
    return issues


def _check_entropy(
    line: str,
    line_num: int,
    file_path: str,
) -> list[Issue]:
    """Flag individual tokens on *line* that exhibit high entropy."""
    issues: list[Issue] = []
    # Split on common delimiters to isolate tokens
    tokens = re.split(r'[\s"\'=:;,\(\)\[\]\{\}]+', line)

    for token in tokens:
        if len(token) < 20:
            continue
        if token in _ENTROPY_SKIP_WORDS:
            continue
        entropy = calculate_entropy(token)
        if entropy > 4.0:
            issues.append(
                Issue(
                    file_path=file_path,
                    line_number=line_num,
                    issue_type="High Entropy String",
                    severity=MEDIUM,
                    message=f"High entropy string detected (entropy={entropy:.2f})",
                    snippet=line.strip()[:120],
                )
            )
    return issues


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_file_for_secrets(file_path: str, content: str) -> list[Issue]:
    """Scan a single file's content for hardcoded secrets.

    This is the per-file API used by the unified pipeline.

    Args:
        file_path: Path to the file (for reporting).
        content: Full text content of the file.

    Returns:
        List of detected ``Issue`` objects.
    """
    issues: list[Issue] = []
    for line_num, line in enumerate(content.splitlines(), start=1):
        issues.extend(_check_regex_rules(line, line_num, file_path))
        issues.extend(_check_entropy(line, line_num, file_path))
    return issues


def scan_for_secrets(root_path: Path) -> tuple[list[Issue], int]:
    """Recursively scan a project directory for hardcoded secrets.

    Convenience wrapper that walks files and delegates to
    :func:`scan_file_for_secrets`.

    Args:
        root_path: Root directory of the project to scan.

    Returns:
        A tuple of ``(issues, files_scanned)``.
    """
    issues: list[Issue] = []
    walk = walk_project_files(root_path)

    for filepath in walk.files:
        try:
            with open(filepath, encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
        except (OSError, PermissionError):
            continue
        issues.extend(scan_file_for_secrets(filepath, content))

    return issues, walk.files_scanned
