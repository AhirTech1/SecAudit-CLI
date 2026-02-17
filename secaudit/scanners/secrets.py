"""Secret detection scanner.

Detects API keys, AWS credentials, JWT secrets, and high-entropy strings
in JavaScript/Node.js projects using regex rules and Shannon entropy.
"""

import math
import os
import re
from pathlib import Path

from secaudit.config import DEFAULT_IGNORE_DIRS, DEFAULT_SCAN_EXTENSIONS
from secaudit.models import HIGH, MEDIUM, Issue

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


def scan_for_secrets(root_path: Path) -> tuple[list[Issue], int]:
    """Recursively scan a project directory for hardcoded secrets.

    Args:
        root_path: Root directory of the project to scan.

    Returns:
        A tuple of ``(issues, files_scanned)`` where *issues* is the list
        of detected ``Issue`` objects and *files_scanned* is the total
        number of files that were inspected.
    """
    issues: list[Issue] = []
    files_scanned: int = 0

    ignore_dirs = set(DEFAULT_IGNORE_DIRS)
    scan_extensions = set(DEFAULT_SCAN_EXTENSIONS)

    for dirpath, dirnames, filenames in os.walk(root_path):
        # Prune ignored directories in-place so os.walk skips them
        dirnames[:] = [d for d in dirnames if d not in ignore_dirs]

        for filename in filenames:
            ext = os.path.splitext(filename)[1]
            if ext not in scan_extensions:
                continue

            filepath = os.path.join(dirpath, filename)
            files_scanned += 1

            try:
                with open(filepath, encoding="utf-8", errors="ignore") as fh:
                    for line_num, line in enumerate(fh, start=1):
                        issues.extend(_check_regex_rules(line, line_num, filepath))
                        issues.extend(_check_entropy(line, line_num, filepath))
            except (OSError, PermissionError):
                # Skip unreadable files silently
                continue

    return issues, files_scanned
