"""Insecure pattern scanner.

Detects dangerous function calls (eval, new Function, child_process.exec/spawn),
missing security middleware (Helmet, rate-limiting), and potential IDOR risks
in JavaScript/Node.js Express applications.
"""

import re
from pathlib import Path

from secaudit.models import HIGH, MEDIUM, Issue
from secaudit.utils import walk_project_files

# ---------------------------------------------------------------------------
# 1. Dangerous code execution patterns (line-by-line)
# ---------------------------------------------------------------------------

_DANGEROUS_EXEC_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\beval\s*\("), "eval()"),
    (re.compile(r"\bnew\s+Function\s*\("), "new Function()"),
    (re.compile(r"child_process\s*\.\s*exec\s*\("), "child_process.exec()"),
    (re.compile(r"child_process\s*\.\s*spawn\s*\("), "child_process.spawn()"),
]

# ---------------------------------------------------------------------------
# 2. IDOR heuristic helpers
# ---------------------------------------------------------------------------

_ROUTE_PARAM_RE = re.compile(r"""(app|router)\.(get|post|put|patch|delete)\s*\(\s*["'][^"']*:[a-zA-Z]+""")
_REQ_PARAMS_RE = re.compile(r"req\.params\.\w+")
_VALIDATION_KEYWORDS = re.compile(r"(?i)(joi|zod|validate|parseInt|Number\(|parseFloat|celebrate|express-validator)")

# ---------------------------------------------------------------------------
# 3. Express middleware detection
# ---------------------------------------------------------------------------

_EXPRESS_RE = re.compile(r"\bexpress\s*\(\s*\)")
_HELMET_RE = re.compile(r"\bhelmet\s*\(")
_RATE_LIMIT_RE = re.compile(r"(\brateLimit\s*\(|express-rate-limit)")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _check_dangerous_exec(
    line: str,
    line_num: int,
    file_path: str,
) -> list[Issue]:
    """Flag dangerous code execution calls on a single line."""
    issues: list[Issue] = []
    for pattern, label in _DANGEROUS_EXEC_RULES:
        if pattern.search(line):
            issues.append(
                Issue(
                    file_path=file_path,
                    line_number=line_num,
                    issue_type="Dangerous Code Execution",
                    severity=HIGH,
                    message=f"Use of {label} detected — potential code injection risk",
                    snippet=line.strip()[:120],
                )
            )
    return issues


def _check_file_level_issues(
    content: str,
    file_path: str,
) -> list[Issue]:
    """Run file-level heuristics for Express middleware & IDOR.

    These checks operate on the entire file content rather than
    individual lines.
    """
    issues: list[Issue] = []
    is_express_app = bool(_EXPRESS_RE.search(content))

    # --- Missing Helmet ---
    if is_express_app and not _HELMET_RE.search(content):
        issues.append(
            Issue(
                file_path=file_path,
                line_number=1,
                issue_type="Missing Helmet Middleware",
                severity=MEDIUM,
                message="Express app without helmet() — missing HTTP security headers",
                snippet="express() detected but helmet() not found",
            )
        )

    # --- Missing Rate Limiting ---
    if is_express_app and not _RATE_LIMIT_RE.search(content):
        issues.append(
            Issue(
                file_path=file_path,
                line_number=1,
                issue_type="Missing Rate Limiting",
                severity=MEDIUM,
                message="Express app without rate limiting — vulnerable to brute-force/DoS",
                snippet="express() detected but rateLimit() not found",
            )
        )

    # --- Potential IDOR ---
    if _ROUTE_PARAM_RE.search(content) and _REQ_PARAMS_RE.search(content):
        if not _VALIDATION_KEYWORDS.search(content):
            for line_num, line in enumerate(content.splitlines(), start=1):
                if _REQ_PARAMS_RE.search(line):
                    issues.append(
                        Issue(
                            file_path=file_path,
                            line_number=line_num,
                            issue_type="Potential IDOR Risk",
                            severity=MEDIUM,
                            message="Route parameter used without validation — potential IDOR",
                            snippet=line.strip()[:120],
                        )
                    )
                    break  # Only flag once per file

    return issues


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_file_for_patterns(file_path: str, content: str) -> list[Issue]:
    """Scan a single file's content for insecure code patterns.

    This is the per-file API used by the unified pipeline.

    Args:
        file_path: Path to the file (for reporting).
        content: Full text content of the file.

    Returns:
        List of detected ``Issue`` objects.
    """
    issues: list[Issue] = []

    # Line-by-line: dangerous execution calls
    for line_num, line in enumerate(content.splitlines(), start=1):
        issues.extend(_check_dangerous_exec(line, line_num, file_path))

    # File-level: middleware & IDOR checks
    issues.extend(_check_file_level_issues(content, file_path))

    return issues


def scan_for_patterns(root_path: Path) -> tuple[list[Issue], int]:
    """Recursively scan a project for insecure code patterns.

    Convenience wrapper that walks files and delegates to
    :func:`scan_file_for_patterns`.

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
        issues.extend(scan_file_for_patterns(filepath, content))

    return issues, walk.files_scanned
