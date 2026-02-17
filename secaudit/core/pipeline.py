"""Unified scanning pipeline.

Walks the project file tree **once** and dispatches each file's content
to every registered scanner, collecting results into a single
:class:`~secaudit.models.ScanResult`.
"""

from pathlib import Path

from secaudit.models import HIGH, LOW, MEDIUM, Issue, ScanResult
from secaudit.scanners.patterns import scan_file_for_patterns
from secaudit.scanners.secrets import scan_file_for_secrets
from secaudit.utils import walk_project_files


def run_scan(root_path: Path) -> ScanResult:
    """Execute a full security scan on *root_path*.

    Files are walked **once**.  Each file is read **once** and its
    content is handed to all registered per-file scanners.

    Args:
        root_path: Root directory of the project to scan.

    Returns:
        A :class:`ScanResult` containing all findings and metadata.
    """
    all_issues: list[Issue] = []
    walk = walk_project_files(root_path)

    for filepath in walk.files:
        try:
            with open(filepath, encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
        except (OSError, PermissionError):
            continue

        all_issues.extend(scan_file_for_secrets(filepath, content))
        all_issues.extend(scan_file_for_patterns(filepath, content))

    # Build severity counts
    severity_counts: dict[str, int] = {HIGH: 0, MEDIUM: 0, LOW: 0}
    for issue in all_issues:
        severity_counts[issue.severity] = severity_counts.get(issue.severity, 0) + 1

    return ScanResult(
        issues=all_issues,
        total_files=walk.files_scanned,
        severity_counts=severity_counts,
    )
