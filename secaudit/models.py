"""SecAudit data models for scan findings."""

from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Severity constants & ordering
# ---------------------------------------------------------------------------

HIGH: str = "HIGH"
MEDIUM: str = "MEDIUM"
LOW: str = "LOW"

SEVERITY_ORDER: dict[str, int] = {
    HIGH: 3,
    MEDIUM: 2,
    LOW: 1,
}


# ---------------------------------------------------------------------------
# Issue model
# ---------------------------------------------------------------------------


@dataclass
class Issue:
    """Represents a single security finding detected during a scan.

    Attributes:
        file_path: Absolute or relative path to the affected file.
        line_number: 1-based line number where the issue was found.
        issue_type: Category of the issue (e.g. "AWS Access Key").
        severity: Risk level — ``HIGH``, ``MEDIUM``, or ``LOW``.
        message: Human-readable description of the finding.
        snippet: The source line (trimmed) that triggered the detection.
    """

    file_path: str
    line_number: int
    issue_type: str
    severity: str
    message: str
    snippet: str

    def __str__(self) -> str:
        return (
            f"[{self.severity}] {self.issue_type} "
            f"at {self.file_path}:{self.line_number} — {self.message}"
        )

    def to_dict(self) -> dict:
        """Return a JSON-serializable dictionary representation."""
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "issue_type": self.issue_type,
            "severity": self.severity,
            "message": self.message,
            "snippet": self.snippet,
        }


# ---------------------------------------------------------------------------
# ScanResult model
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    """Aggregated result from a complete scan run.

    Attributes:
        issues: All detected issues across every scanner.
        total_files: Number of files that were inspected.
        severity_counts: Breakdown of issues by severity level.
    """

    issues: list[Issue] = field(default_factory=list)
    total_files: int = 0
    severity_counts: dict[str, int] = field(
        default_factory=lambda: {HIGH: 0, MEDIUM: 0, LOW: 0}
    )

    # --- helpers ---

    def has_severity(self, level: str) -> bool:
        """Return ``True`` if any issue meets or exceeds *level*.

        Severity ordering: ``HIGH > MEDIUM > LOW``.
        """
        threshold = SEVERITY_ORDER.get(level, 0)
        return any(
            SEVERITY_ORDER.get(issue.severity, 0) >= threshold
            for issue in self.issues
        )

    def to_dict(self) -> dict:
        """Return a JSON-serializable dictionary of the full scan result."""
        return {
            "total_files": self.total_files,
            "total_issues": len(self.issues),
            "severity": dict(self.severity_counts),
            "issues": [issue.to_dict() for issue in self.issues],
        }
