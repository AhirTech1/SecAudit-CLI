"""SecAudit data models for scan findings."""

from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Severity constants
# ---------------------------------------------------------------------------

HIGH: str = "HIGH"
MEDIUM: str = "MEDIUM"
LOW: str = "LOW"


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
