"""Unit tests for the unified pipeline, ScanResult model, and CLI options."""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from secaudit.cli import app
from secaudit.core.pipeline import run_scan
from secaudit.models import HIGH, LOW, MEDIUM, Issue, ScanResult

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _create_test_project(files: dict[str, str]) -> str:
    """Create a temporary project directory with the given files."""
    tmpdir = tempfile.mkdtemp(prefix="secaudit_pipe_")
    for name, content in files.items():
        filepath = os.path.join(tmpdir, name)
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w") as fh:
            fh.write(content)
    return tmpdir


def _sample_issues() -> list[Issue]:
    """Return a small set of issues for model tests."""
    return [
        Issue("a.js", 1, "AWS Access Key", HIGH, "found key", "AKIA..."),
        Issue("b.js", 5, "Generic API Key", MEDIUM, "found api key", "api=xxx"),
        Issue("c.js", 10, "Generic API Key", MEDIUM, "found api key", "key=yyy"),
    ]


# ---------------------------------------------------------------------------
# ScanResult model tests
# ---------------------------------------------------------------------------


class TestScanResult:
    """Tests for the ScanResult dataclass."""

    def test_severity_counts(self) -> None:
        """Severity counts should accurately reflect the issues."""
        result = ScanResult(
            issues=_sample_issues(),
            total_files=3,
            severity_counts={HIGH: 1, MEDIUM: 2, LOW: 0},
        )
        assert result.severity_counts[HIGH] == 1
        assert result.severity_counts[MEDIUM] == 2
        assert result.severity_counts[LOW] == 0

    def test_has_severity_high(self) -> None:
        """has_severity('HIGH') should return True when HIGH issues exist."""
        result = ScanResult(issues=_sample_issues(), total_files=3)
        assert result.has_severity(HIGH) is True

    def test_has_severity_low_when_only_medium(self) -> None:
        """has_severity('LOW') should be True when MEDIUM issues exist."""
        issues = [Issue("a.js", 1, "Test", MEDIUM, "msg", "snip")]
        result = ScanResult(issues=issues, total_files=1)
        assert result.has_severity(LOW) is True

    def test_has_severity_high_when_only_medium(self) -> None:
        """has_severity('HIGH') should be False when only MEDIUM exists."""
        issues = [Issue("a.js", 1, "Test", MEDIUM, "msg", "snip")]
        result = ScanResult(issues=issues, total_files=1)
        assert result.has_severity(HIGH) is False

    def test_to_dict_structure(self) -> None:
        """to_dict() should return expected JSON structure."""
        result = ScanResult(
            issues=_sample_issues(),
            total_files=3,
            severity_counts={HIGH: 1, MEDIUM: 2, LOW: 0},
        )
        d = result.to_dict()
        assert d["total_files"] == 3
        assert d["total_issues"] == 3
        assert d["severity"] == {"HIGH": 1, "MEDIUM": 2, "LOW": 0}
        assert len(d["issues"]) == 3
        assert d["issues"][0]["severity"] == HIGH


# ---------------------------------------------------------------------------
# Pipeline tests
# ---------------------------------------------------------------------------


class TestPipeline:
    """Tests for the run_scan pipeline."""

    def test_pipeline_returns_scan_result(self) -> None:
        """run_scan should return a ScanResult with correct counts."""
        project = _create_test_project(
            {"config.js": 'const key = "AKIAIOSFODNN7EXAMPLE";\n'}
        )
        result = run_scan(Path(project))

        assert isinstance(result, ScanResult)
        assert result.total_files == 1
        assert len(result.issues) >= 1
        assert result.severity_counts[HIGH] >= 1

    def test_pipeline_single_walk(self) -> None:
        """run_scan should call walk_project_files exactly once."""
        project = _create_test_project(
            {"app.js": 'console.log("hello");\n'}
        )

        with patch("secaudit.core.pipeline.walk_project_files", wraps=__import__("secaudit.utils", fromlist=["walk_project_files"]).walk_project_files) as mock_walk:
            run_scan(Path(project))
            assert mock_walk.call_count == 1


# ---------------------------------------------------------------------------
# CLI --json tests
# ---------------------------------------------------------------------------


class TestJSONOutput:
    """Tests for the --json CLI option."""

    def test_json_output_is_valid(self) -> None:
        """--json flag should produce valid, parseable JSON."""
        project = _create_test_project(
            {"config.js": 'const key = "AKIAIOSFODNN7EXAMPLE";\n'}
        )
        result = runner.invoke(app, ["scan", project, "--json"])

        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert "total_files" in data
        assert "total_issues" in data
        assert "severity" in data
        assert "issues" in data
        assert isinstance(data["issues"], list)

    def test_json_output_clean_project(self) -> None:
        """--json on a clean project should report zero issues."""
        project = _create_test_project(
            {"app.js": 'console.log("clean");\n'}
        )
        result = runner.invoke(app, ["scan", project, "--json"])

        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["total_issues"] == 0


# ---------------------------------------------------------------------------
# CLI --fail-on tests
# ---------------------------------------------------------------------------


class TestFailOn:
    """Tests for the --fail-on CLI option."""

    def test_fail_on_high_with_high_issue(self) -> None:
        """--fail-on HIGH should exit 1 when HIGH issues exist."""
        project = _create_test_project(
            {"config.js": 'const key = "AKIAIOSFODNN7EXAMPLE";\n'}
        )
        result = runner.invoke(app, ["scan", project, "--fail-on", "HIGH"])
        assert result.exit_code == 1

    def test_fail_on_high_without_high_issue(self) -> None:
        """--fail-on HIGH should exit 0 when no HIGH issues exist."""
        project = _create_test_project(
            {"app.js": 'console.log("clean");\n'}
        )
        result = runner.invoke(app, ["scan", project, "--fail-on", "HIGH"])
        assert result.exit_code == 0

    def test_fail_on_medium_with_medium_issue(self) -> None:
        """--fail-on MEDIUM should exit 1 when MEDIUM issues exist."""
        project = _create_test_project(
            {"env.js": 'const api_key = "sk_live_abcdefghijklmnop";\n'}
        )
        result = runner.invoke(app, ["scan", project, "--fail-on", "MEDIUM"])
        assert result.exit_code == 1

    def test_fail_on_invalid_value(self) -> None:
        """--fail-on with bad value should exit 1 with error."""
        project = _create_test_project({"app.js": 'console.log("ok");\n'})
        result = runner.invoke(app, ["scan", project, "--fail-on", "CRITICAL"])
        assert result.exit_code == 1
