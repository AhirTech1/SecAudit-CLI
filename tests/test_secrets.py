"""Unit tests for the secret detection scanner."""

import os
import tempfile
from pathlib import Path

import pytest

from secaudit.models import HIGH, MEDIUM
from secaudit.scanners.secrets import calculate_entropy, scan_for_secrets


# ---------------------------------------------------------------------------
# Entropy tests
# ---------------------------------------------------------------------------


class TestCalculateEntropy:
    """Tests for the Shannon entropy function."""

    def test_high_entropy_random_string(self) -> None:
        """A string with diverse characters should have high entropy."""
        random_str = "aB3$kL9@mZ1!pQ7&xR5"
        entropy = calculate_entropy(random_str)
        assert entropy > 4.0, f"Expected entropy > 4.0, got {entropy:.2f}"

    def test_low_entropy_repeated_chars(self) -> None:
        """A string of repeated characters should have zero entropy."""
        repeated = "aaaaaaaaaa"
        entropy = calculate_entropy(repeated)
        assert entropy == 0.0, f"Expected 0.0 entropy, got {entropy:.2f}"

    def test_empty_string(self) -> None:
        """Empty string should return zero entropy."""
        assert calculate_entropy("") == 0.0

    def test_single_character(self) -> None:
        """A single character has zero entropy."""
        assert calculate_entropy("x") == 0.0

    def test_two_distinct_characters_equal_frequency(self) -> None:
        """'ab' should have entropy of exactly 1.0 bit."""
        entropy = calculate_entropy("ab")
        assert abs(entropy - 1.0) < 1e-9


# ---------------------------------------------------------------------------
# Regex detection tests
# ---------------------------------------------------------------------------


def _create_test_project(files: dict[str, str]) -> str:
    """Create a temporary project directory with the given files.

    Args:
        files: Mapping of ``{filename: content}``.

    Returns:
        Path to the temporary directory.
    """
    tmpdir = tempfile.mkdtemp(prefix="secaudit_test_")
    for name, content in files.items():
        filepath = os.path.join(tmpdir, name)
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w") as fh:
            fh.write(content)
    return tmpdir


class TestAWSKeyDetection:
    """Tests for AWS access key regex rule."""

    def test_detects_aws_key(self) -> None:
        """A file containing an AWS key should yield a HIGH issue."""
        project = _create_test_project(
            {"config.js": 'const key = "AKIAIOSFODNN7EXAMPLE";\n'}
        )
        issues, files_scanned = scan_for_secrets(Path(project))

        assert files_scanned == 1
        aws_issues = [i for i in issues if i.issue_type == "AWS Access Key"]
        assert len(aws_issues) >= 1
        assert aws_issues[0].severity == HIGH

    def test_no_false_positive_on_clean_file(self) -> None:
        """A normal JS file should produce no AWS key issues."""
        project = _create_test_project(
            {"app.js": 'console.log("Hello, world!");\n'}
        )
        issues, files_scanned = scan_for_secrets(Path(project))

        assert files_scanned == 1
        aws_issues = [i for i in issues if i.issue_type == "AWS Access Key"]
        assert len(aws_issues) == 0


class TestGenericAPIKeyDetection:
    """Tests for generic API key regex rule."""

    def test_detects_generic_api_key(self) -> None:
        """A line with 'api_key = "long_value"' should be flagged."""
        project = _create_test_project(
            {"env.js": 'const api_key = "sk_live_abcdefghijklmnop";\n'}
        )
        issues, _ = scan_for_secrets(Path(project))

        api_issues = [i for i in issues if i.issue_type == "Generic API Key"]
        assert len(api_issues) >= 1
        assert api_issues[0].severity == MEDIUM


class TestIgnoredDirectories:
    """Ensure files inside ignored directories are skipped."""

    def test_skips_node_modules(self) -> None:
        """Files inside node_modules should not be scanned."""
        project = _create_test_project(
            {
                "node_modules/pkg/index.js": 'const key = "AKIAIOSFODNN7EXAMPLE";\n',
                "index.js": 'console.log("clean");\n',
            }
        )
        issues, files_scanned = scan_for_secrets(Path(project))

        # Only the root index.js should be scanned
        assert files_scanned == 1
        aws_issues = [i for i in issues if i.issue_type == "AWS Access Key"]
        assert len(aws_issues) == 0
