"""Unit tests for the secret detection scanner."""

import os
import re
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
        """A string with diverse characters should have high entropy (updated threshold > 4.5)."""
        # "aB3$kL9@mZ1!pQ7&xR5" is 19 unique chars in 19 positions? No, check length.
        # len is 19. If all unique, H = -19 * (1/19 * log2(1/19)) = log2(19) ≈ 4.24.
        # Wait, 4.24 is < 4.5.
        # I need a higher entropy string for the test to pass with threshold 4.5.
        # "1234567890abcdefABCDEF" -> 22 unique chars. log2(22) ≈ 4.45. Still borderline.
        # Let's use a longer random string.
        # "7yH9@qL2#mZ5!nK8$xP4&rW1%vB6*c" (30 chars, very mixed)
        random_str = "7yH9@qL2#mZ5!nK8$xP4&rW1%vB6*c"
        entropy = calculate_entropy(random_str)
        # Assuming most are unique. 30 chars. log2(30) ≈ 4.9.
        assert entropy > 4.5, f"Expected entropy > 4.5, got {entropy:.2f}"

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


# ---------------------------------------------------------------------------
# Regex detection tests
# ---------------------------------------------------------------------------


def _create_test_project(files: dict[str, str]) -> str:
    """Create a temporary project directory with the given files."""
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


class TestEntropyPrecision:
    """Tests for enhanced entropy scanning rules (Commit 5)."""

    def test_ignores_uuid(self) -> None:
        """UUID strings inside quotes should be ignored."""
        project = _create_test_project(
            {"data.js": 'const id = "123e4567-e89b-12d3-a456-426614174000";'}
        )
        issues, _ = scan_for_secrets(Path(project))
        entr = [i for i in issues if i.issue_type == "High Entropy String"]
        assert len(entr) == 0

    def test_ignores_hex_string(self) -> None:
        """Long hex strings (hashes) should be ignored."""
        # 32 chars hex
        hex_str = "5d41402abc4b2a76b9719d911017c592"
        project = _create_test_project(
            {"hash.js": f'const hash = "{hex_str}";'}
        )
        issues, _ = scan_for_secrets(Path(project))
        entr = [i for i in issues if i.issue_type == "High Entropy String"]
        assert len(entr) == 0

    def test_detects_high_entropy_literal(self) -> None:
        """Random string literals should still be detected."""
        # Need > 4.5.
        # "Xy7z9QaBWC-3dEfGhIjK" (20 chars). unique=20. log2(20)=4.32. FAIL if threshold is 4.5.
        # "Xy7z9QaBWC-3dEfGhIjKLMNOP" (25 chars). log2(25)=4.64. PASS.
        secret = "Xy7z9QaBWC-3dEfGhIjKLMNOP"
        project = _create_test_project(
            {"secret.js": 'const token = "Xy7z9QaBWC-3dEfGhIjKLMNOP";'}
        )
        issues, _ = scan_for_secrets(Path(project))
        
        entr = [i for i in issues if i.issue_type == "High Entropy String"]
        assert len(entr) == 1

    def test_ignores_safe_keywords(self) -> None:
        """Line containing 'checksum' or 'integrity' should be skipped."""
        secret = "Xy7z9QaBWC-3dEfGhIjKLMNOP"
        project = _create_test_project(
            {"lib.js": f'const checksum = "{secret}"; // integrity check'}
        )
        issues, _ = scan_for_secrets(Path(project))
        entr = [i for i in issues if i.issue_type == "High Entropy String"]
        assert len(entr) == 0

    def test_ignores_unquoted_high_entropy(self) -> None:
        """High entropy sequence NOT in quotes (e.g. variable name) should be ignored."""
        project = _create_test_project(
            {"code.js": 'const Xy7z9QaBWC3dEfGhIjKLMNOP = 123;'}
        )
        issues, _ = scan_for_secrets(Path(project))
        entr = [i for i in issues if i.issue_type == "High Entropy String"]
        assert len(entr) == 0
