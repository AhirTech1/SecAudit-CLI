"""Unit tests for file filtering and exclusion logic."""

import os
import tempfile
from pathlib import Path

from secaudit.utils import walk_project_files


def _create_test_structure(files: list[str]) -> str:
    """Create a temporary directory with the given file paths."""
    tmpdir = tempfile.mkdtemp(prefix="secaudit_filter_")
    for path in files:
        full_path = os.path.join(tmpdir, path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        # Create empty file
        with open(full_path, "w") as f:
            f.write("")
    return tmpdir


class TestFileFiltering:
    """Tests for file walker exclusions."""

    def test_ignores_lockfiles(self) -> None:
        """Lock files should be excluded from the scan."""
        project = _create_test_structure(
            [
                "package.json",
                "package-lock.json",
                "yarn.lock",
                "src/index.js",
            ]
        )
        result = walk_project_files(Path(project))

        filenames = [os.path.basename(f) for f in result.files]
        assert "index.js" in filenames
        assert "package-lock.json" not in filenames
        assert "yarn.lock" not in filenames

    def test_ignores_json_files(self) -> None:
        """Generic .json files should be ignored (removed from default ext)."""
        project = _create_test_structure(
            [
                "data.json",
                "config.json",
                "index.js",
            ]
        )
        result = walk_project_files(Path(project))

        filenames = [os.path.basename(f) for f in result.files]
        assert "index.js" in filenames
        assert "data.json" not in filenames
        assert "config.json" not in filenames

    def test_respects_custom_ignore_files(self) -> None:
        """Standard ignores like node_modules should still work."""
        project = _create_test_structure(
            [
                "node_modules/pkg/index.js",
                "src/app.js",
            ]
        )
        result = walk_project_files(Path(project))

        paths = result.files
        assert any("src/app.js" in p for p in paths)
        assert not any("node_modules" in p for p in paths)
