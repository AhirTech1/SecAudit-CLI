"""SecAudit utility helpers."""

import os
from collections.abc import Generator
from pathlib import Path

from secaudit.config import (
    DEFAULT_IGNORE_DIRS,
    DEFAULT_IGNORE_FILES,
    DEFAULT_SCAN_EXTENSIONS,
)


def validate_path(path: str) -> Path:
    """Resolve and validate that *path* points to an existing directory.

    Args:
        path: Raw path string from the CLI.

    Returns:
        Resolved ``Path`` object.

    Raises:
        FileNotFoundError: If the path does not exist.
        NotADirectoryError: If the path is not a directory.
    """
    resolved = Path(path).resolve()

    if not resolved.exists():
        raise FileNotFoundError(f"Path does not exist: {resolved}")

    if not resolved.is_dir():
        raise NotADirectoryError(f"Path is not a directory: {resolved}")

    return resolved


class FileWalkResult:
    """Container returned by :func:`walk_project_files`.

    Attributes:
        files: List of absolute file paths that matched the scan criteria.
        files_scanned: Total number of files that were inspected.
    """

    __slots__ = ("files", "files_scanned")

    def __init__(self) -> None:
        self.files: list[str] = []
        self.files_scanned: int = 0


def walk_project_files(
    root_path: Path,
    *,
    ignore_dirs: set[str] | None = None,
    scan_extensions: set[str] | None = None,
) -> FileWalkResult:
    """Walk a project directory and collect scannable file paths.

    Respects ``DEFAULT_IGNORE_DIRS``, ``DEFAULT_IGNORE_FILES``, and
    ``DEFAULT_SCAN_EXTENSIONS`` from config unless overrides are provided.

    Args:
        root_path: Root directory to walk.
        ignore_dirs: Optional set of directory names to skip.
        scan_extensions: Optional set of file extensions to include.

    Returns:
        A :class:`FileWalkResult` with the matching file paths and count.
    """
    _ignore_dirs = (
        ignore_dirs if ignore_dirs is not None else set(DEFAULT_IGNORE_DIRS)
    )
    _extensions = (
        scan_extensions if scan_extensions is not None else set(DEFAULT_SCAN_EXTENSIONS)
    )

    result = FileWalkResult()

    for dirpath, dirnames, filenames in os.walk(root_path):
        # Prune ignored directories in-place so os.walk skips them
        dirnames[:] = [d for d in dirnames if d not in _ignore_dirs]

        for filename in filenames:
            if filename in DEFAULT_IGNORE_FILES:
                continue

            ext = os.path.splitext(filename)[1]
            if ext not in _extensions:
                continue

            result.files.append(os.path.join(dirpath, filename))
            result.files_scanned += 1

    return result
