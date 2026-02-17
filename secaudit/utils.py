"""SecAudit utility helpers."""

from pathlib import Path


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
