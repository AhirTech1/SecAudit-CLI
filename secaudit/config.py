"""SecAudit configuration constants."""

from secaudit import __app_name__, __version__

APP_NAME: str = __app_name__
VERSION: str = __version__

# Directories / files to skip during scanning
DEFAULT_IGNORE_DIRS: list[str] = [
    "node_modules",
    ".git",
    "dist",
    "build",
    "coverage",
    ".next",
]

DEFAULT_SCAN_EXTENSIONS: list[str] = [
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".json",
    ".env",
]
