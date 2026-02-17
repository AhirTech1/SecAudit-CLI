"""SecAudit CLI — Entry point for the security scanner."""

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel

from secaudit import __app_name__, __version__

# ---------------------------------------------------------------------------
# App & Console
# ---------------------------------------------------------------------------

app = typer.Typer(
    name=__app_name__,
    help="🔒 SecAudit — Security scanner for JavaScript/Node.js projects.",
    add_completion=False,
    rich_markup_mode="rich",
)

console = Console()

# ---------------------------------------------------------------------------
# Version callback
# ---------------------------------------------------------------------------


def _version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"[bold cyan]{__app_name__}[/bold cyan] v{__version__}")
        raise typer.Exit()


# ---------------------------------------------------------------------------
# Global options
# ---------------------------------------------------------------------------


@app.callback()
def main(
    version: Optional[bool] = typer.Option(  # noqa: UP007
        None,
        "--version",
        "-v",
        help="Show the application version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """SecAudit — detect security issues in your JS/Node.js projects."""


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@app.command()
def scan(
    path: str = typer.Argument(
        ...,
        help="Path to the project directory to scan.",
    ),
) -> None:
    """Scan a JavaScript/Node.js project for security issues."""

    target = Path(path).resolve()

    # --- Validate path ---
    if not target.exists():
        console.print(f"[bold red]✗[/bold red] Path does not exist: {target}")
        raise typer.Exit(code=1)

    if not target.is_dir():
        console.print(f"[bold red]✗[/bold red] Path is not a directory: {target}")
        raise typer.Exit(code=1)

    # --- Initialization banner ---
    console.print(
        Panel(
            "[bold green]SecAudit initialized[/bold green]",
            title="🔒 SecAudit",
            subtitle=f"v{__version__}",
            border_style="cyan",
        )
    )
    console.print(f"[dim]Target:[/dim] {target}\n")
