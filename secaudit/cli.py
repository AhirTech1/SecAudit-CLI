"""SecAudit CLI — Entry point for the security scanner."""

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from secaudit import __app_name__, __version__
from secaudit.models import HIGH, LOW, MEDIUM
from secaudit.scanners.secrets import scan_for_secrets

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
# Severity → Rich color mapping
# ---------------------------------------------------------------------------

_SEVERITY_COLORS: dict[str, str] = {
    HIGH: "red",
    MEDIUM: "yellow",
    LOW: "blue",
}

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

    # --- Run secret scanner ---
    console.print("[bold]Scanning for secrets…[/bold]\n")
    issues, files_scanned = scan_for_secrets(target)

    # --- Display results ---
    if issues:
        _print_issues_table(issues)
    else:
        console.print(
            Panel(
                "[bold green]✔ No security issues found[/bold green]",
                border_style="green",
            )
        )

    _print_summary(files_scanned, issues)


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def _print_issues_table(issues: list) -> None:
    """Render detected issues as a Rich table."""
    table = Table(
        title="🔍 Detected Issues",
        show_lines=True,
        header_style="bold magenta",
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("File", style="cyan", max_width=40)
    table.add_column("Line", justify="right", style="dim")
    table.add_column("Type", style="bold")
    table.add_column("Severity", justify="center")
    table.add_column("Message", max_width=50)

    for idx, issue in enumerate(issues, start=1):
        color = _SEVERITY_COLORS.get(issue.severity, "white")
        table.add_row(
            str(idx),
            issue.file_path,
            str(issue.line_number),
            issue.issue_type,
            f"[bold {color}]{issue.severity}[/bold {color}]",
            issue.message,
        )

    console.print(table)
    console.print()


def _print_summary(files_scanned: int, issues: list) -> None:
    """Print a scan summary with severity breakdown."""
    severity_counts: dict[str, int] = {HIGH: 0, MEDIUM: 0, LOW: 0}
    for issue in issues:
        severity_counts[issue.severity] = severity_counts.get(issue.severity, 0) + 1

    summary_lines = [
        f"[bold]Files scanned:[/bold] {files_scanned}",
        f"[bold]Total issues:[/bold]  {len(issues)}",
        "",
        f"[bold red]HIGH:[/bold red]   {severity_counts[HIGH]}",
        f"[bold yellow]MEDIUM:[/bold yellow] {severity_counts[MEDIUM]}",
        f"[bold blue]LOW:[/bold blue]    {severity_counts[LOW]}",
    ]

    console.print(
        Panel(
            "\n".join(summary_lines),
            title="📊 Scan Summary",
            border_style="cyan",
        )
    )
