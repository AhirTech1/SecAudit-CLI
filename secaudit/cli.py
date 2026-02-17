"""SecAudit CLI — Entry point for the security scanner."""

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from secaudit import __app_name__, __version__
from secaudit.core.pipeline import run_scan
from secaudit.models import HIGH, LOW, MEDIUM, ScanResult

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
    output_json: bool = typer.Option(
        False,
        "--json",
        help="Output results as JSON instead of Rich tables.",
    ),
    fail_on: Optional[str] = typer.Option(  # noqa: UP007
        None,
        "--fail-on",
        help="Exit with code 1 if any issue meets this severity (HIGH, MEDIUM, LOW).",
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

    # --- Validate --fail-on value ---
    if fail_on is not None:
        fail_on = fail_on.upper()
        if fail_on not in (HIGH, MEDIUM, LOW):
            console.print(
                f"[bold red]✗[/bold red] Invalid --fail-on value: {fail_on}. "
                f"Must be one of: HIGH, MEDIUM, LOW"
            )
            raise typer.Exit(code=1)

    # --- Run unified pipeline ---
    if not output_json:
        console.print(
            Panel(
                "[bold green]SecAudit initialized[/bold green]",
                title="🔒 SecAudit",
                subtitle=f"v{__version__}",
                border_style="cyan",
            )
        )
        console.print(f"[dim]Target:[/dim] {target}\n")
        console.print("[bold]Scanning…[/bold]\n")

    result = run_scan(target)

    # --- Output ---
    if output_json:
        _print_json(result)
    else:
        _print_rich(result)

    # --- Fail-on check ---
    if fail_on and result.has_severity(fail_on):
        if not output_json:
            console.print(
                f"\n[bold red]✗ Scan failed:[/bold red] "
                f"Issues at severity [bold]{fail_on}[/bold] or above were found."
            )
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def _print_json(result: ScanResult) -> None:
    """Print scan results as structured JSON."""
    print(json.dumps(result.to_dict(), indent=2))


def _print_rich(result: ScanResult) -> None:
    """Render scan results using Rich tables and panels."""
    if result.issues:
        _print_issues_table(result)
    else:
        console.print(
            Panel(
                "[bold green]✔ No security issues found[/bold green]",
                border_style="green",
            )
        )
    _print_summary(result)


def _print_issues_table(result: ScanResult) -> None:
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

    for idx, issue in enumerate(result.issues, start=1):
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


def _print_summary(result: ScanResult) -> None:
    """Print a scan summary with severity breakdown."""
    sc = result.severity_counts

    summary_lines = [
        f"[bold]Files scanned:[/bold] {result.total_files}",
        f"[bold]Total issues:[/bold]  {len(result.issues)}",
        "",
        f"[bold red]HIGH:[/bold red]   {sc.get(HIGH, 0)}",
        f"[bold yellow]MEDIUM:[/bold yellow] {sc.get(MEDIUM, 0)}",
        f"[bold blue]LOW:[/bold blue]    {sc.get(LOW, 0)}",
    ]

    console.print(
        Panel(
            "\n".join(summary_lines),
            title="📊 Scan Summary",
            border_style="cyan",
        )
    )
