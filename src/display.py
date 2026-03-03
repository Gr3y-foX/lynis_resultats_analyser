"""
Terminal display layer — uses `rich` for all output.
"""

from typing import Dict, List, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.rule import Rule
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax
from rich import box
from rich.columns import Columns

console = Console()

# Severity → color mapping
SEV_COLOR = {
    "high":    "bold red",
    "medium":  "bold yellow",
    "low":     "bold green",
    "unknown": "dim",
}

RISK_COLOR = {
    "critical": "bold red",
    "high":     "bold orange1",
    "medium":   "bold yellow",
    "low":      "bold green",
}


# ──────────────────────────────────────────────────────────────────────────────
# Banner
# ──────────────────────────────────────────────────────────────────────────────

def print_banner():
    console.print()
    console.print(Panel.fit(
        "[bold cyan]  Lynis Audit Analyzer  [/bold cyan]\n"
        "[dim]  Local · Private · Automated  [/dim]",
        border_style="cyan",
    ))
    console.print()


# ──────────────────────────────────────────────────────────────────────────────
# Lynis execution progress
# ──────────────────────────────────────────────────────────────────────────────

def print_run_start(lynis_bin: str, version: Optional[str]):
    ver_str = f" [dim](v{version})[/dim]" if version else ""
    console.print(Rule(f"[cyan]Running Lynis Audit{ver_str}[/cyan]"))
    console.print(f"[dim]Binary:[/dim] {lynis_bin}")
    console.print()


def lynis_progress_callback(line: str):
    """Called for each output line from lynis subprocess."""
    if line.strip():
        console.print(f"  [dim]{line}[/dim]")


def print_run_done():
    console.print()
    console.print("[bold green]✓[/bold green] Lynis audit completed.")
    console.print()


# ──────────────────────────────────────────────────────────────────────────────
# Score & summary header
# ──────────────────────────────────────────────────────────────────────────────

def print_summary(analysis: Dict):
    meta  = analysis.get("meta", {})
    score = analysis.get("score", 0)
    risk  = analysis.get("risk", "unknown")
    sev   = analysis.get("severity_counts", {})

    # Score badge
    risk_col   = RISK_COLOR.get(risk, "white")
    score_text = Text(f"  {score}/100  ", style=f"{risk_col} on grey7")

    console.print(Rule("[bold]Security Summary[/bold]"))
    console.print()

    # Score + risk side by side
    left  = Panel(score_text, title="Hardening Score", border_style=risk_col, width=22)
    right = Panel(
        f"[{risk_col}]{risk.upper()}[/{risk_col}]",
        title="Risk Level",
        border_style=risk_col,
        width=20,
    )
    console.print(Columns([left, right]))
    console.print()

    # Metadata table
    info_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    info_table.add_column("Key",   style="dim",  no_wrap=True)
    info_table.add_column("Value", style="white", no_wrap=True)

    rows = [
        ("Host",    meta.get("hostname", "unknown")),
        ("OS",      f"{meta.get('os', '?')} {meta.get('os_version', '')}".strip()),
        ("Kernel",  meta.get("kernel_version", "unknown")),
        ("Scan",    meta.get("scan_date", "unknown")),
        ("Lynis",   meta.get("lynis_version", "unknown")),
        ("Tests",   str(meta.get("lynis_tests_done", "?"))),
    ]
    for key, val in rows:
        if val and val not in ("unknown", "? ", "?"):
            info_table.add_row(key, val)

    console.print(info_table)
    console.print()

    # Severity counts
    sev_table = Table(box=box.SIMPLE_HEAD, title="Findings by Severity")
    sev_table.add_column("Severity", style="bold")
    sev_table.add_column("Count",    justify="right")

    for sev_name, color in [("high", "bold red"), ("medium", "bold yellow"), ("low", "bold green")]:
        count = sev.get(sev_name, 0)
        sev_table.add_row(
            Text(sev_name.capitalize(), style=color),
            str(count),
        )
    console.print(sev_table)
    console.print()

    # Top categories
    top = analysis.get("top_categories", [])
    if top:
        cat_table = Table(box=box.SIMPLE_HEAD, title="Top Affected Categories")
        cat_table.add_column("Category", style="cyan")
        cat_table.add_column("Findings", justify="right")
        for cat, count in top:
            cat_table.add_row(cat, str(count))
        console.print(cat_table)
        console.print()


# ──────────────────────────────────────────────────────────────────────────────
# Review mode — grouped findings
# ──────────────────────────────────────────────────────────────────────────────

def print_review(analysis: Dict, enriched_findings: List[Dict]):
    console.print(Rule("[bold cyan]Full Review[/bold cyan]"))
    console.print()

    if not enriched_findings:
        console.print("[green]No warnings or suggestions found.[/green]")
        return

    category_map = analysis.get("category_map", {})

    # Group enriched findings by category
    cat_findings: Dict[str, List[Dict]] = {}
    for f in enriched_findings:
        cat = f.get("category", "Other")
        cat_findings.setdefault(cat, []).append(f)

    for cat in sorted(cat_findings.keys()):
        items = cat_findings[cat]
        console.print(Rule(f"[bold]{cat}[/bold] ({len(items)})", style="dim"))

        for f in items:
            sev   = f.get("severity", "low")
            color = SEV_COLOR.get(sev, "white")
            tid   = f.get("id", "?")
            desc  = f.get("description", "")
            detail= f.get("detail", "")
            kind  = f.get("type", "")

            icon = "⚠" if kind == "warning" else "•"
            console.print(f"  [{color}]{icon} [{tid}][/{color}]  {desc}")
            if detail:
                console.print(f"    [dim]{detail}[/dim]")

        console.print()


# ──────────────────────────────────────────────────────────────────────────────
# Fix mode — per finding, commands + explanation
# ──────────────────────────────────────────────────────────────────────────────

def print_fixes(enriched_findings: List[Dict]):
    console.print(Rule("[bold cyan]Fix Commands[/bold cyan]"))
    console.print()

    if not enriched_findings:
        console.print("[green]Nothing to fix — no findings.[/green]")
        return

    no_fix = []
    for f in enriched_findings:
        fix = f.get("fix")
        tid = f.get("id", "?")
        sev = f.get("severity", "low")
        col = SEV_COLOR.get(sev, "white")
        desc = f.get("description", "")

        if not fix:
            no_fix.append(f)
            continue

        # Header for this fix
        console.print(Panel(
            f"[{col}][{tid}][/{col}]  {desc}",
            border_style=col,
            padding=(0, 1),
        ))

        # Why (one sentence)
        console.print(f"  [bold]Why:[/bold] {fix.get('why', '')}")
        console.print()

        # Commands block
        cmds = fix.get("cmds", [])
        if cmds:
            code = "\n".join(cmds)
            console.print(Syntax(code, "bash", theme="monokai", line_numbers=False, word_wrap=True))

        console.print()

    if no_fix:
        console.print(Rule("[dim]Findings without a specific fix recipe[/dim]", style="dim"))
        for f in no_fix:
            tid  = f.get("id", "?")
            desc = f.get("description", "")
            detail = f.get("detail", "")
            solution = f.get("solution", "")
            console.print(f"  [dim]• [{tid}][/dim]  {desc}")
            if solution:
                console.print(f"    [italic dim]Hint: {solution}[/italic dim]")
            elif detail:
                console.print(f"    [italic dim]{detail}[/italic dim]")
        console.print()


# ──────────────────────────────────────────────────────────────────────────────
# History view
# ──────────────────────────────────────────────────────────────────────────────

def print_history(scans: List[Dict]):
    console.print(Rule("[bold]Scan History[/bold]"))
    console.print()

    if not scans:
        console.print("[dim]No previous scans found.[/dim]")
        return

    t = Table(box=box.SIMPLE_HEAD)
    t.add_column("#",         justify="right", style="dim")
    t.add_column("Date",      style="cyan")
    t.add_column("Host",      style="white")
    t.add_column("Score",     justify="right")
    t.add_column("Risk",      justify="center")
    t.add_column("Warnings",  justify="right")
    t.add_column("Sugg.",     justify="right")

    for i, s in enumerate(reversed(scans), start=1):
        meta = s.get("meta", {})
        risk = s.get("risk", "?")
        score = str(s.get("score", "?"))
        t.add_row(
            str(i),
            meta.get("scan_date", "unknown")[:16],
            meta.get("hostname", "?"),
            score,
            Text(risk, style=RISK_COLOR.get(risk, "white")),
            str(s.get("warnings_count", "?")),
            str(s.get("suggestions_count", "?")),
        )

    console.print(t)
    console.print()


# ──────────────────────────────────────────────────────────────────────────────
# Error / info helpers
# ──────────────────────────────────────────────────────────────────────────────

def print_error(msg: str):
    console.print(f"\n[bold red]ERROR:[/bold red] {msg}\n")


def print_warning(msg: str):
    console.print(f"[bold yellow]WARNING:[/bold yellow] {msg}")


def print_info(msg: str):
    console.print(f"[dim]{msg}[/dim]")


def print_success(msg: str):
    console.print(f"[bold green]✓[/bold green] {msg}")


def prompt_mode() -> str:
    """Ask user which mode to use if no flag was given."""
    console.print("[bold]What would you like to do?[/bold]")
    console.print("  [cyan]1[/cyan]  Review   — view all findings grouped by category")
    console.print("  [cyan]2[/cyan]  Fix      — show exact commands to fix each issue")
    console.print("  [cyan]3[/cyan]  Both     — review then fix commands")
    console.print("  [cyan]4[/cyan]  History  — show previous scan results")
    console.print()
    choice = input("  Enter choice [1/2/3/4]: ").strip()
    mapping = {"1": "review", "2": "fix", "3": "both", "4": "history"}
    return mapping.get(choice, "both")
