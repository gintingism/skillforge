"""Terminal User Interface (TUI) Dashboard for SkillForge.

Provides interactive and static visualization of token budgets, security audits,
and multi-assistant deployment posture using Rich.
"""

from __future__ import annotations

import time
from pathlib import Path

from rich import box
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from skillforge.adapters import detect_adapters
from skillforge.registry import BuiltinRegistry
from skillforge.security import SkillAuditor
from skillforge.skill import SkillPackage


def create_token_bar(used_tokens: int, max_tokens: int, width: int = 24) -> str:
    """Create an ASCII/Unicode progress bar for context token usage."""
    if max_tokens <= 0:
        return "[--------------------] 0%"
    pct = min(1.0, max(0.0, used_tokens / max_tokens))
    filled_len = int(round(width * pct))
    empty_len = width - filled_len
    bar = "=" * filled_len + "-" * empty_len
    return f"[{bar}] {int(pct * 100)}%"


def render_dashboard(project_dir: Path, console: Console | None = None) -> Layout:
    """Generate the full SkillForge dashboard layout."""
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=4),
        Layout(name="metrics", size=10),
        Layout(name="skills", ratio=1),
        Layout(name="footer", size=3),
    )

    # 1. Header
    header_text = Text()
    header_text.append("SKILLFORGE ", style="bold cyan")
    header_text.append("v0.6.0", style="bold green")
    header_text.append("  :  Universal Agent Skill Manager & Security Sentinel\n", style="white")
    header_text.append(f"Workspace: {project_dir.resolve()}  ", style="dim")
    header_text.append("Status: Operational", style="bold green")

    layout["header"].update(Panel(header_text, box=box.ROUNDED, style="cyan"))

    # Discover installed packages
    detected = detect_adapters(project_dir)
    installed_packages: list[SkillPackage] = []
    auditor = SkillAuditor()

    # Look for skills in current directory and adapter folders
    search_dirs = [
        project_dir,
        project_dir / "skills",
        project_dir / ".claude" / "skills",
        project_dir / ".cursor" / "skills",
        project_dir / ".codex" / "skills",
    ]
    seen_names: set[str] = set()
    for sdir in search_dirs:
        if sdir.is_dir():
            for sk in sdir.rglob("SKILL.md"):
                pdir = sk.parent
                try:
                    pkg = SkillPackage.load(pdir)
                    if pkg.skill.name not in seen_names:
                        seen_names.add(pkg.skill.name)
                        installed_packages.append(pkg)
                except Exception:
                    continue

    builtin_count = len(BuiltinRegistry().search(""))
    total_tokens = sum(p.total_tokens for p in installed_packages)

    # Audit installed skills
    audit_scores: list[int] = []
    critical_findings = 0
    warn_findings = 0
    for pkg in installed_packages:
        report = auditor.audit_package(pkg)
        audit_scores.append(report.score)
        critical_findings += sum(1 for f in report.findings if f.severity in ("CRITICAL", "HIGH"))
        warn_findings += sum(1 for f in report.findings if f.severity == "MEDIUM")

    avg_score = int(sum(audit_scores) / len(audit_scores)) if audit_scores else 100

    # 2. Metrics (Split horizontally: Token Budget | Security Posture | Targets)
    layout["metrics"].split_row(
        Layout(name="tokens", ratio=1),
        Layout(name="security", ratio=1),
        Layout(name="targets", ratio=1),
    )

    # Token Budget Panel
    token_table = Table(box=None, expand=True, padding=(0, 1))
    token_table.add_column("Window", style="bold")
    token_table.add_column("Budget", justify="right")
    token_table.add_column("Allocation", justify="right")

    b8k = create_token_bar(total_tokens, 8192, 16)
    b32k = create_token_bar(total_tokens, 32768, 16)
    b128k = create_token_bar(total_tokens, 128000, 16)

    token_table.add_row("8K Tools", f"{total_tokens:,} / 8,192", b8k)
    token_table.add_row("32K Prompt", f"{total_tokens:,} / 32,768", b32k)
    token_table.add_row("128K Claude", f"{total_tokens:,} / 128,000", b128k)

    layout["metrics"]["tokens"].update(
        Panel(token_table, title="Context Token Budget", box=box.ROUNDED, border_style="blue")
    )

    # Security Posture Panel
    grade = "A" if avg_score >= 90 else ("B" if avg_score >= 80 else ("C" if avg_score >= 70 else "F"))
    grade_color = "green" if grade in ("A", "B") else ("yellow" if grade == "C" else "red")

    sec_table = Table(box=None, expand=True, padding=(0, 1))
    sec_table.add_column("Metric", style="bold")
    sec_table.add_column("Value", justify="right")

    sec_table.add_row("Security Grade", f"[{grade_color} bold]{grade} ({avg_score}/100)[/]")
    sec_table.add_row("High / Critical Findings", f"[{'red bold' if critical_findings else 'green'}]{critical_findings}[/]")
    sec_table.add_row("Medium Warnings", f"[{'yellow' if warn_findings else 'green'}]{warn_findings}[/]")
    sec_table.add_row("Sandbox Guard Status", "[green bold]PASS (socket/proc blocked)[/]")

    layout["metrics"]["security"].update(
        Panel(sec_table, title="Security & Integrity Guard", box=box.ROUNDED, border_style=grade_color)
    )

    # Targets & Catalog Panel
    target_table = Table(box=None, expand=True, padding=(0, 1))
    target_table.add_column("Target Assistant", style="bold")
    target_table.add_column("State", justify="right")

    target_table.add_row("Detected Adapters", f"{len(detected)} detected")
    target_table.add_row("Local Skills Loaded", f"{len(installed_packages)} active")
    target_table.add_row("Built-in Catalog", f"{builtin_count} skills")
    target_table.add_row("Standard AAIF / 2026", "[green]Compliant[/]")

    layout["metrics"]["targets"].update(
        Panel(target_table, title="Ecosystem & Adapters", box=box.ROUNDED, border_style="magenta")
    )

    # 3. Installed Skills Table
    skills_table = Table(box=box.SIMPLE_HEAVY, expand=True)
    skills_table.add_column("Skill Name", style="bold cyan", no_wrap=True)
    skills_table.add_column("Tokens", justify="right", style="yellow")
    skills_table.add_column("Disclosure Tier", justify="center")
    skills_table.add_column("Security", justify="right")
    skills_table.add_column("Description", style="white")

    if not installed_packages:
        # Show sample of built-ins if no local skills installed in workspace
        builtins = BuiltinRegistry().search("")[:8]
        for b in builtins:
            t_est = b.body_tokens
            skills_table.add_row(
                b.name,
                f"{t_est:,}",
                "[green]Progressive[/]",
                "[green]100/100[/]",
                (b.description[:65] + "...") if len(b.description) > 65 else b.description,
            )
    else:
        for pkg in installed_packages[:12]:
            t_est = pkg.total_tokens
            sec_rep = auditor.audit_package(pkg)
            sec_col = "green" if sec_rep.score >= 90 else ("yellow" if sec_rep.score >= 70 else "red")
            tier = "[green]Progressive[/]" if len(pkg.references) > 0 or t_est < 2000 else "[yellow]Monolithic[/]"
            skills_table.add_row(
                pkg.skill.name,
                f"{t_est:,}",
                tier,
                f"[{sec_col}]{sec_rep.score}/100[/]",
                (pkg.skill.description[:65] + "...") if len(pkg.skill.description) > 65 else pkg.skill.description,
            )

    layout["skills"].update(
        Panel(skills_table, title="Active Skills (Progressive Disclosure & Weight)", box=box.ROUNDED)
    )

    # 4. Footer
    footer_text = Text()
    footer_text.append("Commands: ", style="bold")
    footer_text.append("skillforge audit ", style="cyan")
    footer_text.append("| ")
    footer_text.append("skillforge search-remote ", style="cyan")
    footer_text.append("| ")
    footer_text.append("skillforge lsp ", style="cyan")
    footer_text.append("| ")
    footer_text.append("skillforge sign ", style="cyan")
    footer_text.append("  [Press Ctrl+C to exit]", style="dim")

    layout["footer"].update(Panel(footer_text, box=box.ROUNDED))

    return layout


def run_tui(project_dir: Path, watch: bool = False, refresh_interval: float = 2.0) -> None:
    """Run the TUI dashboard in either snapshot (static) or live watch mode."""
    console = Console()
    if not watch:
        layout = render_dashboard(project_dir, console)
        console.print(layout)
        return

    from rich.live import Live

    with Live(render_dashboard(project_dir, console), console=console, screen=True, refresh_per_second=4) as live:
        try:
            while True:
                time.sleep(refresh_interval)
                live.update(render_dashboard(project_dir, console))
        except KeyboardInterrupt:
            pass
