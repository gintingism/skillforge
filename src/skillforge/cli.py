"""Typer command-line interface for SkillForge."""

from __future__ import annotations

import logging
import zipfile
from pathlib import Path

import typer

from .adapters import detect_adapters
from .errors import SkillForgeError
from .mcp_server import run_mcp_server
from .registry import BuiltinRegistry, CompositeRegistry, LocalRegistry, Registry
from .skill import Skill

app = typer.Typer(help="Create, validate, discover, install, and package portable skills.")
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def _registry(path: Path) -> Registry:
    """Use configured local skills first, then explicit packaged built-ins."""
    return CompositeRegistry((LocalRegistry(path), BuiltinRegistry()))


@app.command()
def validate(path: Path) -> None:
    """Validate a SKILL.md file."""
    try:
        skill = Skill.load(path)
    except SkillForgeError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Valid skill: {skill.name}")


@app.command()
def create(
    name: str,
    description: str = typer.Option(..., "--description", "-d"),
    directory: Path = typer.Option(Path("."), "--directory", "-o"),
) -> None:
    """Create a starter SKILL.md."""
    try:
        skill = Skill(name, description, f"# {name}\n\nAdd instructions here.\n")
        directory.mkdir(parents=True, exist_ok=True)
        target = directory / "SKILL.md"
        target.write_text(skill.render(), encoding="utf-8")
    except (SkillForgeError, OSError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Created {target}")


@app.command()
def pack(path: Path, output: Path = typer.Option(..., "--output", "-o")) -> None:
    """Pack a skill file or skill directory into a zip archive."""
    try:
        skill_path = path / "SKILL.md" if path.is_dir() else path
        skill = Skill.load(skill_path)
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(f"{skill.name}/SKILL.md", skill.render())
    except (SkillForgeError, OSError, zipfile.BadZipFile) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Packed {output}")


@app.command()
def search(query: str, registry: Path = typer.Option(Path(".skillforge"), "--registry")) -> None:
    """Search a local registry."""
    try:
        skills = _registry(registry).search(query)
    except SkillForgeError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    for skill in skills:
        typer.echo(f"{skill.name}\t{skill.description}")


@app.command()
def install(
    name: str,
    registry: Path = typer.Option(Path(".skillforge"), "--registry"),
    project: Path = typer.Option(Path("."), "--project"),
) -> None:
    """Install a skill from a local registry into detected assistant targets."""
    try:
        skill_path = _registry(registry).install(name, project / ".skillforge-staging")
        skill = Skill.load(skill_path)
        adapters = detect_adapters(project)
        if not adapters:
            typer.echo("No supported assistant target detected.", err=True)
            raise typer.Exit(code=1)
        for adapter in adapters:
            typer.echo(f"Installed {adapter.install(skill, project)}")
        skill_path.unlink()
        skill_path.parent.rmdir()
    except (SkillForgeError, OSError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc


@app.command("serve-mcp")
def serve_mcp() -> None:
    """Serve SkillForge over MCP stdio."""
    run_mcp_server()
