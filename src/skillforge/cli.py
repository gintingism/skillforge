"""Typer command-line interface for SkillForge."""

from __future__ import annotations

import json
import logging
import zipfile
from pathlib import Path
from typing import Any

import typer

from .adapters import detect_adapters
from .errors import SecurityAuditError, SkillForgeError
from .mcp_server import run_mcp_server
from .registry import BuiltinRegistry, CompositeRegistry, GitRemoteRegistry, LocalRegistry, Registry
from .security import SkillAuditor, audit_path
from .skill import Skill, SkillPackage

app = typer.Typer(help="Universal package manager, security auditor, and MCP server for portable agent skills.")
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def _registry(path: Path) -> Registry:
    """Use configured local skills first, then explicit packaged built-ins."""
    return CompositeRegistry((LocalRegistry(path), BuiltinRegistry()))


@app.command()
def validate(
    path: Path,
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    """Validate a SKILL.md file or skill directory against the portable specification."""
    try:
        skill = Skill.load(path)
    except SkillForgeError as exc:
        if json_output:
            typer.echo(json.dumps({"valid": False, "path": str(path), "error": str(exc)}))
        else:
            typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    if json_output:
        typer.echo(
            json.dumps(
                {
                    "valid": True,
                    "path": str(path),
                    "name": skill.name,
                    "description": skill.description,
                }
            )
        )
    else:
        typer.echo(f"Valid skill: {skill.name}")


@app.command()
def audit(
    path: Path,
    strict: bool = typer.Option(False, "--strict", help="Fail on any warning or low-severity finding."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    """Audit a skill for prompt injection, zero-width unicode, and security issues."""
    try:
        report = audit_path(path)
    except (SkillForgeError, OSError) as exc:
        if json_output:
            typer.echo(json.dumps({"passed": False, "error": str(exc)}))
        else:
            typer.echo(f"Audit error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if json_output:
        typer.echo(json.dumps(report.to_dict()))
    else:
        typer.echo(report.render_text())

    if not report.passed or (strict and report.findings):
        raise typer.Exit(code=1)


@app.command()
def create(
    name: str,
    description: str = typer.Option(..., "--description", "-d", help="What the skill does and when to use it."),
    directory: Path = typer.Option(Path("."), "--directory", "-o", help="Destination directory."),
    full: bool = typer.Option(False, "--full", help="Scaffold full scripts/ and references/ directories."),
) -> None:
    """Create a starter SKILL.md or full skill package structure."""
    try:
        Skill.validate_name(name)
        target_dir = directory / name if full else directory
        target_dir.mkdir(parents=True, exist_ok=True)
        target = target_dir / "SKILL.md"

        instructions = (
            f"# {name}\n\n"
            "## When to Use\n"
            f"Use this skill when tasked with {name.replace('-', ' ')}.\n\n"
            "## Workflow\n"
            "1. Step one instructions.\n"
            "2. Step two instructions.\n"
        )
        skill = Skill(name=name, description=description, body=instructions)
        target.write_text(skill.render(), encoding="utf-8")

        if full:
            scripts_dir = target_dir / "scripts"
            scripts_dir.mkdir(exist_ok=True)
            (scripts_dir / "run.py").write_text("#!/usr/bin/env python3\n# Helper execution script\n", encoding="utf-8")
            refs_dir = target_dir / "references"
            refs_dir.mkdir(exist_ok=True)
            (refs_dir / "guide.md").write_text("# Reference Documentation\n", encoding="utf-8")

    except (SkillForgeError, OSError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Created {target}")


@app.command()
def pack(path: Path, output: Path = typer.Option(..., "--output", "-o", help="Output zip archive path.")) -> None:
    """Pack a skill file or full skill directory package into a zip archive."""
    try:
        package = SkillPackage.load(path)
        package.pack_zip(output)
    except (SkillForgeError, OSError, zipfile.BadZipFile) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Packed {output}")


@app.command()
def unpack(archive: Path, output: Path = typer.Option(Path("."), "--output", "-o", help="Destination folder.")) -> None:
    """Unpack a portable skill zip archive safely."""
    try:
        package = SkillPackage.unpack_zip(archive, output)
    except (SkillForgeError, OSError, zipfile.BadZipFile) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Unpacked skill '{package.skill.name}' into {output}")


@app.command()
def search(query: str, registry: Path = typer.Option(Path(".skillforge"), "--registry")) -> None:
    """Search available skills across local and built-in registries."""
    try:
        skills = _registry(registry).search(query)
    except SkillForgeError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    for skill in skills:
        typer.echo(f"{skill.name}\t{skill.description}")


@app.command("list")
def list_installed_skills(
    project: Path = typer.Option(Path("."), "--project", "-p", help="Target project root."),
    global_scope: bool = typer.Option(False, "--global", "-g", help="Inspect global user assistant configs."),
) -> None:
    """List all skills installed across detected assistants."""
    adapters = detect_adapters(project, global_scope=global_scope)
    if not adapters:
        typer.echo("No supported assistant configurations detected.")
        return

    found: dict[str, list[str]] = {}
    for adapter in adapters:
        adapter_name = type(adapter).__name__.replace("Adapter", "")
        skills = adapter.list_skills(project)
        if skills:
            found[adapter_name] = skills

    if not found:
        typer.echo("No installed skills found in detected assistants.")
        return

    typer.echo("Installed Skills:")
    for assistant, skills in sorted(found.items()):
        typer.echo(f"  [{assistant}]:")
        for s in skills:
            typer.echo(f"    - {s}")


@app.command()
def install(
    name: str,
    registry: Path = typer.Option(Path(".skillforge"), "--registry"),
    project: Path = typer.Option(Path("."), "--project"),
    global_install: bool = typer.Option(False, "--global", "-g", help="Install into global assistant configs."),
) -> None:
    """Install a skill from a registry into detected assistant targets."""
    try:
        staging_dir = project / ".skillforge-staging"
        skill_path = _registry(registry).install(name, staging_dir)
        package = SkillPackage.load(skill_path.parent if skill_path.name == "SKILL.md" else skill_path)

        adapters = detect_adapters(project, global_scope=global_install)
        if not adapters:
            typer.echo("No supported assistant target detected.", err=True)
            raise typer.Exit(code=1)

        for adapter in adapters:
            installed_dest = adapter.install(package, project)
            typer.echo(f"Installed {installed_dest}")

        # Clean up staging
        if staging_dir.exists():
            for child in staging_dir.rglob("*"):
                if child.is_file():
                    child.unlink()
            for child in sorted(staging_dir.rglob("*"), reverse=True):
                if child.is_dir():
                    child.rmdir()
            staging_dir.rmdir()

    except (SkillForgeError, OSError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc


@app.command()
def add(
    spec: str = typer.Argument(..., help="Remote spec, e.g. 'owner/repo:skill' or Git URL."),
    project: Path = typer.Option(Path("."), "--project", "-p", help="Target project root."),
    global_install: bool = typer.Option(False, "--global", "-g", help="Install into global assistant configuration."),
    skip_audit: bool = typer.Option(False, "--skip-audit", help="Skip security auditing before install."),
) -> None:
    """Fetch, security-audit, and install a skill directly from a remote GitHub or Git repository."""
    try:
        typer.echo(f"Fetching '{spec}'...")
        remote_reg = GitRemoteRegistry()
        package = remote_reg.fetch_skill(spec)

        if not skip_audit:
            typer.echo(f"Auditing security of '{package.skill.name}'...")
            report = SkillAuditor().audit_package(package)
            if not report.passed:
                typer.echo("Security audit FAILED:", err=True)
                typer.echo(report.render_text(), err=True)
                raise typer.Exit(code=1)
            typer.echo(f"Security audit passed (Score: {report.score}/100)")

        adapters = detect_adapters(project, global_scope=global_install)
        if not adapters:
            typer.echo("No supported assistant target detected.", err=True)
            raise typer.Exit(code=1)

        for adapter in adapters:
            installed = adapter.install(package, project)
            typer.echo(f"Installed {installed}")

        # Record in skillforge.lock
        lock_file = project / "skillforge.lock"
        lock_data: dict[str, Any] = {}
        if lock_file.is_file():
            try:
                lock_data = json.loads(lock_file.read_text(encoding="utf-8"))
            except Exception:
                pass
        lock_data[package.skill.name] = {
            "spec": spec,
            "version": package.skill.metadata.get("version", "unknown"),
        }
        lock_file.write_text(json.dumps(lock_data, indent=2), encoding="utf-8")
        typer.echo(f"Updated lockfile {lock_file}")

    except (SkillForgeError, OSError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc


@app.command()
def remove(
    name: str = typer.Argument(..., help="Name of the skill to remove."),
    project: Path = typer.Option(Path("."), "--project", "-p", help="Target project root."),
    global_install: bool = typer.Option(False, "--global", "-g", help="Remove from global configuration."),
) -> None:
    """Remove an installed skill from detected assistants and skillforge.lock."""
    adapters = detect_adapters(project, global_scope=global_install)
    if not adapters:
        typer.echo("No supported assistant targets detected.", err=True)
        raise typer.Exit(code=1)

    removed_any = False
    for adapter in adapters:
        if adapter.remove(name, project):
            typer.echo(f"Removed from {type(adapter).__name__.replace('Adapter', '')}")
            removed_any = True

    # Remove from skillforge.lock
    lock_file = project / "skillforge.lock"
    if lock_file.is_file():
        try:
            lock_data = json.loads(lock_file.read_text(encoding="utf-8"))
            if name in lock_data:
                del lock_data[name]
                lock_file.write_text(json.dumps(lock_data, indent=2), encoding="utf-8")
                typer.echo(f"Removed '{name}' from skillforge.lock")
        except Exception:
            pass

    if not removed_any:
        typer.echo(f"Skill '{name}' was not found in any detected assistants.")


@app.command("serve-mcp")
def serve_mcp() -> None:
    """Serve SkillForge over MCP stdio."""
    run_mcp_server()
