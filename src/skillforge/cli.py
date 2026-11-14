"""Typer command-line interface for SkillForge."""

from __future__ import annotations

import difflib
import json
import logging
import zipfile
from pathlib import Path
from typing import Any

import typer

from .adapters import detect_adapters
from .context_linter import lint_project_context
from .errors import SecurityAuditError, SkillForgeError
from .evals import detect_trigger_collisions, init_evals, run_evals
from .mcp_server import run_mcp_server
from .openapi import import_openapi
from .optimizer import optimize_skill
from .registry import BuiltinRegistry, CompositeRegistry, GitRemoteRegistry, LocalRegistry, Registry
from .security import Severity, SkillAuditor, audit_mcp_config, audit_path
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
    sandbox: bool = typer.Option(False, "--sandbox", help="Execute bundled Python scripts inside an isolated offline sandbox harness."),
    policy_file: Path | None = typer.Option(None, "--policy", help="Path to .skillforge-policy.yaml rule suppression and threshold file."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
    sarif_output: Path | None = typer.Option(None, "--sarif", help="Emit OASIS SARIF v2.1.0 report for GitHub Code Scanning."),
) -> None:
    """Audit a skill for prompt injection, zero-width unicode, and security issues."""
    from .policy import SecurityPolicy, apply_policy

    try:
        report = audit_path(path, sandbox=sandbox)
        if policy_file is not None:
            loaded_policy = SecurityPolicy.load(policy_file)
            eval_res = apply_policy(report, loaded_policy)
            active_report = eval_res.report
            if sarif_output:
                sarif_output.parent.mkdir(parents=True, exist_ok=True)
                sarif_output.write_text(json.dumps(active_report.to_sarif(), indent=2), encoding="utf-8")
                if not json_output:
                    typer.echo(f"Wrote SARIF report to {sarif_output}")
            if json_output:
                typer.echo(json.dumps(eval_res.to_dict()))
            else:
                typer.echo(eval_res.render_text())
            if not eval_res.passed or (strict and active_report.findings):
                raise typer.Exit(code=1)
            return
    except (SkillForgeError, OSError) as exc:
        if json_output:
            typer.echo(json.dumps({"passed": False, "error": str(exc)}))
        else:
            typer.echo(f"Audit error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if sarif_output:
        sarif_output.parent.mkdir(parents=True, exist_ok=True)
        sarif_output.write_text(json.dumps(report.to_sarif(), indent=2), encoding="utf-8")
        if not json_output:
            typer.echo(f"Wrote SARIF report to {sarif_output}")

    if json_output:
        typer.echo(json.dumps(report.to_dict()))
    else:
        typer.echo(report.render_text())

    if not report.passed or (strict and report.findings):
        raise typer.Exit(code=1)


@app.command("audit-mcp")
def audit_mcp(
    path: Path = typer.Argument(Path("mcp.json"), help="Path to mcp.json or claude_desktop_config.json file."),
    strict: bool = typer.Option(False, "--strict", help="Fail on any warning or low-severity finding."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
    sarif_output: Path | None = typer.Option(None, "--sarif", help="Emit OASIS SARIF v2.1.0 report for GitHub Code Scanning."),
) -> None:
    """Audit an MCP configuration file for plaintext secrets, shell command wrappers, and unpinned packages."""
    try:
        report = audit_mcp_config(path)
    except (SkillForgeError, OSError) as exc:
        if json_output:
            typer.echo(json.dumps({"passed": False, "error": str(exc)}))
        else:
            typer.echo(f"MCP audit error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if sarif_output:
        sarif_output.parent.mkdir(parents=True, exist_ok=True)
        sarif_output.write_text(json.dumps(report.to_sarif(), indent=2), encoding="utf-8")
        if not json_output:
            typer.echo(f"Wrote SARIF report to {sarif_output}")

    if json_output:
        typer.echo(json.dumps(report.to_dict()))
    else:
        typer.echo(report.render_text())

    if not report.passed or (strict and report.findings):
        raise typer.Exit(code=1)


@app.command()
def badge(
    path: Path = typer.Argument(Path("."), help="Path to skill directory or SKILL.md file."),
    markdown_only: bool = typer.Option(False, "--markdown", "-m", help="Print only the markdown badge string."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    """Generate an official 'Audited by SkillForge' shield badge for your skill repository."""
    try:
        report = audit_path(path)
    except (SkillForgeError, OSError) as exc:
        if json_output:
            typer.echo(json.dumps({"passed": False, "error": str(exc)}))
        else:
            typer.echo(f"Audit error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if report.passed:
        label = "SkillForge"
        message = f"Security%20Passed%20{report.score}%2F100"
        color = "2ea44f"
    else:
        label = "SkillForge"
        message = "Audit%20Failed"
        color = "cb2431"

    badge_url = f"https://img.shields.io/badge/{label}-{message}-{color}?logo=shield&style=flat-square"
    repo_url = "https://github.com/gintingism/skillforge"
    md_badge = f"[![Audited by SkillForge]({badge_url})]({repo_url})"
    html_badge = f'<a href="{repo_url}"><img src="{badge_url}" alt="Audited by SkillForge" /></a>'

    if json_output:
        typer.echo(
            json.dumps(
                {
                    "passed": report.passed,
                    "score": report.score,
                    "badge_url": badge_url,
                    "markdown": md_badge,
                    "html": html_badge,
                },
                indent=2,
            )
        )
        return

    if markdown_only:
        typer.echo(md_badge)
        return

    status_str = "PASSED" if report.passed else "FAILED"
    typer.echo(f"Audit Status: {status_str} (Score: {report.score}/100)")
    typer.echo("\nMarkdown Badge (copy-paste into your SKILL.md or README.md):")
    typer.echo(f"  {md_badge}\n")
    typer.echo("HTML Badge:")
    typer.echo(f"  {html_badge}\n")
    typer.echo(f"Shield URL: {badge_url}")


@app.command("lint-context")
def lint_context(
    project: Path = typer.Option(Path("."), "--project", "-p", help="Target project root."),
    strict: bool = typer.Option(False, "--strict", help="Fail if any warning or finding is detected."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    """Lint project instruction files (AGENTS.md, CLAUDE.md, etc.) for token bloat, buzzwords, and missing guardrails."""
    try:
        report = lint_project_context(project)
    except (SkillForgeError, OSError) as exc:
        if json_output:
            typer.echo(json.dumps({"passed": False, "error": str(exc)}))
        else:
            typer.echo(f"Context lint error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if json_output:
        typer.echo(json.dumps(report.to_dict(), indent=2))
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
        if full:
            instructions += (
                "\n## Progressive Disclosure\n"
                "- Deep reference: see `references/guide.md`\n"
                "- Helper script: run `scripts/run.py`\n"
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


@app.command("import-openapi")
def import_openapi_cmd(
    spec_path: Path = typer.Argument(..., help="Path to OpenAPI/Swagger JSON or YAML specification file."),
    output_dir: Path = typer.Option(Path("./skills"), "--output", "-o", help="Destination skills directory."),
    name: str | None = typer.Option(None, "--name", "-n", help="Optional override for skill name."),
) -> None:
    """Convert an OpenAPI / Swagger specification into a progressive disclosure skill package."""
    try:
        pkg = import_openapi(spec_path, output_dir, skill_name=name)
        dest = output_dir / pkg.skill.name
        typer.echo(f"Successfully imported '{pkg.skill.name}' into {dest}")
        typer.echo(f"  SKILL.md:               {pkg.skill.body_lines} lines (~{pkg.skill.body_tokens} body tokens)")
        typer.echo(f"  endpoints.md reference: ~{pkg.resource_tokens} tokens")
    except (SkillForgeError, OSError) as exc:
        typer.echo(f"Import error: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@app.command("test")
def test_skill(
    path: Path = typer.Argument(Path("."), help="Path to skill directory or SKILL.md file."),
    init: bool = typer.Option(False, "--init", help="Generate starter evals/evals.json test suite."),
    evals_path: Path | None = typer.Option(None, "--evals", help="Path to custom evals.json test suite file."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    """Run trigger accuracy and output assertions against an evals.json test suite."""
    try:
        if init:
            target_file = init_evals(path)
            typer.echo(f"Initialized eval suite in {target_file}")
            return

        report = run_evals(path, evals_path=evals_path)
    except (SkillForgeError, OSError) as exc:
        if json_output:
            typer.echo(json.dumps({"passed": False, "error": str(exc)}))
        else:
            typer.echo(f"Eval error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if json_output:
        typer.echo(json.dumps(report.to_dict(), indent=2))
    else:
        typer.echo(f"Running evals for '{report.skill_name}' ({report.total_cases} test cases)...")
        for r in report.results:
            status = "PASS" if r.passed else "FAIL"
            typer.echo(f"  [{status}] {r.case_id}: \"{r.prompt[:50]}\"")
            if not r.passed:
                typer.echo(f"         Reason: {r.reason}", err=True)

        status_str = "PASSED" if report.passed else "FAILED"
        typer.echo(f"\nResult: {status_str} ({report.passed_cases}/{report.total_cases} passed)")

    if not report.passed:
        raise typer.Exit(code=1)


@app.command("optimize")
def optimize_skill_cmd(
    path: Path = typer.Argument(Path("."), help="Path to skill directory or SKILL.md file."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Optional output destination directory."),
    max_lines: int = typer.Option(400, "--max-lines", help="Maximum lines for SKILL.md body."),
    max_tokens: int = typer.Option(4000, "--max-tokens", help="Maximum token count for SKILL.md body."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    """Refactor a bloated SKILL.md into progressive disclosure references."""
    try:
        result = optimize_skill(
            package_dir=path,
            output_dir=output,
            max_lines=max_lines,
            max_tokens=max_tokens,
        )
    except (SkillForgeError, OSError) as exc:
        if json_output:
            typer.echo(json.dumps({"success": False, "error": str(exc)}))
        else:
            typer.echo(f"Optimization error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if json_output:
        typer.echo(json.dumps(result.to_dict(), indent=2))
        return

    typer.echo(f"Optimized '{result.skill_name}':")
    typer.echo(f"  Lines:  {result.original_lines} -> {result.optimized_lines} ({result.lines_saved} lines saved)")
    typer.echo(f"  Tokens: ~{result.original_tokens} -> ~{result.optimized_tokens} ({result.tokens_saved} tokens saved)")

    if result.extracted_references:
        typer.echo("  Extracted References:")
        for ref in result.extracted_references:
            typer.echo(f"    - {ref}")
    else:
        typer.echo("  No sections required extraction (already within budget).")

    if result.saved_path:
        typer.echo(f"  Destination: {result.saved_path}")

    status_str = "PASSED" if result.passed_audit else "FAILED"
    typer.echo(f"  Audit Verification: {status_str}")
    if result.audit_findings:
        for finding in result.audit_findings:
            typer.echo(f"    [Finding] {finding}")


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
    audit_gate: bool = typer.Option(True, "--audit-gate/--no-audit-gate", help="Enforce security audit before installation."),
    min_score: int = typer.Option(80, "--min-score", help="Minimum required security score to allow installation."),
    insecure: bool = typer.Option(False, "--insecure", help="Bypass security audit gate."),
) -> None:
    """Install a skill from a registry into detected assistant targets."""
    try:
        staging_dir = project / ".skillforge-staging"
        skill_path = _registry(registry).install(name, staging_dir)
        package = SkillPackage.load(skill_path.parent if skill_path.name == "SKILL.md" else skill_path)

        if not insecure and audit_gate:
            report = SkillAuditor().audit_package(package)
            if report.score < min_score or any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in report.findings):
                typer.echo(
                    f"Security audit gate rejected installation for '{package.skill.name}' (Score: {report.score}/{min_score})",
                    err=True,
                )
                for f in report.findings:
                    if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
                        typer.echo(f"  [{f.severity.value}] {f.rule_id}: {f.message}", err=True)
                typer.echo("Use --insecure to bypass this security gate if you trust the source.", err=True)
                raise typer.Exit(code=2)

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
            "sha256": package.compute_sha256(),
            "commit": package.commit_sha,
        }
        lock_file.write_text(json.dumps(lock_data, indent=2), encoding="utf-8")
        typer.echo(f"Updated lockfile {lock_file}")

    except (SkillForgeError, OSError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc


@app.command()
def sync(
    project: Path = typer.Option(Path("."), "--project", "-p", help="Target project root containing skillforge.lock."),
    registry: Path = typer.Option(Path(".skillforge"), "--registry", help="Local registry fallback path."),
    global_install: bool = typer.Option(False, "--global", "-g", help="Install into global assistant configuration."),
    skip_audit: bool = typer.Option(False, "--skip-audit", help="Skip security auditing before install."),
) -> None:
    """Install and verify all skills recorded in skillforge.lock."""
    lock_file = project / "skillforge.lock"
    if not lock_file.is_file():
        typer.echo(f"Lockfile not found: {lock_file}", err=True)
        raise typer.Exit(code=1)

    try:
        lock_data = json.loads(lock_file.read_text(encoding="utf-8"))
    except Exception as exc:
        typer.echo(f"Invalid skillforge.lock JSON: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if not isinstance(lock_data, dict) or not lock_data:
        typer.echo("No skills listed in skillforge.lock.")
        return

    adapters = detect_adapters(project, global_scope=global_install)
    if not adapters:
        typer.echo("No supported assistant target detected.", err=True)
        raise typer.Exit(code=1)

    composite_reg = _registry(registry)
    auditor = SkillAuditor()

    try:
        for skill_name, entry in sorted(lock_data.items()):
            spec = str(entry.get("spec", skill_name)) if isinstance(entry, dict) else str(entry)
            expected_sha = entry.get("sha256") if isinstance(entry, dict) else None
            pinned_commit = entry.get("commit") if isinstance(entry, dict) else None

            if spec.startswith("builtin:"):
                package = BuiltinRegistry().get_package(spec.split(":", 1)[1])
            elif "/" not in spec and ":" not in spec:
                package = composite_reg.get_package(spec)
            else:
                package = GitRemoteRegistry().fetch_skill(spec, commit=pinned_commit)

            actual_sha = package.compute_sha256()
            if expected_sha and actual_sha != expected_sha:
                typer.echo(
                    f"Integrity verification FAILED for '{skill_name}': "
                    f"expected sha256 {expected_sha}, got {actual_sha}",
                    err=True,
                )
                raise typer.Exit(code=1)

            if not skip_audit:
                report = auditor.audit_package(package)
                if not report.passed:
                    typer.echo(f"Security audit FAILED for '{skill_name}':", err=True)
                    typer.echo(report.render_text(), err=True)
                    raise typer.Exit(code=1)

            for adapter in adapters:
                installed = adapter.install(package, project)
                typer.echo(f"Synced {skill_name} -> {installed}")

    except (SkillForgeError, OSError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc


@app.command()
def verify(
    project: Path = typer.Option(Path("."), "--project", "-p", help="Target project root containing skillforge.lock."),
    global_scope: bool = typer.Option(False, "--global", "-g", help="Verify global assistant configuration."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    """Verify integrity of installed skills against skillforge.lock without modifying files."""
    lock_file = project / "skillforge.lock"
    if not lock_file.is_file():
        typer.echo(f"Lockfile not found: {lock_file}", err=True)
        raise typer.Exit(code=1)

    try:
        lock_data = json.loads(lock_file.read_text(encoding="utf-8"))
    except Exception as exc:
        typer.echo(f"Invalid skillforge.lock JSON: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if not isinstance(lock_data, dict) or not lock_data:
        typer.echo("Lockfile is empty.")
        return

    packages = _discover_packages(project, global_scope=global_scope)
    results: list[dict[str, Any]] = []
    has_error = False

    for skill_name, entry in sorted(lock_data.items()):
        expected_sha = entry.get("sha256") if isinstance(entry, dict) else None
        pkg = packages.get(skill_name)

        if pkg is None:
            has_error = True
            results.append({
                "skill": skill_name,
                "status": "MISSING",
                "message": "Skill recorded in lockfile is not installed in any detected environment.",
            })
            continue

        actual_sha = pkg.compute_sha256()
        if expected_sha and actual_sha != expected_sha:
            has_error = True
            results.append({
                "skill": skill_name,
                "status": "DRIFT",
                "message": f"Integrity drift: expected {expected_sha[:12]}..., found {actual_sha[:12]}...",
                "expected_sha256": expected_sha,
                "actual_sha256": actual_sha,
            })
        else:
            results.append({
                "skill": skill_name,
                "status": "VERIFIED",
                "sha256": actual_sha,
            })

    unmanaged = [name for name in sorted(packages) if name not in lock_data]

    if json_output:
        typer.echo(
            json.dumps(
                {
                    "status": "FAILED" if has_error else "PASSED",
                    "results": results,
                    "unmanaged_skills": unmanaged,
                },
                indent=2,
            )
        )
    else:
        for r in results:
            st = r["status"]
            if st == "VERIFIED":
                typer.echo(f"  OK       {r['skill']} (sha256: {r['sha256'][:16]}...)")
            elif st == "DRIFT":
                typer.echo(f"  DRIFT    {r['skill']} - {r['message']}", err=True)
            elif st == "MISSING":
                typer.echo(f"  MISSING  {r['skill']} - {r['message']}", err=True)
        if unmanaged:
            typer.echo(f"\nUnmanaged skills installed (not in lockfile): {', '.join(unmanaged)}")

        if has_error:
            typer.echo("\nVerification FAILED: integrity drift or missing skills detected.", err=True)
            raise typer.Exit(code=1)
        typer.echo(f"\nVerification PASSED: {len(results)} skill(s) match skillforge.lock.")


def _discover_packages(
    path: Path | None = None,
    global_scope: bool = False,
    builtin: bool = False,
) -> dict[str, SkillPackage]:
    """Discover installed or packaged skills across assistant layouts."""
    packages: dict[str, SkillPackage] = {}
    if builtin:
        reg = BuiltinRegistry()
        for skill in reg.search(""):
            packages[skill.name] = reg.get_package(skill.name)
        return packages

    if global_scope:
        global_roots = (
            Path.home() / ".gemini" / "config" / "skills",
            Path.home() / ".claude" / "skills",
            Path.home() / ".cursor" / "skills",
            Path.home() / ".agents" / "skills",
        )
        for root in global_roots:
            if root.is_dir():
                for skill_md in sorted(root.glob("*/SKILL.md")):
                    try:
                        pkg = SkillPackage.load(skill_md.parent)
                        packages.setdefault(pkg.skill.name, pkg)
                    except Exception:
                        pass
        return packages

    target = path or Path(".")
    if target.is_file() or (target / "SKILL.md").is_file():
        pkg = SkillPackage.load(target)
        packages[pkg.skill.name] = pkg
        return packages

    # Direct child folders with SKILL.md (e.g. if path is already a skills/ dir)
    if target.is_dir():
        for skill_md in sorted(target.glob("*/SKILL.md")):
            try:
                pkg = SkillPackage.load(skill_md.parent)
                packages.setdefault(pkg.skill.name, pkg)
            except Exception:
                pass

    search_roots = (
        target / ".claude" / "skills",
        target / ".cursor" / "skills",
        target / ".gemini" / "skills",
        target / ".gemini" / "config" / "skills",
        target / ".windsurf" / "skills",
        target / ".cline" / "skills",
        target / "skills",
        target / ".agents" / "skills",
        target / ".skillforge",
    )
    for root in search_roots:
        if root.is_dir():
            for skill_md in sorted(root.glob("*/SKILL.md")):
                try:
                    pkg = SkillPackage.load(skill_md.parent)
                    packages.setdefault(pkg.skill.name, pkg)
                except Exception:
                    pass

    return packages


@app.command()
def budget(
    path: Path = typer.Option(Path("."), "--path", "-p", help="Project root or skill directory to profile."),
    builtin: bool = typer.Option(False, "--builtin", help="Profile all built-in SkillForge skills."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    """Measure startup pointer token load vs on-demand body token load across skills."""
    try:
        packages = _discover_packages(path, builtin=builtin)
    except (SkillForgeError, OSError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    items: list[dict[str, Any]] = []
    total_pointer = 0
    total_body = 0
    total_resources = 0

    for name, pkg in sorted(packages.items()):
        p_tok = pkg.skill.pointer_tokens
        b_tok = pkg.skill.body_tokens
        r_tok = pkg.resource_tokens
        over = pkg.skill.body_lines > 500 or b_tok > 5000
        total_pointer += p_tok
        total_body += b_tok
        total_resources += r_tok
        items.append(
            {
                "name": name,
                "pointer_tokens": p_tok,
                "body_tokens": b_tok,
                "resource_tokens": r_tok,
                "body_lines": pkg.skill.body_lines,
                "disable_model_invocation": pkg.skill.disable_model_invocation,
                "over_budget": over,
            }
        )

    summary = {
        "skills_count": len(items),
        "startup_pointer_tokens": total_pointer,
        "on_demand_body_tokens": total_body,
        "disclosed_resource_tokens": total_resources,
        "skills": items,
    }

    if json_output:
        typer.echo(json.dumps(summary))
        return

    if not items:
        typer.echo("No skills found to profile.")
        return

    typer.echo(f"Context Budget Profile ({len(items)} skills)")
    typer.echo(f"  Always-Loaded Startup Pointer Cost: ~{total_pointer} tokens")
    typer.echo(f"  On-Demand SKILL.md Body Cost:       ~{total_body} tokens")
    typer.echo(f"  Disclosed Resources Cost:           ~{total_resources} tokens\n")
    for item in items:
        status = " [OVER BUDGET]" if item["over_budget"] else ""
        typer.echo(
            f"  - {item['name']:<28} pointer: {item['pointer_tokens']:>4} tok | "
            f"body: {item['body_tokens']:>5} tok ({item['body_lines']:>3} lines) | "
            f"resources: {item['resource_tokens']:>5} tok{status}"
        )


@app.command()
def doctor(
    project: Path = typer.Option(Path("."), "--project", "-p", help="Target project root to diagnose."),
    global_scope: bool = typer.Option(False, "--global", "-g", help="Diagnose global user assistant configurations."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    """Run a comprehensive health, security, and context budget diagnostic across installed skills."""
    packages = _discover_packages(project, global_scope=global_scope)
    if not packages:
        msg = "No installed skills found in detected assistant environments."
        if json_output:
            typer.echo(json.dumps({"status": "clean", "skills_count": 0, "message": msg}))
        else:
            typer.echo(msg)
        return

    auditor = SkillAuditor()
    total_pointer = 0
    total_body = 0
    passed_count = 0
    failed_count = 0
    critical_findings = 0
    high_findings = 0
    all_findings: list[dict[str, Any]] = []

    for name, pkg in sorted(packages.items()):
        report = auditor.audit_package(pkg)
        total_pointer += pkg.skill.pointer_tokens
        total_body += pkg.skill.body_tokens
        if report.passed:
            passed_count += 1
        else:
            failed_count += 1

        for f in report.findings:
            if f.severity == Severity.CRITICAL:
                critical_findings += 1
            elif f.severity == Severity.HIGH:
                high_findings += 1
            all_findings.append(
                {
                    "skill": name,
                    "rule_id": f.rule_id,
                    "severity": f.severity.value,
                    "message": f.message,
                    "file": f.file,
                }
            )

    collisions = detect_trigger_collisions(packages)

    result = {
        "status": "FAILED" if failed_count > 0 else "HEALTHY",
        "skills_scanned": len(packages),
        "passed_skills": passed_count,
        "failed_skills": failed_count,
        "total_pointer_tokens": total_pointer,
        "total_body_tokens": total_body,
        "critical_issues": critical_findings,
        "high_issues": high_findings,
        "findings": all_findings,
        "trigger_collisions": collisions,
    }

    if json_output:
        typer.echo(json.dumps(result))
        if failed_count > 0:
            raise typer.Exit(code=1)
        return

    scope_name = "Global" if global_scope else "Project"
    status_str = "PASSED (All Healthy)" if failed_count == 0 else f"WARNING ({failed_count} skills flagged)"
    typer.echo(f"SkillForge Doctor Diagnostic ({scope_name}: {len(packages)} skills)")
    typer.echo(f"  Health Status:        {status_str}")
    typer.echo(f"  Startup Context Load: ~{total_pointer} tokens (Every turn discovery cost)")
    typer.echo(f"  On-Demand Body Cost:  ~{total_body} tokens")
    typer.echo(f"  Security Findings:    {critical_findings} Critical, {high_findings} High, {len(all_findings)} Total\n")

    if all_findings:
        typer.echo("Findings:")
        for finding in all_findings:
            typer.echo(f"  [{finding['severity']}] {finding['skill']} -> {finding['rule_id']}: {finding['message']}")

    if collisions:
        typer.echo("\nTrigger Collisions (Confusability Warnings):")
        for col in collisions:
            shared_str = ", ".join(col["shared_triggers"])
            typer.echo(
                f"  [COLLISION] {col['skill_a']} <-> {col['skill_b']} "
                f"(overlap: {int(col['overlap_ratio'] * 100)}% on: {shared_str})"
            )

    if failed_count > 0:
        raise typer.Exit(code=1)


@app.command()
def diff(
    target_a: str = typer.Argument(..., help="Path to local skill folder, or skill name."),
    target_b: str | None = typer.Argument(None, help="Comparison target (remote spec 'owner/repo:skill' or second path)."),
    project: Path = typer.Option(Path("."), "--project", "-p", help="Target project root."),
) -> None:
    """Compare two skills or inspect local changes against an upstream spec."""
    try:
        path_a = Path(target_a)
        if path_a.exists():
            pkg_a = SkillPackage.load(path_a)
        else:
            pkg_a = _registry(project / ".skillforge").get_package(target_a)

        if target_b is None:
            lock_file = project / "skillforge.lock"
            remote_spec = None
            if lock_file.is_file():
                try:
                    data = json.loads(lock_file.read_text(encoding="utf-8"))
                    if pkg_a.skill.name in data:
                        entry = data[pkg_a.skill.name]
                        remote_spec = entry.get("spec") if isinstance(entry, dict) else str(entry)
                except Exception:
                    pass
            if not remote_spec:
                typer.echo(f"No second target provided and no lockfile spec found for '{pkg_a.skill.name}'.", err=True)
                raise typer.Exit(code=1)
            pkg_b = GitRemoteRegistry().fetch_skill(remote_spec)
        else:
            path_b = Path(target_b)
            if path_b.exists():
                pkg_b = SkillPackage.load(path_b)
            elif "/" in target_b or ":" in target_b:
                pkg_b = GitRemoteRegistry().fetch_skill(target_b)
            else:
                pkg_b = _registry(project / ".skillforge").get_package(target_b)

        sha_a = pkg_a.compute_sha256()
        sha_b = pkg_b.compute_sha256()
        typer.echo(f"Diff: {pkg_a.skill.name} ({sha_a[:8]}) <-> {pkg_b.skill.name} ({sha_b[:8]})")
        if sha_a == sha_b:
            typer.echo("Skills are identical (SHA-256 match).")
            return

        lines_a = pkg_a.skill.render().splitlines(keepends=True)
        lines_b = pkg_b.skill.render().splitlines(keepends=True)
        diff_lines = list(difflib.unified_diff(lines_a, lines_b, fromfile="target_a/SKILL.md", tofile="target_b/SKILL.md"))
        if diff_lines:
            typer.echo("".join(diff_lines))

        all_refs = sorted(set(pkg_a.references.keys()) | set(pkg_b.references.keys()))
        for ref in all_refs:
            in_a = ref in pkg_a.references
            in_b = ref in pkg_b.references
            if in_a and not in_b:
                typer.echo(f"- Deleted reference: references/{ref}")
            elif in_b and not in_a:
                typer.echo(f"+ Added reference: references/{ref}")
            elif pkg_a.references[ref] != pkg_b.references[ref]:
                typer.echo(f"~ Modified reference: references/{ref}")

        all_scripts = sorted(set(pkg_a.scripts.keys()) | set(pkg_b.scripts.keys()))
        for script in all_scripts:
            in_a = script in pkg_a.scripts
            in_b = script in pkg_b.scripts
            if in_a and not in_b:
                typer.echo(f"- Deleted script: scripts/{script}")
            elif in_b and not in_a:
                typer.echo(f"+ Added script: scripts/{script}")
            elif pkg_a.scripts[script] != pkg_b.scripts[script]:
                typer.echo(f"~ Modified script: scripts/{script}")

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
    try:
        Skill.validate_name(name)
    except SkillForgeError as exc:
        typer.echo(f"Refusing to remove {name!r}: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    adapters = detect_adapters(project, global_scope=global_install)
    if not adapters:
        typer.echo("No supported assistant targets detected.", err=True)
        raise typer.Exit(code=1)

    removed_any = False
    for adapter in adapters:
        try:
            removed = adapter.remove(name, project)
        except SkillForgeError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=1) from exc
        if removed:
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


@app.command("search-remote")
def search_remote(
    query: str = typer.Argument("", help="Search query (empty to list all remote skills)."),
    tag: str | None = typer.Option(None, "--tag", "-t", help="Filter by tag."),
) -> None:
    """Search the remote skills catalog (community and ecosystem repositories)."""
    from skillforge.remote_index import RemoteIndex

    idx = RemoteIndex()
    results = idx.search(query, tag=tag)
    if not results:
        typer.echo(f"No remote skills matched '{query}'.")
        return

    typer.echo(f"Found {len(results)} remote skill(s):")
    for r in results:
        vbadge = " [VERIFIED]" if r.verified else ""
        typer.echo(f"  {r.name:<32} {r.spec:<48}{vbadge}")
        typer.echo(f"    {r.description}")


@app.command("index")
def index_repo(
    repo_dir: Path = typer.Argument(Path("."), help="Path to local or cloned repository to index."),
    url: str = typer.Option("https://github.com/community/skills", "--url", help="Repository URL."),
) -> None:
    """Scan and index all SKILL.md packages in a repository into the local discovery catalog."""
    from skillforge.remote_index import RemoteIndex

    idx = RemoteIndex()
    found = idx.index_directory(repo_dir, url)
    typer.echo(f"Indexed {len(found)} skill(s) from {repo_dir} into {idx.cache_file}.")
    for s in found:
        typer.echo(f"  + {s.name} ({s.spec}) - Security Score: {s.security_score}/100")


@app.command("lsp")
def run_lsp() -> None:
    """Run SkillForge Language Server Protocol (LSP) daemon over stdio."""
    from skillforge.lsp import SkillLanguageServer

    server = SkillLanguageServer()
    server.run_stdio()


@app.command("keygen")
def keygen(
    out: Path | None = typer.Option(None, "--out", "-o", help="Optional output file to save key."),
) -> None:
    """Generate a cryptographically secure 256-bit signing key for skill releases."""
    from skillforge.signing import SkillSigner

    key = SkillSigner.generate_key()
    if out:
        out.write_text(key.strip() + "\n", encoding="utf-8")
        typer.echo(f"Generated secret key saved to {out}")
    else:
        typer.echo(f"Secret signing key (keep safe!):\n{key}")


@app.command("sign")
def sign_artifact(
    path: Path = typer.Argument(..., help="Path to skill directory or skillforge.lock."),
    key: str | None = typer.Option(None, "--key", "-k", help="Secret key hex string (or env SKILLFORGE_KEY)."),
    key_file: Path | None = typer.Option(None, "--key-file", help="File containing secret key."),
    signer: str = typer.Option("local-maintainer", "--signer", help="Signer identity tag."),
) -> None:
    """Sign a skill package or lockfile with HMAC-SHA256 tamper-evident attestation."""
    import os
    from skillforge.signing import SkillSigner, SigningError

    secret = key or (
        key_file.read_text(encoding="utf-8").strip()
        if key_file and key_file.is_file()
        else os.environ.get("SKILLFORGE_KEY")
    )
    if not secret:
        typer.echo("Error: A signing key must be provided via --key, --key-file, or SKILLFORGE_KEY env var.", err=True)
        raise typer.Exit(code=1)

    try:
        if path.is_file() and path.name.endswith(".lock"):
            sig_file = SkillSigner.sign_lockfile(path, secret, signer_id=signer)
            typer.echo(f"Signed lockfile: {sig_file}")
        elif path.is_dir() or path.name == "SKILL.md":
            skill_dir = path if path.is_dir() else path.parent
            payload = SkillSigner.sign_skill(skill_dir, secret, signer_id=signer)
            sig_file = SkillSigner.write_signature(skill_dir, payload)
            typer.echo(f"Signed skill package ({len(payload['manifest'])} files): {sig_file}")
        else:
            typer.echo(f"Error: Path {path} is neither a skill directory nor a lockfile.", err=True)
            raise typer.Exit(code=1)
    except SigningError as exc:
        typer.echo(f"Signing failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@app.command("verify-signature")
def verify_sig(
    path: Path = typer.Argument(..., help="Path to skill directory or skillforge.lock to verify."),
    key: str | None = typer.Option(None, "--key", "-k", help="Optional secret key to verify HMAC."),
    key_file: Path | None = typer.Option(None, "--key-file", help="File containing secret key."),
) -> None:
    """Verify signature manifest integrity and cryptographic authenticity."""
    import os
    from skillforge.signing import SkillSigner

    secret = key or (
        key_file.read_text(encoding="utf-8").strip()
        if key_file and key_file.is_file()
        else os.environ.get("SKILLFORGE_KEY")
    )

    if path.is_file() and path.name.endswith(".lock"):
        res = SkillSigner.verify_lockfile(path, key=secret)
    elif path.is_dir() or path.name == "SKILL.md":
        skill_dir = path if path.is_dir() else path.parent
        res = SkillSigner.verify_skill(skill_dir, key=secret)
    else:
        typer.echo(f"Error: Path {path} is neither a skill directory nor a lockfile.", err=True)
        raise typer.Exit(code=1)

    if res.valid:
        typer.echo(f"Verification PASSED: {res.summary}")
    else:
        typer.echo(f"Verification FAILED: {res.summary}", err=True)
        for issue in res.issues:
            typer.echo(f"  [TAMPER DETECTED] {issue}", err=True)
        raise typer.Exit(code=1)


@app.command("tui")
def tui_command(
    project: Path = typer.Option(Path("."), "--project", "-p", help="Target project root."),
    static: bool = typer.Option(False, "--static", help="Print static dashboard snapshot once."),
    watch: bool = typer.Option(False, "--watch", "-w", help="Enable continuous live refresh."),
) -> None:
    """Launch interactive terminal dashboard showing token budgets, security posture, and skills."""
    from skillforge.tui import run_tui

    run_tui(project, watch=watch)


@app.command("firewall-mcp")
def firewall_mcp(
    check: Path | None = typer.Option(None, "--check", "-c", help="Inspect a JSONL file of MCP JSON-RPC traffic."),
    audit_log: Path | None = typer.Option(None, "--audit-log", "-l", help="Path to write JSONL forensic audit log."),
    allow_tool: list[str] | None = typer.Option(None, "--allow-tool", "-a", help="Restrict allowed MCP tool names."),
    no_redact: bool = typer.Option(False, "--no-redact", help="Disable automatic secret redaction on responses."),
    json_output: bool = typer.Option(False, "--json", help="Emit audit summary as JSON."),
    command: list[str] | None = typer.Argument(None, help="Upstream MCP server command and arguments to proxy."),
) -> None:
    """Run inline zero-trust MCP JSON-RPC security firewall or inspect a JSONL traffic capture."""
    from skillforge.mcp_firewall import MCPFirewall

    allowed_set = set(allow_tool) if allow_tool else None
    fw = MCPFirewall(
        allowed_tools=allowed_set,
        audit_log_path=audit_log,
        redact_secrets=not no_redact,
    )

    try:
        if check is not None:
            if not check.is_file():
                typer.echo(f"Error: JSONL file not found: {check}", err=True)
                raise typer.Exit(code=1)
            lines = check.read_text(encoding="utf-8").splitlines()
            summary = fw.audit_stream(lines)
            if json_output:
                typer.echo(json.dumps(summary.to_dict(), indent=2))
            else:
                status_str = "PASSED" if summary.passed else "BLOCKED"
                typer.echo(
                    f"MCP Firewall Inspection: {status_str} "
                    f"(Total: {summary.total_messages}, Allowed: {summary.allowed_count}, "
                    f"Redacted: {summary.redacted_count}, Blocked: {summary.blocked_count})"
                )
                for dec in summary.decisions:
                    if dec.violations:
                        for v in dec.violations:
                            typer.echo(f"  [{dec.action}] {v.rule_id} ({v.severity}) at {v.field_path}: {v.message}")
            if not summary.passed:
                raise typer.Exit(code=1)
            return

        if not command:
            typer.echo("Error: Provide either --check <jsonl_file> or an upstream MCP command to proxy.", err=True)
            raise typer.Exit(code=1)

        rc = fw.run_stdio_proxy(command)
        raise typer.Exit(code=rc)
    except SkillForgeError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc


@app.command("bench")
def bench_command(
    path: Path = typer.Argument(Path("."), help="Path to a skill directory or collection root."),
    evals: Path | None = typer.Option(None, "--evals", "-e", help="Custom evals.json file path."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Save JSON benchmark scorecard to file."),
    json_output: bool = typer.Option(False, "--json", help="Emit benchmark report as JSON."),
) -> None:
    """Run multi-model semantic trigger benchmark matrix (Precision, Recall, F1, FPR)."""
    from skillforge.benchmark import run_benchmark

    try:
        packages = _discover_packages(path=path)
        if not packages:
            pkg_dir = path.parent if path.is_file() else path
            packages = {pkg_dir.name: SkillPackage.load(pkg_dir)}

        reports = []
        any_failed = False
        for _, pkg in sorted(packages.items()):
            if pkg.source_dir is None:
                continue
            rep = run_benchmark(pkg.source_dir, evals_path=evals if len(packages) == 1 else None)
            reports.append(rep)
            if not rep.passed:
                any_failed = True

        payload = {
            "passed": not any_failed,
            "skill_count": len(reports),
            "benchmarks": [r.to_dict() for r in reports],
        }
        if output is not None:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        if json_output:
            typer.echo(json.dumps(payload, indent=2))
        else:
            for r in reports:
                typer.echo(r.render_text())
                typer.echo("")
            if output is not None:
                typer.echo(f"Saved benchmark scorecard to {output}")

        if any_failed:
            raise typer.Exit(code=1)
    except SkillForgeError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc


@app.command("refactor-progressive")
def refactor_progressive_command(
    path: Path = typer.Argument(..., help="Path to the skill directory to slice into progressive disclosure."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Output directory (defaults to in-place)."),
    target_tokens: int = typer.Option(500, "--target-tokens", "-t", help="Target token ceiling for SKILL.md body."),
    min_lines: int = typer.Option(8, "--min-lines", help="Minimum section lines required for extraction."),
    json_output: bool = typer.Option(False, "--json", help="Emit refactoring report as JSON."),
) -> None:
    """Slice a monolithic SKILL.md into progressive disclosure references with semantic preservation."""
    from skillforge.optimizer import refactor_progressive_skill

    try:
        pkg_dir = path.parent if path.is_file() else path
        res = refactor_progressive_skill(
            pkg_dir,
            output_dir=output,
            target_tokens=target_tokens,
            min_section_lines=min_lines,
        )
        if json_output:
            typer.echo(json.dumps(res, indent=2))
        else:
            typer.echo(f"Progressive Disclosure Refactoring: {res['skill']}")
            typer.echo(f"  Original Body:  {res['original_lines']} lines (~{res['original_tokens']} tokens)")
            typer.echo(f"  Optimized Body: {res['optimized_lines']} lines (~{res['optimized_tokens']} tokens)")
            typer.echo(f"  Tokens Saved:   {res['tokens_saved']} tokens")
            typer.echo(f"  Preservation:   {res['semantic_preservation_ratio']:.1%} semantic vocabulary retained")
            if res["extracted_references"]:
                typer.echo("  Extracted References:")
                for ref in res["extracted_references"]:
                    typer.echo(f"    + {ref}")
        if not res["passed_audit"]:
            raise typer.Exit(code=1)
    except SkillForgeError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc


@app.command("run-sandboxed")
def run_sandboxed_command(
    script: Path = typer.Argument(..., help="Path to Python script to execute inside the capability jail."),
    timeout: float = typer.Option(5.0, "--timeout", "-t", help="Execution timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit execution report as JSON."),
    args: list[str] | None = typer.Argument(None, help="Arguments passed to the script."),
) -> None:
    """Execute a bundled Python script inside an isolated zero-trust capability jail."""
    from skillforge.sandbox_runner import run_in_sandbox

    try:
        res = run_in_sandbox(script, script_args=args, timeout_sec=timeout)
        if json_output:
            typer.echo(json.dumps(res.to_dict(), indent=2))
        else:
            status_str = "PASSED" if res.passed else "BLOCKED / FAILED"
            typer.echo(
                f"Sandbox Execution [{status_str}]: {res.script_path} "
                f"(exit={res.exit_code}, {res.duration_ms:.1f}ms)"
            )
            if res.blocked_events:
                for ev in res.blocked_events:
                    typer.echo(f"  [BLOCKED:{ev['category']}] {ev['detail']}", err=True)
            if res.stdout.strip():
                typer.echo(res.stdout.rstrip())
        if not res.passed:
            raise typer.Exit(code=1)
    except SkillForgeError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc


@app.command("sbom")
def sbom_command(
    path: Path = typer.Argument(Path("."), help="Project root or skill directory to inventory."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write SBOM JSON to file (e.g. bom.json)."),
    sbom_format: str = typer.Option("cyclonedx", "--format", "-f", help="SBOM format: 'cyclonedx' (v1.6) or 'spdx' (v2.3)."),
    include_builtin: bool = typer.Option(False, "--include-builtin", help="Include built-in catalog skills in inventory."),
    json_output: bool = typer.Option(False, "--json", help="Emit full SBOM JSON to stdout."),
) -> None:
    """Generate a CycloneDX v1.6 AIBOM or SPDX v2.3 Software Bill of Materials for agent skills and MCP servers."""
    from skillforge.sbom import generate_sbom

    try:
        packages = _discover_packages(path=path, builtin=include_builtin)
        report = generate_sbom(
            packages=packages,
            project_root=path if path.is_dir() else path.parent,
            sbom_format=sbom_format,
        )
        if output is not None:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(report.to_json(indent=2), encoding="utf-8")

        if json_output:
            typer.echo(report.to_json(indent=2))
        else:
            typer.echo(report.render_text())
            if output is not None:
                typer.echo(f"\nSaved {report.format_name} SBOM to {output}")
    except (SkillForgeError, ValueError, OSError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc


@app.command("provenance")
def provenance_command(
    path: Path = typer.Argument(..., help="Path to skill directory or SKILL.md file."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Output path (defaults to <skill>/provenance.intoto.jsonl)."),
    key: str | None = typer.Option(None, "--key", "-k", envvar="SKILLFORGE_SIGNING_KEY", help="Optional HMAC signing key."),
    signer_id: str = typer.Option("skillforge-attestor", "--signer", "-s", help="Attestor / signer identifier."),
    json_output: bool = typer.Option(False, "--json", help="Emit provenance envelope JSON to stdout."),
) -> None:
    """Generate an in-toto v1 Statement with SLSA v1.0 Provenance attestation for a skill package."""
    from skillforge.provenance import generate_provenance, write_provenance

    try:
        envelope = generate_provenance(path, signing_key=key, signer_id=signer_id)
        written = write_provenance(path, envelope, output_path=output)
        if json_output:
            typer.echo(json.dumps(envelope, indent=2))
        else:
            stmt = envelope["statement"]
            subj_count = len(stmt.get("subject", []))
            signed_state = "signed" if envelope.get("signatures") else "unsigned"
            typer.echo(f"Generated SLSA v1.0 provenance ({signed_state}, {subj_count} subjects) -> {written}")
    except (SkillForgeError, OSError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc


@app.command("verify-provenance")
def verify_provenance_command(
    path: Path = typer.Argument(..., help="Path to skill directory or SKILL.md file."),
    provenance_file: Path | None = typer.Option(None, "--provenance", "-p", help="Custom provenance file path."),
    key: str | None = typer.Option(None, "--key", "-k", envvar="SKILLFORGE_SIGNING_KEY", help="HMAC key to verify envelope signature."),
    json_output: bool = typer.Option(False, "--json", help="Emit verification result as JSON."),
) -> None:
    """Verify SLSA v1.0 provenance subject digests and optional HMAC signature against skill files on disk."""
    from skillforge.provenance import verify_provenance

    res = verify_provenance(path, provenance_path=provenance_file, signing_key=key)
    if json_output:
        typer.echo(json.dumps(res.to_dict(), indent=2))
    else:
        typer.echo(res.render_text())
    if not res.valid:
        raise typer.Exit(code=1)


@app.command("graph")
def graph_command(
    path: Path = typer.Argument(Path("."), help="Project root or skills directory to analyze."),
    mermaid: bool = typer.Option(False, "--mermaid", help="Output Mermaid flowchart TD diagram."),
    include_builtin: bool = typer.Option(False, "--include-builtin", help="Include built-in catalog skills."),
    json_output: bool = typer.Option(False, "--json", help="Emit dependency graph analysis as JSON."),
) -> None:
    """Analyze skill dependency graph, compute topological load order, and detect cycles or privilege escalation."""
    from skillforge.dependency_graph import analyze_dependency_graph

    try:
        packages = _discover_packages(path=path, builtin=include_builtin)
        report = analyze_dependency_graph(packages)
        if json_output:
            typer.echo(json.dumps(report.to_dict(), indent=2))
        elif mermaid:
            typer.echo(report.to_mermaid())
        else:
            typer.echo(report.render_text())
        if not report.passed:
            raise typer.Exit(code=1)
    except SkillForgeError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc


@app.command("sync-rules")
def sync_rules_command(
    project: Path = typer.Argument(Path("."), help="Target project root containing AGENTS.md."),
    source: str = typer.Option("AGENTS.md", "--source", "-s", help="Source of truth instruction file name."),
    targets: str = typer.Option("cursor,claude,cursorrules", "--targets", "-t", help="Comma-separated targets: cursor,claude,cursorrules,windsurf,cline."),
    check: bool = typer.Option(False, "--check", help="Check for rule drift and directive conflicts without modifying files."),
    json_output: bool = typer.Option(False, "--json", help="Emit synchronization report as JSON."),
) -> None:
    """Synchronize AGENTS.md into .cursor/rules/00-core.mdc, CLAUDE.md, and editor rule files, or check for drift."""
    from skillforge.rule_sync import sync_context_rules

    target_list = [t.strip().lower() for t in targets.split(",") if t.strip()]
    try:
        report = sync_context_rules(
            project_root=project,
            source_file=source,
            targets=target_list,
            check_only=check,
        )
        if json_output:
            typer.echo(json.dumps(report.to_dict(), indent=2))
        else:
            typer.echo(report.render_text())
        if not report.passed:
            raise typer.Exit(code=1)
    except SkillForgeError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc


@app.command("policy")
def policy_command(
    path: Path = typer.Argument(Path(".skillforge-policy.yaml"), help="Path to policy YAML file."),
    init: bool = typer.Option(False, "--init", help="Create a starter .skillforge-policy.yaml file."),
    check: bool = typer.Option(False, "--check", help="Validate syntax, severity overrides, and expiration dates."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    """Create or validate a .skillforge-policy.yaml security policy file."""
    from .policy import SecurityPolicy

    try:
        if init:
            if path.exists():
                typer.echo(f"Policy file already exists: {path}", err=True)
                raise typer.Exit(code=1)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(SecurityPolicy.default_template(), encoding="utf-8")
            if json_output:
                typer.echo(json.dumps({"created": str(path)}))
            else:
                typer.echo(f"Created starter security policy at {path}")
            return

        loaded = SecurityPolicy.load(path)
        expired = [s.rule_id for s in loaded.suppressions if s.is_expired()]
        payload = {
            "valid": True,
            "path": str(path),
            "min_score": loaded.min_score,
            "disable_rules": sorted(loaded.disable_rules),
            "severity_overrides": {k: v.value for k, v in loaded.severity_overrides.items()},
            "suppressions_count": len(loaded.suppressions),
            "expired_suppressions": expired,
        }
        if json_output:
            typer.echo(json.dumps(payload, indent=2))
        else:
            typer.echo(
                f"Policy valid: {path} (min_score={loaded.min_score}, "
                f"suppressions={len(loaded.suppressions)}, expired={len(expired)})"
            )
        if check and expired:
            raise typer.Exit(code=1)
    except (SkillForgeError, OSError) as exc:
        if json_output:
            typer.echo(json.dumps({"valid": False, "error": str(exc)}))
        else:
            typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc


@app.command("scan-all")
def scan_all_command(
    path: Path = typer.Argument(Path("."), help="Workspace root directory to sweep."),
    home: bool = typer.Option(False, "--home", help="Include standard user home IDE directories (~/.claude, ~/.cursor, ~/.gemini, ~/.windsurf)."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON report."),
    sarif_output: Path | None = typer.Option(None, "--sarif", help="Write consolidated OASIS SARIF v2.1.0 report."),
) -> None:
    """Sweep project and local IDE directories for all skills and MCP configurations."""
    from .scanner_sweep import run_machine_sweep

    report = run_machine_sweep(project_root=path, include_home=home)
    if sarif_output is not None:
        sarif_output.parent.mkdir(parents=True, exist_ok=True)
        sarif_output.write_text(json.dumps(report.to_sarif(), indent=2), encoding="utf-8")
        if not json_output:
            typer.echo(f"Wrote SARIF sweep report to {sarif_output}")

    if json_output:
        typer.echo(json.dumps(report.to_dict(), indent=2))
    else:
        typer.echo(report.render_text())
    if not report.passed:
        raise typer.Exit(code=1)


@app.command("check")
def check_command(
    project: Path = typer.Option(Path("."), "--project", "-p", help="Target project root containing skillforge.lock."),
    global_scope: bool = typer.Option(False, "--global", "-g", help="Discover globally installed skills."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    """Check installed skills in skillforge.lock for upstream updates or local drift."""
    from .lifecycle import check_lockfile_updates

    try:
        installed = _discover_packages(project, global_scope=global_scope)
        report = check_lockfile_updates(project_root=project, installed_packages=installed)
        if json_output:
            typer.echo(json.dumps(report.to_dict(), indent=2))
        else:
            typer.echo(report.render_text())
        if report.updates_available > 0 or report.drift_count > 0:
            raise typer.Exit(code=1)
    except SkillForgeError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc


@app.command("update")
def update_command(
    skills: list[str] | None = typer.Argument(None, help="Optional skill names to update (defaults to all in lockfile)."),
    project: Path = typer.Option(Path("."), "--project", "-p", help="Target project root containing skillforge.lock."),
    min_score: int = typer.Option(80, "--min-score", help="Minimum security audit score required to accept an update."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    """Fetch, security-audit, and update locked skills recorded in skillforge.lock."""
    from .lifecycle import update_locked_skills

    try:
        result = update_locked_skills(
            project_root=project,
            skill_names=skills,
            min_score=min_score,
        )
        if json_output:
            typer.echo(json.dumps(result, indent=2))
        else:
            typer.echo(
                f"SkillForge Update: {len(result['updated'])} updated, "
                f"{len(result['skipped'])} up-to-date, {len(result['blocked'])} blocked by security gate"
            )
            for item in result["updated"]:
                typer.echo(f"  [UPDATED] {item['name']} (score: {item['audit_score']}/100)")
            for item in result["blocked"]:
                typer.echo(
                    f"  [BLOCKED] {item['name']} failed audit gate (score={item['score']}, findings={item['findings']})",
                    err=True,
                )
        if not result["passed"]:
            raise typer.Exit(code=1)
    except SkillForgeError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc


@app.command("migrate-lock")
def migrate_lock_command(
    source: Path = typer.Argument(Path("skills-lock.json"), help="Path to vercel-labs/skills lockfile (skills-lock.json)."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Destination path (defaults to skillforge.lock)."),
    project: Path = typer.Option(Path("."), "--project", "-p", help="Project root for computing SHA-256 of installed skills."),
    json_output: bool = typer.Option(False, "--json", help="Emit migration summary as JSON."),
) -> None:
    """Convert a vercel-labs/skills skills-lock.json file into skillforge.lock."""
    from .lifecycle import migrate_vercel_lockfile

    try:
        installed = _discover_packages(project)
        summary = migrate_vercel_lockfile(
            source_lock=source,
            output_lock=output,
            installed_packages=installed,
        )
        if json_output:
            typer.echo(json.dumps(summary, indent=2))
        else:
            typer.echo(
                f"Migrated {summary['migrated_count']} skill(s) from {summary['source']} -> {summary['output']}"
            )
    except SkillForgeError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc


@app.command("telemetry")
def telemetry_command(
    project: Path = typer.Argument(Path("."), help="Target project root."),
    clear: bool = typer.Option(False, "--clear", help="Clear local telemetry ledger."),
    json_output: bool = typer.Option(False, "--json", help="Emit telemetry summary as JSON."),
) -> None:
    """Inspect local offline skill usage ledger and identify unused pointer-token waste."""
    from .telemetry import render_telemetry_report, resolve_telemetry_path, summarize_telemetry

    log_path = resolve_telemetry_path(project)
    if clear:
        if log_path.is_file():
            log_path.unlink()
        if json_output:
            typer.echo(json.dumps({"cleared": str(log_path)}))
        else:
            typer.echo(f"Cleared local telemetry log: {log_path}")
        return

    installed = _discover_packages(project)
    summary = summarize_telemetry(log_path, installed_packages=installed)
    if json_output:
        typer.echo(json.dumps(summary, indent=2))
    else:
        typer.echo(render_telemetry_report(summary))


if __name__ == "__main__":
    app()

