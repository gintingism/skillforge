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
from .security import Severity, SkillAuditor, audit_mcp_config, audit_path, pin_mcp_config
from .skill import Skill, SkillPackage

app = typer.Typer(help="Universal package manager, security auditor, and MCP server for portable agent skills.")
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def _registry(path: Path) -> Registry:
    """Use configured local skills first, then explicit packaged built-ins."""
    return CompositeRegistry((LocalRegistry(path), BuiltinRegistry()))


@app.command()
def validate(
    path: Path,
    strict_spec: bool = typer.Option(False, "--strict-spec", help="Enforce strict agentskills.io specification limits."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    """Validate a SKILL.md file or skill directory against the portable specification."""
    try:
        skill = Skill.load(path)
        source_dir = path.resolve() if path.is_dir() else (path.resolve().parent if path.name == "SKILL.md" else None)
        if strict_spec:
            issues = skill.validate_strict_spec(source_dir=source_dir)
            if issues:
                raise SkillForgeError("; ".join(issues))
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
    rules_file: Path | None = typer.Option(None, "--rules", help="Path to a custom YAML/YARA-style rule pack file."),
    llm_judge: bool = typer.Option(False, "--llm-judge", help="Run opt-in prompt-hardened LLM semantic intent-vs-behavior review."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
    sarif_output: Path | None = typer.Option(None, "--sarif", help="Emit OASIS SARIF v2.1.0 report for GitHub Code Scanning."),
) -> None:
    """Audit a skill for prompt injection, zero-width unicode, and security issues."""
    from .custom_rules import load_custom_rule_pack, merge_custom_rule_findings
    from .policy import SecurityPolicy, apply_policy
    from .semantic_judge import run_semantic_judge

    try:
        report = audit_path(path, sandbox=sandbox)
        if rules_file is not None:
            loaded_rules = load_custom_rule_pack(rules_file)
            target_pkg = SkillPackage.load(path)
            merge_custom_rule_findings(report, target_pkg, loaded_rules)
        if llm_judge:
            target_pkg = SkillPackage.load(path)
            judge_res = run_semantic_judge(target_pkg)
            report.findings.extend(judge_res.findings)
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
    pin_lock: Path | None = typer.Option(None, "--pin-lock", help="Write pinned MCP server & tool schema hashes to lockfile."),
    verify_lock: Path | None = typer.Option(None, "--verify-lock", help="Verify MCP config against pinned mcp-lock.json to detect rug-pulls (MCP-008)."),
    live: bool = typer.Option(False, "--live", help="Probe configured stdio/HTTP MCP servers live for tools/prompts/resources and MCP Apps."),
    server_card: Path | None = typer.Option(None, "--server-card", help="Audit an MCP Server Card JSON (/.well-known/mcp/server-card.json)."),
    strict: bool = typer.Option(False, "--strict", help="Fail on any warning or low-severity finding."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
    sarif_output: Path | None = typer.Option(None, "--sarif", help="Emit OASIS SARIF v2.1.0 report for GitHub Code Scanning."),
) -> None:
    """Audit an MCP configuration file for plaintext secrets, shell command wrappers, unpinned packages, and rug-pulls."""
    from .mcp_live import audit_mcp_app_resource, audit_mcp_server_card, probe_http_mcp_server, probe_stdio_mcp_server
    from .security import AuditFinding, Severity, _extract_mcp_servers

    try:
        if server_card is not None:
            report = audit_mcp_server_card(server_card)
        else:
            if pin_lock is not None:
                written_lock = pin_mcp_config(path, lock_path=pin_lock)
                if not json_output:
                    typer.echo(f"Pinned MCP server & tool fingerprints to {written_lock}")
            report = audit_mcp_config(path, lock_path=verify_lock)
            if live and path.is_file():
                raw_cfg = json.loads(path.read_text(encoding="utf-8"))
                servers = _extract_mcp_servers(raw_cfg)
                for s_name, s_cfg in sorted(servers.items()):
                    if not isinstance(s_cfg, dict):
                        continue
                    cmd = str(s_cfg.get("command", "")).strip()
                    remote_url = str(s_cfg.get("url", s_cfg.get("endpoint", ""))).strip()
                    if cmd:
                        args = [str(a) for a in (s_cfg.get("args") or [])] if isinstance(s_cfg.get("args"), list) else []
                        env_map = {str(k): str(v) for k, v in (s_cfg.get("env") or {}).items()} if isinstance(s_cfg.get("env"), dict) else {}
                        disc = probe_stdio_mcp_server(s_name, cmd, args, env_map)
                    elif remote_url:
                        hdrs = {str(k): str(v) for k, v in (s_cfg.get("headers") or {}).items()} if isinstance(s_cfg.get("headers"), dict) else {}
                        disc = probe_http_mcp_server(s_name, remote_url, hdrs)
                    else:
                        continue
                    if not disc.reachable:
                        report.findings.append(
                            AuditFinding(
                                rule_id="MCP-008",
                                severity=Severity.LOW,
                                message=f"Live MCP probe unreachable for server '{s_name}': {disc.error}",
                                file=f"{path.name}::{s_name}",
                            )
                        )
                        continue
                    for res in disc.resources:
                        uri = str(res.get("uri", ""))
                        if uri.startswith("ui://"):
                            report.findings.extend(
                                audit_mcp_app_resource(
                                    uri,
                                    html=str(res.get("text", res.get("html", ""))),
                                    csp=str(res.get("csp", "")),
                                    sandbox_flags=res.get("sandbox"),
                                    source_label=f"{path.name}::{s_name}",
                                )
                            )
    except (SkillForgeError, OSError, json.JSONDecodeError) as exc:
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
            Path.home() / ".gemini" / "skills",
            Path.home() / ".claude" / "skills",
            Path.home() / ".cursor" / "skills",
            Path.home() / ".opencode" / "skills",
            Path.home() / ".roo" / "skills",
            Path.home() / ".codex" / "skills",
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
        target / ".opencode" / "skills",
        target / ".roo" / "skills",
        target / ".codex" / "skills",
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
def serve_mcp(
    transport: str = typer.Option("stdio", "--transport", "-t", help="MCP transport: stdio, sse, or streamable-http."),
) -> None:
    """Serve SkillForge over MCP."""
    if transport not in ("stdio", "sse", "streamable-http"):
        typer.echo(f"Error: Unsupported MCP transport '{transport}'. Use stdio, sse, or streamable-http.", err=True)
        raise typer.Exit(code=1)
    run_mcp_server(transport=transport)  # type: ignore[arg-type]


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
    out: Path | None = typer.Option(None, "--out", "-o", help="Optional output file to save key (for ed25519, writes <out> and <out>.pub)."),
    algorithm: str = typer.Option("hmac-sha256", "--algorithm", "-a", help="Key algorithm: hmac-sha256 or ed25519."),
) -> None:
    """Generate a cryptographic signing key or Ed25519 keypair for skill releases."""
    from skillforge.signing import SkillSigner, SigningError

    try:
        if algorithm == "ed25519":
            priv_pem, pub_pem = SkillSigner.generate_ed25519_keypair()
            if out:
                out.write_text(priv_pem, encoding="utf-8")
                pub_path = out.with_suffix(out.suffix + ".pub") if out.suffix else Path(f"{out}.pub")
                pub_path.write_text(pub_pem, encoding="utf-8")
                typer.echo(f"Generated Ed25519 keypair: private={out}, public={pub_path}")
            else:
                typer.echo(f"{priv_pem}\n{pub_pem}")
            return

        if algorithm != "hmac-sha256":
            typer.echo(f"Error: Unsupported algorithm '{algorithm}'.", err=True)
            raise typer.Exit(code=1)

        key = SkillSigner.generate_key()
        if out:
            out.write_text(key.strip() + "\n", encoding="utf-8")
            typer.echo(f"Generated secret key saved to {out}")
        else:
            typer.echo(f"Secret signing key (keep safe!):\n{key}")
    except SigningError as exc:
        typer.echo(f"Keygen failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@app.command("sign")
def sign_artifact(
    path: Path = typer.Argument(..., help="Path to skill directory or skillforge.lock."),
    key: str | None = typer.Option(None, "--key", "-k", help="Secret key hex or Ed25519 PEM (or env SKILLFORGE_KEY)."),
    key_file: Path | None = typer.Option(None, "--key-file", help="File containing secret key or Ed25519 private key PEM."),
    signer: str = typer.Option("local-maintainer", "--signer", help="Signer identity tag."),
    algorithm: str = typer.Option("hmac-sha256", "--algorithm", "-a", help="Signing algorithm: hmac-sha256, ed25519, or sigstore-bundle."),
    sigstore: bool = typer.Option(False, "--sigstore", help="Sign using Sigstore Bundle v0.3 keyless OIDC + Rekor format."),
    oidc_issuer: str = typer.Option("https://token.actions.githubusercontent.com", "--oidc-issuer", help="OIDC issuer claim for Sigstore bundles."),
    oidc_identity: str | None = typer.Option(None, "--oidc-identity", help="OIDC identity subject claim for Sigstore bundles."),
) -> None:
    """Sign a skill package or lockfile with tamper-evident cryptographic attestation."""
    import os
    from skillforge.signing import SkillSigner, SigningError

    effective_alg = "sigstore-bundle" if sigstore else algorithm
    secret = key or (
        key_file.read_text(encoding="utf-8").strip()
        if key_file and key_file.is_file()
        else os.environ.get("SKILLFORGE_KEY")
    )

    if effective_alg == "sigstore-bundle":
        skill_dir = path if path.is_dir() else path.parent
        try:
            bundle, _ = SkillSigner.sign_sigstore_bundle(
                skill_dir,
                oidc_issuer=oidc_issuer,
                oidc_identity=oidc_identity or signer,
                private_key_pem=secret,
            )
            bundle_path = skill_dir / "SKILL.sigstore.json"
            bundle_path.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
            typer.echo(f"Signed skill package (sigstore-bundle): {bundle_path}")
        except SigningError as exc:
            typer.echo(f"Signing failed: {exc}", err=True)
            raise typer.Exit(code=1) from exc
        return

    if not secret:
        typer.echo("Error: A signing key must be provided via --key, --key-file, or SKILLFORGE_KEY env var.", err=True)
        raise typer.Exit(code=1)

    try:
        if path.is_file() and path.name.endswith(".lock"):
            sig_file = SkillSigner.sign_lockfile(path, secret, signer_id=signer, algorithm=effective_alg)
            typer.echo(f"Signed lockfile ({effective_alg}): {sig_file}")
        elif path.is_dir() or path.name == "SKILL.md":
            skill_dir = path if path.is_dir() else path.parent
            payload = SkillSigner.sign_skill(skill_dir, secret, signer_id=signer, algorithm=effective_alg)
            sig_file = SkillSigner.write_signature(skill_dir, payload)
            typer.echo(f"Signed skill package ({len(payload['manifest'])} files, {effective_alg}): {sig_file}")
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
    sigstore_bundle: Path | None = typer.Option(None, "--sigstore-bundle", help="Verify a Sigstore Bundle v0.3 JSON file."),
    oidc_issuer: str | None = typer.Option(None, "--oidc-issuer", help="Expected OIDC issuer for Sigstore verification."),
    oidc_identity: str | None = typer.Option(None, "--oidc-identity", help="Expected OIDC identity subject for Sigstore verification."),
) -> None:
    """Verify signature manifest integrity and cryptographic authenticity."""
    import os
    from skillforge.signing import SkillSigner

    secret = key or (
        key_file.read_text(encoding="utf-8").strip()
        if key_file and key_file.is_file()
        else os.environ.get("SKILLFORGE_KEY")
    )

    if sigstore_bundle is not None:
        skill_dir = path if path.is_dir() else path.parent
        res = SkillSigner.verify_sigstore_bundle(
            skill_dir,
            sigstore_bundle,
            expected_issuer=oidc_issuer,
            expected_identity=oidc_identity,
            public_key_pem=secret,
        )
    elif path.is_file() and path.name.endswith(".lock"):
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
    wrap_config: Path | None = typer.Option(None, "--wrap-config", "-w", help="Wrap mcpServers in an mcp.json file with skillforge firewall-mcp."),
    http_upstream: str | None = typer.Option(None, "--http-upstream", help="Upstream MCP Streamable-HTTP URL to reverse-proxy through the firewall."),
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host for HTTP proxy mode."),
    port: int = typer.Option(8787, "--port", help="Bind port for HTTP proxy mode."),
    audit_log: Path | None = typer.Option(None, "--audit-log", "-l", help="Path to write JSONL forensic audit log."),
    allow_tool: list[str] | None = typer.Option(None, "--allow-tool", "-a", help="Restrict allowed MCP tool names."),
    no_redact: bool = typer.Option(False, "--no-redact", help="Disable automatic secret redaction on responses."),
    json_output: bool = typer.Option(False, "--json", help="Emit audit summary as JSON."),
    command: list[str] | None = typer.Argument(None, help="Upstream MCP server command and arguments to proxy."),
) -> None:
    """Run inline zero-trust MCP JSON-RPC security firewall (stdio or Streamable-HTTP) or inspect a JSONL traffic capture."""
    from skillforge.mcp_firewall import MCPFirewall, wrap_mcp_config

    allowed_set = set(allow_tool) if allow_tool else None
    fw = MCPFirewall(
        allowed_tools=allowed_set,
        audit_log_path=audit_log,
        redact_secrets=not no_redact,
    )

    try:
        if http_upstream is not None:
            typer.echo(f"Starting SkillForge MCP Streamable-HTTP Firewall on http://{host}:{port} -> {http_upstream}")
            rc = fw.run_http_proxy(http_upstream, host=host, port=port)
            raise typer.Exit(code=rc)

        if wrap_config is not None:
            res = wrap_mcp_config(wrap_config)
            if json_output:
                typer.echo(json.dumps(res, indent=2))
            else:
                typer.echo(f"Wrapped {res['wrapped_servers']} MCP server(s) in {res['config']}")
            return

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
            typer.echo("Error: Provide --check <jsonl_file>, --http-upstream <url>, or an upstream MCP command to proxy.", err=True)
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
    key: str | None = typer.Option(None, "--key", "-k", envvar="SKILLFORGE_SIGNING_KEY", help="Optional HMAC key or Ed25519 private key PEM."),
    key_file: Path | None = typer.Option(None, "--key-file", help="Optional file containing signing key or Ed25519 private key PEM."),
    algorithm: str = typer.Option("hmac-sha256", "--algorithm", "-a", help="Signing algorithm: hmac-sha256, ed25519, or sigstore-bundle."),
    sigstore: bool = typer.Option(False, "--sigstore", help="Generate SLSA v1.0 provenance as a Sigstore Bundle v0.3 OIDC attestation."),
    signer_id: str = typer.Option("skillforge-attestor", "--signer", "-s", help="Attestor / signer identifier."),
    json_output: bool = typer.Option(False, "--json", help="Emit provenance envelope JSON to stdout."),
) -> None:
    """Generate an in-toto v1 Statement with SLSA v1.0 Provenance attestation for a skill package."""
    from skillforge.provenance import generate_provenance, write_provenance

    effective_alg = "sigstore-bundle" if sigstore else algorithm
    resolved_key = key or (key_file.read_text(encoding="utf-8").strip() if key_file and key_file.is_file() else None)
    try:
        envelope = generate_provenance(path, signing_key=resolved_key, signer_id=signer_id, algorithm=effective_alg)
        written = write_provenance(path, envelope, output_path=output)
        if json_output:
            typer.echo(json.dumps(envelope, indent=2))
        else:
            stmt = envelope["statement"]
            subj_count = len(stmt.get("subject", []))
            signed_state = f"signed/{effective_alg}" if envelope.get("signatures") else "unsigned"
            typer.echo(f"Generated SLSA v1.0 provenance ({signed_state}, {subj_count} subjects) -> {written}")
    except (SkillForgeError, OSError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc


@app.command("verify-provenance")
def verify_provenance_command(
    path: Path = typer.Argument(..., help="Path to skill directory or SKILL.md file."),
    provenance_file: Path | None = typer.Option(None, "--provenance", "-p", help="Custom provenance file path."),
    key: str | None = typer.Option(None, "--key", "-k", envvar="SKILLFORGE_SIGNING_KEY", help="HMAC key or Ed25519 public key PEM."),
    key_file: Path | None = typer.Option(None, "--key-file", help="Optional file containing HMAC key or Ed25519 public key PEM."),
    json_output: bool = typer.Option(False, "--json", help="Emit verification result as JSON."),
) -> None:
    """Verify SLSA v1.0 provenance subject digests and optional cryptographic signature against skill files on disk."""
    from skillforge.provenance import verify_provenance

    resolved_key = key or (key_file.read_text(encoding="utf-8").strip() if key_file and key_file.is_file() else None)
    res = verify_provenance(path, provenance_path=provenance_file, signing_key=resolved_key)
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


@app.command("hooks")
def hooks_command(
    project: Path = typer.Argument(Path("."), help="Target project root."),
    init: bool = typer.Option(False, "--init", help="Install PreToolUse, PostToolUse, and UserPromptSubmit guard hooks."),
    target: str = typer.Option("claude", "--target", help="Comma-separated agent targets: claude, cursor, gemini, codex, or all."),
    events: str = typer.Option("PreToolUse,PostToolUse,UserPromptSubmit", "--events", help="Comma-separated hook lifecycle events to install."),
    check_payload: str | None = typer.Option(None, "--check-payload", help="Inspect a JSON tool-call payload against MCP firewall rules."),
    check_response: str | None = typer.Option(None, "--check-response", help="Inspect a PostToolUse JSON/text response for secret leakage or indirect prompt injection."),
    json_output: bool = typer.Option(False, "--json", help="Emit result as JSON."),
) -> None:
    """Install or execute multi-event agent session security hooks (Claude Code, Cursor, Gemini, Codex)."""
    from .mcp_firewall import MCPFirewall
    from .plugins_and_packs import install_agent_hooks

    if check_response is not None:
        fw = MCPFirewall()
        try:
            parsed_resp: Any = json.loads(check_response)
        except json.JSONDecodeError:
            parsed_resp = {"text": check_response}
        resp_msg = (
            parsed_resp
            if isinstance(parsed_resp, dict) and "result" in parsed_resp
            else {"jsonrpc": "2.0", "id": 1, "result": parsed_resp}
        )
        decision, sanitized = fw.inspect_response(resp_msg)
        out = {
            "passed": decision.action != "BLOCK",
            "action": decision.action,
            "sanitized_result": sanitized.get("result"),
            "violations": [
                {"rule_id": v.rule_id, "severity": v.severity, "message": v.message, "field_path": v.field_path}
                for v in decision.violations
            ],
        }
        if json_output:
            typer.echo(json.dumps(out))
        else:
            typer.echo(f"PostToolUse Hook Check: {decision.action} ({len(decision.violations)} violation(s))")
        if decision.action == "BLOCK":
            raise typer.Exit(code=2)
        return

    if check_payload is not None:
        fw = MCPFirewall()
        try:
            parsed = json.loads(check_payload)
        except json.JSONDecodeError as exc:
            raise typer.Exit(code=1) from exc
        req_msg = (
            parsed
            if isinstance(parsed, dict) and "method" in parsed
            else {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": parsed if isinstance(parsed, dict) else {"raw": parsed}}
        )
        decision = fw.inspect_request(req_msg)
        out = {
            "passed": decision.action != "BLOCK",
            "action": decision.action,
            "violations": [
                {"rule_id": v.rule_id, "severity": v.severity, "message": v.message, "field_path": v.field_path}
                for v in decision.violations
            ],
        }
        if json_output:
            typer.echo(json.dumps(out))
        else:
            typer.echo(f"Hook Check: {decision.action} ({len(decision.violations)} violation(s))")
        if decision.action == "BLOCK":
            raise typer.Exit(code=2)
        return

    if init:
        raw_targets = ["claude", "cursor", "gemini", "codex"] if target.strip().lower() == "all" else [t.strip() for t in target.split(",") if t.strip()]
        raw_events = [e.strip() for e in events.split(",") if e.strip()]
        try:
            summary = install_agent_hooks(project, targets=raw_targets, events=raw_events)
        except SkillForgeError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=1) from exc
        if json_output:
            typer.echo(json.dumps(summary))
        else:
            typer.echo(
                f"Installed {', '.join(summary['events'])} security guard hooks into: {', '.join(summary['settings_paths'])}"
            )
        return

    typer.echo("Specify --init, --check-payload '<json>', or --check-response '<json>'.", err=True)
    raise typer.Exit(code=1)


@app.command("normalize")
def normalize_command(
    path: Path = typer.Argument(..., help="Path to SKILL.md file or skill directory to normalize."),
    write: bool = typer.Option(False, "--write", "-w", help="Overwrite SKILL.md in place with AAIF 6-field normalized frontmatter."),
    fix_name: bool = typer.Option(False, "--fix-name", help="Also normalize underscores/invalid chars in the skill name."),
    json_output: bool = typer.Option(False, "--json", help="Emit normalization report as JSON."),
) -> None:
    """Normalize SKILL.md frontmatter to conform strictly to the 6-field AAIF agentskills.io standard."""
    skill_file = path / "SKILL.md" if path.is_dir() else path
    try:
        skill = Skill.load(skill_file)
        normalized, changes = skill.normalize_portable(fix_name=fix_name)
        rendered = normalized.render()
        if write:
            skill_file.write_text(rendered, encoding="utf-8")
        remaining = normalized.validate_strict_spec(source_dir=skill_file.parent if path.is_dir() else None)
    except (SkillForgeError, OSError) as exc:
        if json_output:
            typer.echo(json.dumps({"normalized": False, "error": str(exc)}))
        else:
            typer.echo(f"Normalize error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    payload = {
        "normalized": True,
        "path": str(skill_file),
        "written": write,
        "changes": changes,
        "remaining_strict_issues": remaining,
    }
    if json_output:
        typer.echo(json.dumps(payload, indent=2))
    else:
        typer.echo(f"Normalized '{normalized.name}' ({len(changes)} change(s), written={write})")
        for ch in changes:
            typer.echo(f"  - {ch}")
        for rem in remaining:
            typer.echo(f"  [REMAINING] {rem}")


@app.command("audit-plugin")
def audit_plugin_command(
    path: Path = typer.Argument(Path("."), help="Path to an Agent Plugins 1.0 bundle directory."),
    strict: bool = typer.Option(False, "--strict", help="Fail on any warning or low-severity finding."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
    sarif_output: Path | None = typer.Option(None, "--sarif", help="Emit OASIS SARIF v2.1.0 report."),
) -> None:
    """Audit an Agent Plugins 1.0 bundle (.claude-plugin, .codex-plugin, skills, subagents, MCP, and hooks)."""
    from .plugins_and_packs import audit_plugin_bundle

    try:
        report = audit_plugin_bundle(path)
    except (SkillForgeError, OSError) as exc:
        if json_output:
            typer.echo(json.dumps({"passed": False, "error": str(exc)}))
        else:
            typer.echo(f"Plugin audit error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if sarif_output:
        sarif_output.parent.mkdir(parents=True, exist_ok=True)
        sarif_output.write_text(json.dumps(report.to_sarif(), indent=2), encoding="utf-8")

    if json_output:
        typer.echo(json.dumps(report.to_dict(), indent=2))
    else:
        typer.echo(report.render_text())

    if not report.passed or (strict and report.findings):
        raise typer.Exit(code=1)


@app.command("pack-bundle")
def pack_bundle_command(
    action: str = typer.Argument(..., help="Action: init, audit, or install."),
    manifest: Path = typer.Argument(Path("skillforge-pack.yaml"), help="Path to skillforge-pack.yaml or package.json skill pack."),
    project: Path = typer.Option(Path("."), "--project", "-p", help="Target project root for pack install."),
    json_output: bool = typer.Option(False, "--json", help="Emit result as JSON."),
) -> None:
    """Initialize, security-audit, or install a team Skill Pack bundle (skillforge-pack.yaml / skills.sh interop)."""
    from .plugins_and_packs import SkillPackEntry, SkillPackManifest

    act = action.strip().lower()
    if act == "init":
        starter = SkillPackManifest(
            name=project.resolve().name or "team-skill-pack",
            version="1.0.0",
            description="Curated team SkillForge skill bundle.",
            skills=[
                SkillPackEntry(name="systematic-debugging", source="builtin:systematic-debugging", min_score=90),
                SkillPackEntry(name="secret-sanitizer", source="builtin:secret-sanitizer", min_score=90),
            ],
        )
        manifest.write_text(starter.to_yaml(), encoding="utf-8")
        if json_output:
            typer.echo(json.dumps({"initialized": True, "manifest": str(manifest), "skills": len(starter.skills)}))
        else:
            typer.echo(f"Created Skill Pack manifest: {manifest}")
        return

    try:
        pack = SkillPackManifest.load(manifest)
    except SkillForgeError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    builtin_reg = BuiltinRegistry()
    auditor = SkillAuditor()
    results: list[dict[str, Any]] = []
    all_passed = True

    for entry in pack.skills:
        pkg: SkillPackage | None = None
        if entry.source.startswith("builtin:") or entry.source == entry.name:
            b_name = entry.source.removeprefix("builtin:")
            try:
                pkg = builtin_reg.get_package(b_name)
            except SkillForgeError:
                pkg = None
        if pkg is None:
            local_cand = Path(entry.source)
            if not local_cand.is_absolute():
                local_cand = manifest.parent / entry.source
            if local_cand.exists():
                pkg = SkillPackage.load(local_cand)
        if pkg is None:
            results.append({"name": entry.name, "source": entry.source, "passed": False, "error": "Skill source not found locally/builtin"})
            all_passed = False
            continue

        rep = auditor.audit_package(pkg)
        passed = rep.passed and rep.score >= entry.min_score
        if not passed:
            all_passed = False
        installed_targets: list[str] = []
        if act == "install" and passed:
            from .adapters import UniversalAgentsAdapter

            adapters = detect_adapters(project) or [UniversalAgentsAdapter()]
            for adapter in adapters:
                adapter.install(pkg, project)
                installed_targets.append(adapter.__class__.__name__)
        results.append(
            {
                "name": entry.name,
                "source": entry.source,
                "score": rep.score,
                "min_score": entry.min_score,
                "passed": passed,
                "installed_targets": installed_targets,
            }
        )

    out = {"pack": pack.name, "action": act, "passed": all_passed, "skills": results}
    if json_output:
        typer.echo(json.dumps(out, indent=2))
    else:
        typer.echo(f"Skill Pack '{pack.name}' ({act}): {'PASSED' if all_passed else 'FAILED'}")
        for r in results:
            status = "PASS" if r.get("passed") else "FAIL"
            typer.echo(f"  [{status}] {r['name']} (score={r.get('score', 0)}/{r.get('min_score', 80)})")
    if not all_passed:
        raise typer.Exit(code=1)


@app.command("audit-a2a")
def audit_a2a_command(
    path: Path = typer.Argument(..., help="Path to A2A v1.0 /.well-known/agent-card.json file."),
    key_file: Path | None = typer.Option(None, "--key-file", help="Ed25519 public key PEM to cryptographically verify JWS signatures."),
    sign_key: Path | None = typer.Option(None, "--sign-key", help="Ed25519 private key PEM to sign the Agent Card in-place per A2A v1.0 §8.4."),
    strict: bool = typer.Option(False, "--strict", help="Fail on any warning or low-severity finding."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    """Audit or JWS-sign an Agent2Agent (A2A) v1.0 Agent Card JSON document."""
    from .a2a_audit import audit_agent_card, sign_agent_card_jws

    try:
        if sign_key is not None:
            card_obj = json.loads(path.read_text(encoding="utf-8"))
            priv_pem = sign_key.read_text(encoding="utf-8").strip()
            signed = sign_agent_card_jws(card_obj, priv_pem)
            path.write_text(json.dumps(signed, indent=2) + "\n", encoding="utf-8")
            if not json_output:
                typer.echo(f"Signed A2A Agent Card (EdDSA JWS) -> {path}")
        pub_pem = key_file.read_text(encoding="utf-8").strip() if key_file and key_file.is_file() else None
        report = audit_agent_card(path, public_key_pem=pub_pem)
    except (SkillForgeError, OSError, json.JSONDecodeError) as exc:
        if json_output:
            typer.echo(json.dumps({"passed": False, "error": str(exc)}))
        else:
            typer.echo(f"A2A audit error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if json_output:
        typer.echo(json.dumps(report.to_dict(), indent=2))
    else:
        typer.echo(report.render_text())

    if not report.passed or (strict and report.findings):
        raise typer.Exit(code=1)


@app.command("mcp-manifest")
def mcp_manifest_command(
    path: Path = typer.Argument(..., help="Path to skill directory or SKILL.md."),
    verify: Path | None = typer.Option(None, "--verify", help="Verify local skill files against an existing SEP-2640 manifest JSON."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write generated SEP-2640 manifest JSON to path."),
) -> None:
    """Generate or verify a SEP-2640 (io.modelcontextprotocol/skills) SHA-256 skill manifest."""
    from .mcp_skills_ext import build_skill_entry, package_file_bytes, verify_skill_manifest

    try:
        pkg = SkillPackage.load(path)
        if verify is not None:
            entry = json.loads(verify.read_text(encoding="utf-8"))
            raw_map = {
                f"skill://{pkg.skill.name}/{rel}": raw
                for rel, raw in package_file_bytes(pkg).items()
            }
            res = verify_skill_manifest(entry, raw_map)
            typer.echo(json.dumps(res.to_dict(), indent=2))
            if not res.valid:
                raise typer.Exit(code=1)
            return

        entry = build_skill_entry(pkg)
        rendered = json.dumps(entry, indent=2) + "\n"
        if output is not None:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(rendered, encoding="utf-8")
            typer.echo(f"Wrote SEP-2640 skill manifest -> {output}")
        else:
            typer.echo(rendered.rstrip())
    except (SkillForgeError, OSError, json.JSONDecodeError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc


if __name__ == "__main__":
    app()

