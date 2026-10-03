from pathlib import Path

from typer.testing import CliRunner

from skillforge.cli import app
from skillforge.registry import LocalRegistry
from skillforge.skill import Skill

runner = CliRunner()


def test_create_validate_and_pack_commands(tmp_path: Path) -> None:
    created = tmp_path / "created"
    result = runner.invoke(
        app,
        ["create", "demo", "--description", "A demo", "--directory", str(created)],
    )
    assert result.exit_code == 0, result.output
    skill_path = created / "SKILL.md"
    assert skill_path.exists()

    result = runner.invoke(app, ["validate", str(skill_path)])
    assert result.exit_code == 0, result.output

    archive = tmp_path / "demo.zip"
    result = runner.invoke(app, ["pack", str(skill_path), "--output", str(archive)])
    assert result.exit_code == 0, result.output
    assert archive.exists()


def test_cli_validate_and_pack_report_errors(tmp_path: Path) -> None:
    missing = tmp_path / "missing.md"
    result = runner.invoke(app, ["validate", str(missing)])
    assert result.exit_code == 1
    assert "Unable to read" in result.output

    result = runner.invoke(app, ["pack", str(missing), "--output", str(tmp_path / "out.zip")])
    assert result.exit_code == 1


def test_cli_create_rejects_unsafe_name(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["create", "../escape", "--description", "bad", "--directory", str(tmp_path)],
    )
    assert result.exit_code == 1
    assert "safe" in result.output


def test_cli_search_and_install(tmp_path: Path) -> None:
    registry_path = tmp_path / "registry"
    registry = LocalRegistry(registry_path)
    registry.publish(Skill("demo", "A demo skill", "Body\n"))

    result = runner.invoke(app, ["search", "demo", "--registry", str(registry_path)])
    assert result.exit_code == 0
    assert "demo\tA demo skill" in result.output

    project = tmp_path / "project"
    (project / ".github").mkdir(parents=True)
    (project / ".claude").mkdir()
    result = runner.invoke(
        app,
        ["install", "demo", "--registry", str(registry_path), "--project", str(project)],
    )
    assert result.exit_code == 0, result.output
    assert (project / ".github" / "copilot-instructions.md").exists()
    assert (project / ".claude" / "skills" / "demo" / "SKILL.md").exists()


def test_cli_install_without_detected_target_fails(tmp_path: Path) -> None:
    registry_path = tmp_path / "registry"
    LocalRegistry(registry_path).publish(Skill("demo", "A demo", "Body\n"))
    result = runner.invoke(
        app,
        ["install", "demo", "--registry", str(registry_path), "--project", str(tmp_path / "project")],
    )
    assert result.exit_code == 1
    assert "No supported assistant target" in result.output
