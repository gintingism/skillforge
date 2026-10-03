from pathlib import Path

import pytest

from skillforge.errors import SkillValidationError
from skillforge.errors import SkillParseError
from skillforge.skill import Skill, parse_skill


def test_parse_skill_frontmatter_and_body() -> None:
    skill = parse_skill(
        "---\nname: hello-world\ndescription: Say hello\n---\n\n# Hello\n"
    )
    assert skill.name == "hello-world"
    assert skill.description == "Say hello"
    assert skill.body == "# Hello\n"


def test_parse_skill_requires_name_and_description() -> None:
    with pytest.raises(SkillValidationError, match="name"):
        parse_skill("---\ndescription: missing name\n---\nBody")


def test_skill_rejects_path_traversal_name() -> None:
    with pytest.raises(SkillValidationError, match="safe"):
        Skill(name="../escape", description="bad", body="")


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ("name: demo\n", "begin"),
        ("---\nname: demo\n", "closed"),
        ("---\n- item\n---\nBody", "mapping"),
        ("---\n: invalid: yaml\n---\nBody", "YAML"),
    ],
)
def test_parse_skill_rejects_malformed_documents(document: str, message: str) -> None:
    error_type = SkillParseError if message in {"begin", "closed", "YAML"} else SkillValidationError
    with pytest.raises(error_type, match=message):
        parse_skill(document)


@pytest.mark.parametrize(
    ("name", "description"),
    [
        ("", "desc"),
        ("demo", ""),
        ("UPPER", "desc"),
    ],
)
def test_skill_rejects_invalid_metadata(name: str, description: str) -> None:
    with pytest.raises(SkillValidationError):
        Skill(name=name, description=description, body="")


def test_load_reports_missing_file(tmp_path: Path) -> None:
    with pytest.raises(SkillParseError, match="Unable to read"):
        Skill.load(tmp_path / "missing.md")


def test_load_and_render_skill(tmp_path: Path) -> None:
    path = tmp_path / "SKILL.md"
    path.write_text("---\nname: demo\ndescription: Demo\n---\n\nBody\n", encoding="utf-8")
    skill = Skill.load(path)
    assert skill.render() == path.read_text(encoding="utf-8")
