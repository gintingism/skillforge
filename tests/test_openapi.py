import json
from pathlib import Path

from typer.testing import CliRunner

from skillforge.cli import app
from skillforge.openapi import import_openapi
from skillforge.security import SkillAuditor

runner = CliRunner()


def test_import_openapi_json(tmp_path: Path) -> None:
    spec_data = {
        "openapi": "3.0.0",
        "info": {
            "title": "Petstore Store",
            "version": "1.2.0",
            "description": "Sample Petstore API for agents",
        },
        "servers": [{"url": "https://api.petstore.com/v1"}],
        "paths": {
            "/pets": {
                "get": {
                    "summary": "List all pets",
                    "operationId": "listPets",
                    "parameters": [
                        {"name": "limit", "in": "query", "required": False}
                    ],
                    "responses": {"200": {"description": "A paged array of pets"}},
                },
                "post": {
                    "summary": "Create a pet",
                    "operationId": "createPet",
                    "responses": {"201": {"description": "Null response"}},
                },
            }
        },
    }
    spec_file = tmp_path / "openapi.json"
    spec_file.write_text(json.dumps(spec_data), encoding="utf-8")

    out_dir = tmp_path / "skills"
    pkg = import_openapi(spec_file, out_dir)

    assert pkg.skill.name == "petstore-store"
    assert "endpoints.md" in pkg.references
    assert "/pets" in pkg.skill.body
    assert (out_dir / "petstore-store" / "SKILL.md").exists()
    assert (out_dir / "petstore-store" / "references" / "endpoints.md").exists()

    # Verify that the generated skill passes security & progressive disclosure audits
    report = SkillAuditor().audit_package(pkg)
    assert report.passed is True


def test_cli_import_openapi_command(tmp_path: Path) -> None:
    yaml_content = """
swagger: "2.0"
info:
  title: "Payment Gateway"
  version: "2.0.0"
host: "api.payments.com"
basePath: "/v2"
paths:
  /charges:
    post:
      summary: "Create a charge"
      operationId: "chargeCard"
      responses:
        200:
          description: "Charge successful"
"""
    spec_file = tmp_path / "swagger.yaml"
    spec_file.write_text(yaml_content, encoding="utf-8")

    out_dir = tmp_path / "imported"
    res = runner.invoke(app, ["import-openapi", str(spec_file), "-o", str(out_dir), "--name", "payments-api"])
    assert res.exit_code == 0
    assert "Successfully imported 'payments-api'" in res.output
    assert (out_dir / "payments-api" / "SKILL.md").exists()
    assert (out_dir / "payments-api" / "references" / "endpoints.md").exists()
