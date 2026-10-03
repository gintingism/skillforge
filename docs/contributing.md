# Contributing

## Setup

```powershell
python -m pip install -e ".[dev,docs]"
```

## Checks

Run checks before opening a pull request:

```powershell
python -m pytest --cov=skillforge --cov-report=term-missing
python -m mypy src
python -m build
mkdocs build --strict
```

Keep changes focused. Add tests for behavior changes. Keep MCP stdout reserved for protocol traffic.
