## Project Overview

-   Python package with `src` layout
-   Package name: `bwssh`
-   Uses `uv` for envs/deps

## Dev Commands

-   Install/sync deps: `uv sync`
-   Run app: `uv run bwssh`
-   Lint: `uv run ruff check .`
-   Format: `uv run ruff format .`
-   Type check: `uv run mypy src tests`
-   Tests: `uv run pytest`

## Notes

-   Type hints are exported via `src/bwssh/py.typed`
-   Ruff config lives in `pyproject.toml`
