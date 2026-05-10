#!/usr/bin/env bash
set -euo pipefail

ruff check .
ruff format --check backend
mypy backend
pytest
bandit -r backend -x backend/tests
pip-audit --skip-editable
npm --prefix frontend run lint
npm --prefix frontend run typecheck
