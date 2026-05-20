#!/usr/bin/env bash
set -euo pipefail

ruff check .
ruff format --check backend
mypy backend
pytest
bandit -r backend -x backend/tests
pip-audit --skip-editable --ignore-vuln PYSEC-2025-183
npm --prefix frontend run lint
npm --prefix frontend run typecheck
