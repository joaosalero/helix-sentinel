#!/usr/bin/env bash
set -euo pipefail

ruff check backend
ruff format --check backend
mypy backend
pytest

