#!/usr/bin/env bash
set -euo pipefail

python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev,security]"
cp -n .env.example .env

echo "Development environment bootstrapped. Start services with: docker compose up -d postgres redis"

