#!/usr/bin/env bash
set -euo pipefail

python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade "pip>=26.1"
python -m pip install -e ".[dev,security]"
cp -n .env.example .env

echo "Development environment bootstrapped."
echo "Next: docker compose up -d postgres redis"
echo "Then: alembic -c backend/alembic.ini upgrade head"
echo "API: uvicorn helix_sentinel.main:create_app --factory --app-dir backend --reload"
echo "Frontend: cd frontend && npm install && npm run dev"
