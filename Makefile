.PHONY: install test lint format typecheck security up down migrate

install:
	python -m pip install -e ".[dev,security]"

test:
	pytest

lint:
	ruff check backend

format:
	ruff format backend

typecheck:
	mypy backend

security:
	bandit -c pyproject.toml -r backend/helix_sentinel
	pip-audit

up:
	docker compose up -d postgres redis prometheus grafana

down:
	docker compose down

migrate:
	alembic -c backend/alembic.ini upgrade head

