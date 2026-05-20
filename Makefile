.PHONY: install test lint format format-check typecheck security frontend-lint frontend-typecheck check release-check up down migrate

install:
	python -m pip install --upgrade "pip>=26.1"
	python -m pip install -e ".[dev,security]"

test:
	pytest

lint:
	ruff check .

format:
	ruff format backend

format-check:
	ruff format --check backend

typecheck:
	mypy backend

security:
	bandit -r backend -x backend/tests
	pip-audit --skip-editable --ignore-vuln PYSEC-2025-183

frontend-lint:
	npm --prefix frontend run lint

frontend-typecheck:
	npm --prefix frontend run typecheck

check: lint format-check typecheck test security frontend-lint frontend-typecheck

release-check: check

up:
	docker compose up -d postgres redis prometheus otel-collector grafana

down:
	docker compose down

migrate:
	alembic -c backend/alembic.ini upgrade head
