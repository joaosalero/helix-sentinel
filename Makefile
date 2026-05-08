.PHONY: install test lint format typecheck security up down migrate

install:
	python -m pip install -e ".[dev,security]"

test:
	pytest

lint:
	ruff check .

format:
	ruff format backend

typecheck:
	mypy backend

security:
	bandit -r backend -x backend/tests
	pip-audit

up:
	docker compose up -d postgres redis prometheus grafana

down:
	docker compose down

migrate:
	alembic -c backend/alembic.ini upgrade head
