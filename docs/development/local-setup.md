# Local Development Setup

1. Create and activate a Python 3.12 virtual environment.
2. Install backend dependencies with `python -m pip install -e ".[dev,security]"`.
3. Copy `.env.example` to `.env` and rotate `HELIX_SECRET_KEY` for non-local environments.
4. Start PostgreSQL and Redis with `docker compose up -d postgres redis`.
5. Apply migrations with `alembic -c backend/alembic.ini upgrade head`.
6. Start the API with `uvicorn helix_sentinel.main:create_app --factory --app-dir backend --reload`.

PyCharm should use `.venv` as the project interpreter and `backend` as an additional source root.

## Git Workflow

Use feature branches and keep changes small enough to review. All new behavior must include tests. Security-sensitive changes should include clear notes in the PR description explaining validation and logging expectations.

