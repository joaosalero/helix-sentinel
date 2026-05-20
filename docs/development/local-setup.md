# Local Development Setup

## Backend

1. Create and activate a Python 3.12 virtual environment.
2. Upgrade installer tooling with `python -m pip install --upgrade "pip>=26.1"`, then install backend dependencies with `python -m pip install -e ".[dev,security]"`.
3. Copy `.env.example` to `.env` and rotate `HELIX_SECRET_KEY`, `HELIX_AUTH_SECRET_KEY`, and `HELIX_AUTH_REFRESH_SECRET_KEY` outside local development.
4. Start PostgreSQL and Redis with `docker compose up -d postgres redis`.
5. Apply migrations with `alembic -c backend/alembic.ini upgrade head`.
6. Start the authoritative API runtime with `uvicorn helix_sentinel.main:create_app --factory --app-dir backend --reload`.

The runtime mounts product APIs under `/api/v1` and exposes Prometheus metrics at `/metrics`.

PyCharm should use `.venv` as the project interpreter and `backend` as an additional source root.

## Frontend

The SOC dashboard is a separate Next.js app:

```bash
cd frontend
npm ci
npm run dev
```

Use `HELIX_API_BASE_URL` to point the dashboard at a non-default API URL. Use `HELIX_API_TOKEN` in `frontend/.env.local` when calling protected API routes from the server-rendered dashboard.

## Observability

Start the local observability stack with:

```bash
make up
```

This starts PostgreSQL, Redis, Prometheus, the OpenTelemetry collector, and Grafana. The API still runs from the host shell with Uvicorn. Grafana is available at `http://localhost:3001`; Prometheus is available at `http://localhost:9090`.

## Operational Smoke Check

After migrations and startup, verify `/api/v1/ready`, `/metrics`, and the SOC dashboard. Prometheus will show the API target as down until the host-run Uvicorn process is listening on `localhost:8000`.

## Validation

Run repository checks with:

```bash
scripts/check.sh
```

For focused work, use `make test`, `make lint`, `make typecheck`, `make security`, `make frontend-lint`, and `make frontend-typecheck`. Before publication or sharing a demo branch, use `make release-check`.

## Git Workflow

Use feature branches and keep changes small enough to review. All new behavior must include tests. Security-sensitive changes should include clear notes in the PR description explaining validation and logging expectations.
