# Helix Sentinel

Helix Sentinel is a production-oriented Security Analytics and Detection Engineering platform scaffold. It is designed as a modular monolith for SOC analytics, detection lifecycle management, threat enrichment, validation workflows, and AI-assisted analysis without introducing premature distributed-system complexity.

## Engineering Goals

- Security-first backend foundations with typed Python, FastAPI, SQLAlchemy 2.x, PostgreSQL, Redis, JWT-ready authentication, and auditability.
- Observability-first runtime with structured logs, correlation IDs, Prometheus-ready metrics, OpenTelemetry hooks, and health checks.
- Domain-oriented modular monolith boundaries for identity, events, detections, analytics, threat intelligence, validation, and audit logging.
- Frontend architecture prepared for a professional enterprise SaaS experience using Next.js, TypeScript, TailwindCSS, and shadcn/ui conventions.
- DevSecOps-ready repository with linting, typing, testing, dependency scanning, secret scanning, and CI workflow foundations.

## Repository Layout

```text
backend/        FastAPI modular monolith, domain modules, tests, Alembic
frontend/       Next.js architecture scaffold and design-system foundations
infra/          Local observability, security scanner, and Docker support files
docs/           Architecture, security, operations, and development standards
scripts/        Local bootstrap and validation helpers
.github/        CI, security workflows, and contribution templates
```

## Local Setup

Prerequisites:

- Python 3.12
- Node.js 20+
- Docker and Docker Compose
- Git with SSH configured for GitHub

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev,security]"
cp .env.example .env
docker compose up -d postgres redis
alembic -c backend/alembic.ini upgrade head
uvicorn helix_sentinel.main:create_app --factory --app-dir backend --reload
```

`helix_sentinel.main:create_app` is the authoritative backend runtime. It mounts health, metrics, authentication, event ingestion, Detection Engineering, SOC analytics, Threat Analytics, AI-assisted analytics, and IOC enrichment APIs under `HELIX_API_PREFIX` while exposing Prometheus metrics at `/metrics`.

`helix_sentinel.db.base.Base` is the authoritative SQLAlchemy metadata owner. Alembic targets `helix_sentinel.db.models.Base.metadata`, which registers the active feature persistence models used by `app.*`.

Authentication user lookups, audit event persistence, event ingestion persistence, detection rule persistence, and IOC enrichment persistence use PostgreSQL-backed repositories in the authoritative runtime. In-memory repositories are retained for isolated tests and explicit overrides.

Frontend dependencies are intentionally separate:

```bash
cd frontend
npm install
npm run typecheck
```

## Development Commands

```bash
make test
make lint
make typecheck
make security
make up
make down
```

Local observability endpoints after `make up`:

- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3001`
- API metrics: `http://localhost:8000/metrics`
- API readiness: `http://localhost:8000/api/v1/ready`
- OpenTelemetry OTLP: `localhost:4317` for gRPC, `localhost:4318` for HTTP

Required backend validation before completing changes:

```bash
pytest
ruff check .
mypy backend
bandit -r backend -x backend/tests
```

## Security Baseline

Helix Sentinel starts with defense-in-depth defaults: strict configuration validation, safe logging expectations, SQLAlchemy query construction, JWT-ready auth boundaries, RBAC-ready models, audit events, dependency scanning, secret scanning, and security middleware placeholders. Offensive tooling and exploit functionality are intentionally out of scope.

## Testing Rule

Every future module, endpoint, service, analytics pipeline, worker, or domain behavior must include corresponding tests in the same change. Feature additions without test updates are not accepted.
