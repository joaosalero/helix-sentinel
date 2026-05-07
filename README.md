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

## Security Baseline

Helix Sentinel starts with defense-in-depth defaults: strict configuration validation, safe logging expectations, SQLAlchemy query construction, JWT-ready auth boundaries, RBAC-ready models, audit events, dependency scanning, secret scanning, and security middleware placeholders. Offensive tooling and exploit functionality are intentionally out of scope.

## Testing Rule

Every future module, endpoint, service, analytics pipeline, worker, or domain behavior must include corresponding tests in the same change. Feature additions without test updates are not accepted.

