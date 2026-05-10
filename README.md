# Helix Sentinel

Helix Sentinel is a production-oriented Security Analytics and Detection Engineering platform. It is designed as a modular monolith for SOC analytics, persisted alert workflow, investigation support, threat enrichment, validation workflows, and deterministic AI-assisted analysis without introducing premature distributed-system complexity.

## At a Glance

- **What it is:** a realistic SOC operations and security analytics application with persisted investigation workflows.
- **What to review first:** the Next.js SOC dashboard, the alert lifecycle APIs, analytics/reporting services, and the architecture docs.
- **What it avoids:** SIEM query languages, realtime streams, microservices, graph engines, and governance/compliance scope.
- **Best demo path:** posture overview -> open alert queue -> selected alert investigation -> acknowledgement or closure -> audit/security activity.
- **Release gate:** `make release-check` runs the full local validation suite used for publication readiness.

## Engineering Goals

- Security-first backend foundations with typed Python, FastAPI, SQLAlchemy 2.x, PostgreSQL, Redis, JWT-ready authentication, and auditability.
- Observability-first runtime with structured logs, correlation IDs, Prometheus-ready metrics, OpenTelemetry hooks, and health checks.
- Domain-oriented modular monolith boundaries for identity, events, detections, analytics, threat intelligence, validation, and audit logging.
- Operational SOC dashboard using Next.js, TypeScript, TailwindCSS, and shadcn/ui conventions.
- DevSecOps-ready repository with linting, typing, testing, dependency scanning, secret scanning, and CI workflow foundations.

## Repository Layout

```text
backend/        FastAPI modular monolith, domain modules, tests, Alembic
frontend/       Next.js SOC operations dashboard and typed API client
infra/          Local observability, security scanner, and Docker support files
docs/           Architecture, security, operations, and development standards
scripts/        Local bootstrap and validation helpers
.github/        CI, security workflows, and contribution templates
```

## Showcase Surfaces

The current public-facing experience centers on an operational SOC dashboard, not a marketing page. It demonstrates:

- Executive security posture, risk drivers, queue pressure, and consolidated SOC KPIs.
- Open alert queues with assignment, age, severity, and selected-alert investigation context.
- Analyst workflow actions for acknowledgement and closure with persisted investigation notes and dispositions.
- Contextual event timelines using bounded source/category pivots around the selected alert.
- Detection coverage, ATT&CK activity, silent active rules, and rule efficacy summaries.
- Audit-backed security activity, tenant-scope denial visibility, actor concentration, and recent audit trail visibility.
- Prometheus/Grafana-ready operational observability.

For a quick evaluator pass, start the API and frontend, open the dashboard, select an alert from the queue, review the context timeline and triage readiness block, then acknowledge or close the alert. That path exercises the persisted alert lifecycle, deterministic reporting layer, bounded investigation event retrieval, server-side API token handling, and audit-backed operational visibility without requiring a SIEM query language or realtime infrastructure. A concise reviewer path is available in [docs/showcase.md](docs/showcase.md).

## Local Setup

Prerequisites:

- Python 3.12
- Node.js 20+
- Docker and Docker Compose
- Git with SSH configured for GitHub

Bootstrap backend dependencies and local configuration:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade "pip>=26.1"
python -m pip install -e ".[dev,security]"
cp .env.example .env
```

Start infrastructure, apply migrations, and run the authoritative API:

```bash
docker compose up -d postgres redis
alembic -c backend/alembic.ini upgrade head
uvicorn helix_sentinel.main:create_app --factory --app-dir backend --reload
```

`helix_sentinel.main:create_app` is the authoritative backend runtime. It mounts health, metrics, authentication, event ingestion, Detection Engineering, SOC analytics, Threat Analytics, AI-assisted analytics, and IOC enrichment APIs under `HELIX_API_PREFIX` while exposing Prometheus metrics at `/metrics`.

`helix_sentinel.db.base.Base` is the authoritative SQLAlchemy metadata owner. Alembic targets `helix_sentinel.db.models.Base.metadata`, which registers the active feature persistence models used by `app.*`.

Authentication user lookups, audit event persistence, event ingestion persistence, detection rule persistence, and IOC enrichment persistence use PostgreSQL-backed repositories in the authoritative runtime. In-memory repositories are retained for isolated tests and explicit overrides.

The frontend runs separately and calls the API from the server side. Set `HELIX_API_TOKEN` in `frontend/.env.local` when using protected API routes.

```bash
cd frontend
npm install
npm run dev
```

Common local URLs:

- API readiness: `http://localhost:8000/api/v1/ready`
- API metrics: `http://localhost:8000/metrics`
- Frontend: `http://localhost:3000`
- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3001`

For the longer setup path, see [docs/development/local-setup.md](docs/development/local-setup.md).

## Validation

Run the same checks expected by the repository workflows:

```bash
scripts/check.sh
```

Or run targeted commands:

```bash
make test
make lint
make typecheck
make security
make frontend-lint
make frontend-typecheck
make release-check
```

Frontend-only checks:

```bash
cd frontend
npm run lint
npm run typecheck
```

## Development Commands

```bash
make test
make lint
make typecheck
make security
make frontend-lint
make frontend-typecheck
make up
make down
```

`make up` starts PostgreSQL, Redis, Prometheus, the OpenTelemetry collector, and Grafana. Run the API with Uvicorn from the local shell so reload, logs, and debugger attachment stay simple.

## Documentation Map

- [Public showcase guide](docs/showcase.md)
- [Public release readiness](docs/release-readiness.md)
- [Architecture overview](docs/architecture/overview.md)
- [Contribution guide](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [SOC analytics](docs/architecture/soc-analytics.md)
- [Detection engineering](docs/architecture/detection-engineering.md)
- [Authentication and RBAC](docs/security/authentication-rbac.md)
- [Observability](docs/operations/observability.md)
- [Repository standards](docs/development/repository-standards.md)

## Security Baseline

Helix Sentinel starts with defense-in-depth defaults: strict configuration validation, safe logging expectations, SQLAlchemy query construction, JWT-ready auth boundaries, RBAC-ready models, audit events, dependency scanning, and secret scanning. Offensive tooling and exploit functionality are intentionally out of scope.

Report vulnerabilities privately through the process in [SECURITY.md](SECURITY.md). Do not open public issues with exploit details, secrets, tokens, private tenant data, or proof-of-concept payloads.

## Testing Rule

Every future module, endpoint, service, analytics pipeline, worker, or domain behavior must include corresponding tests in the same change. Feature additions without test updates are not accepted.
