# Helix Sentinel

**Security analytics and detection engineering in a modular SOC workbench.**

Helix Sentinel is an independently developed FastAPI and Next.js project for
reviewing security events, running bounded detections, investigating persisted
alerts, and following the resulting audit trail. The current development preview
demonstrates deterministic workflows and explicit repository boundaries; it is
not a production-ready SIEM or a complete multi-tenant security boundary.

## At a glance

| Area | Implemented behavior | Evidence |
| --- | --- | --- |
| Event ingestion | Single JSON events, validation, normalization, PostgreSQL persistence | [Ingestion](docs/architecture/event-ingestion.md) |
| Detection engineering | Sigma metadata import, active-rule evaluation over bounded event history, persisted rule/event alerts | [Detections](docs/architecture/detection-engineering.md) |
| Investigation | Tenant-scoped alert queries, acknowledgement, closure, disposition, and investigation notes | [API routes](backend/app/api/routes/detections.py) |
| Analytics | Event summaries, alert workflow metrics, ATT&CK mappings, deterministic threat and anomaly scores | [SOC analytics](docs/architecture/soc-analytics.md) |
| Identity and audit | Argon2, separately signed access/refresh JWTs, permission guards, PostgreSQL-backed users and audit events | [Authentication](docs/security/authentication-rbac.md) |
| Interface | Server-rendered SOC dashboard with a typed API client and server-side bearer-token handling | [Dashboard](frontend/features/soc-dashboard/soc-dashboard.tsx) |
| Operations | Readiness checks, Prometheus metrics, Grafana provisioning, OpenTelemetry hooks, CI quality/security checks | [Observability](docs/operations/observability.md) |

"AI-assisted" analytics refers to explainable deterministic heuristics. The
implemented analytics do not require an external model provider or a training
pipeline.

## Review one complete workflow

1. Start the API and dashboard using the setup below.
2. Use an already provisioned local account with the required permissions.
3. Seed synthetic events, import a small active rule, and execute it over the
   `default` tenant.
4. Select its alert, inspect the related event context, acknowledge it, and close
   it with a synthetic investigation note.
5. Review the persisted alert and audit-backed security activity.

The [synthetic walkthrough](docs/demo-data.md#event-to-evidence-walkthrough)
provides the request bodies and expected observations.
[Investigation case study](docs/showcase.md) links the replay, its assertions and its operating limits.

## Architecture and engineering decisions

The application deploys as a **modular monolith** with PostgreSQL as the system
of record. Its authoritative entry point is
[`helix_sentinel.main:create_app`](backend/helix_sentinel/main.py).

| Location | Responsibility |
| --- | --- |
| `backend/app/` | Active feature services, HTTP routes, schemas, repositories, and security dependencies |
| `backend/helix_sentinel/` | Application factory, platform configuration, database foundation, observability, and supporting modules |
| `frontend/` | Next.js / TypeScript dashboard and server-side API integration |
| `infra/` | Security tooling and local observability configuration |
| `docs/` | Architecture, development, operations, and security documentation |

The shared SQLAlchemy metadata owner is `helix_sentinel.db.base.Base`.
The existing namespace split is intentional for this iteration; it does not
represent two independently deployed backends.
See the [architecture overview](docs/architecture/overview.md).

Rule execution is synchronous and bounded by tenant, time range, source, and
event count. The current evaluator supports a limited set of normalized-field
selectors; it does **not** implement the full Sigma condition language or
translate rules into a SIEM query language.

## Local setup

The commands below target Linux/WSL with Python 3.12, Node.js 24, Git, Docker,
and Docker Compose. Run the API and frontend in separate terminals.

```bash
git clone https://github.com/joaosalero/helix-sentinel.git
cd helix-sentinel
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade "pip>=26.1"
python -m pip install -e ".[dev,security]"
cp .env.example .env
docker compose up -d postgres redis
alembic -c backend/alembic.ini upgrade head
uvicorn helix_sentinel.main:create_app --factory --app-dir backend --reload
```

In a second terminal, from the repository root:

```bash
cd frontend
npm ci
npm run dev
```

The dashboard calls protected API routes from the server. Configure
`HELIX_API_TOKEN` in the ignored `frontend/.env.local` using a valid token from
your local account. Migrations create the schema; the quick start does not
automatically provision a user or issue a working dashboard token. Do not treat
an empty or unauthorized dashboard as a populated demo.

| Surface | Local URL |
| --- | --- |
| Dashboard | [http://localhost:3000](http://localhost:3000) |
| Interactive API documentation (local mode) | [http://localhost:8000/docs](http://localhost:8000/docs) |
| Readiness | [http://localhost:8000/api/v1/ready](http://localhost:8000/api/v1/ready) |
| Metrics | [http://localhost:8000/metrics](http://localhost:8000/metrics) |
| Prometheus, after `make up` | [http://localhost:9090](http://localhost:9090) |
| Grafana, after `make up` | [http://localhost:3001](http://localhost:3001) |

[Local setup](docs/development/local-setup.md) explains environment configuration
and observability startup. Rotate all development signing secrets before any
non-local deployment and keep local configuration out of version control.

## Security boundaries and current limitations

- **Event ingestion:** `POST /api/v1/events/ingest` requires an active bearer
  principal with `events:ingest`. An omitted tenant inherits the account scope.
  The shared tenant guard checks explicit tenant values before persistence.
- **Session lifecycle:** refresh reissues JWTs but does not persist single-use
  token consumption or revocation. Logout records an audit event; existing
  tokens remain valid until expiry.
- **Tenant scope:** protected query routes enforce principal-based scope, but the
  current PostgreSQL user adapter assigns the `default` tenant. This is not
  complete customer multi-organization tenancy.
- **Detection semantics:** safe YAML parsing prevents object construction, but it
  does not establish full Sigma compatibility. Use simple supported selectors;
  validate results against known synthetic events before trusting a rule.
- **Evidence:** audit-backed activity and persisted investigation state support
  review; the project does not claim forensic chain-of-custody certification.
- **Deployment:** production hardening, trusted account provisioning, ingress
  controls, session revocation, and deployment-specific validation remain
  necessary. The project does not claim enterprise SIEM scale, autonomous
  response, streaming ingestion, or compliance certification.

Use synthetic data for demonstrations. Never commit tokens, private tenant
identifiers, customer telemetry, local endpoints, or screenshots containing
sensitive operational data. Report vulnerabilities through
[`SECURITY.md`](SECURITY.md).

## Validation

Run the existing gates from the repository root in a prepared development
environment:

```bash
make test
make lint
make format-check
make typecheck
make security
make frontend-lint
make frontend-typecheck
```

`make check`, `make release-check`, and `scripts/check.sh` aggregate the
repository checks. Frontend CI additionally builds the application and audits
dependencies. The configured checks are not a claim that every environment or
future commit passes; retain the actual output for the revision being reviewed.

## Documentation

- [Architecture and runtime boundaries](docs/architecture/overview.md)
- [Backend API capabilities](backend/README.md)
- [Authentication and RBAC](docs/security/authentication-rbac.md)
- [Detection execution and investigation](docs/architecture/detection-engineering.md)
- [Synthetic event-to-evidence walkthrough](docs/demo-data.md)
- [Release readiness](docs/release-readiness.md)
- [Contributing](CONTRIBUTING.md)

Released under the [MIT License](LICENSE).
