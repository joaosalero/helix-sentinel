# Helix Sentinel

<p align="center">
  <strong>Production-oriented Security Analytics and Detection Engineering Platform</strong>
</p>

<p align="center">
  A modular-monolith SOC platform focused on operational visibility, persisted investigation workflows,
  detection engineering, threat enrichment, auditability, and deterministic security analytics.
</p>

---

## Overview

Helix Sentinel is a security-focused SOC operations platform built to demonstrate realistic Detection Engineering, security analytics, operational workflows, and observability patterns without introducing unnecessary distributed-system complexity.

The project intentionally prioritizes:

* deterministic operational workflows;
* typed backend engineering;
* security-first architecture;
* auditability and observability;
* modular domain boundaries;
* maintainable infrastructure;
* production-oriented backend design.

Unlike many showcase SIEM projects, Helix Sentinel deliberately avoids:

* realtime streaming pipelines;
* microservice fragmentation;
* SIEM query languages;
* artificial "AI-everywhere" abstractions;
* graph engines;
* governance/compliance platform scope.

The repository is designed as a realistic engineering portfolio project for:

* Detection Engineering;
* SOC Platform Engineering;
* Security Backend Engineering;
* AppSec-oriented backend development;
* DevSecOps workflows;
* operational observability;
* security analytics.

---

# Dashboard Review Path

The primary evaluator surface is the SOC operations dashboard. Start the backend
and frontend locally, then review the executive posture strip, operational brief,
detection coverage, security activity, open alert queue, and selected-alert
investigation detail.

Use `python3 scripts/seed-demo-events.py` when bounded synthetic ingestion context
is useful for screenshots or walkthroughs.

For screenshot and walkthrough guidance, see [docs/showcase.md](docs/showcase.md).

---

# Core Features

## SOC Operations Dashboard

* Executive posture overview
* Operational SOC KPIs
* Queue pressure visibility
* Alert age and assignment visibility
* Detection coverage summaries
* Threat and ATT&CK activity indicators
* Investigation readiness panels
* Audit-backed operational visibility

## Detection Engineering

* Persisted detection rules
* Rule execution workflows
* Alert lifecycle management
* Detection efficacy visibility
* Silent-rule tracking
* Analyst acknowledgement and closure workflows

## Threat Analytics

* IOC enrichment
* Threat summarization
* AI-assisted anomaly scoring
* Deterministic operational analytics
* Bounded investigation pivots

## Security Engineering

* Structured logging
* Correlation IDs
* RBAC-ready architecture
* Audit event persistence
* Secret scanning
* Dependency scanning
* Semgrep security validation
* Gitleaks integration
* CI security workflows

## Observability

* Prometheus metrics
* Grafana integration
* OpenTelemetry hooks
* Health/readiness endpoints
* Operational telemetry support

---

# Architecture

Helix Sentinel is intentionally implemented as a modular monolith.

The architecture focuses on:

* clear domain boundaries;
* deterministic persistence;
* operational simplicity;
* maintainability;
* lower infrastructure overhead;
* strong typing and validation;
* explicit security boundaries.

## Technology Stack

### Backend

* Python 3.12
* FastAPI
* SQLAlchemy 2.x
* PostgreSQL
* Redis
* Alembic
* Pydantic

### Frontend

* Next.js
* TypeScript
* TailwindCSS
* shadcn/ui

### Security and Quality

* Semgrep
* Gitleaks
* Dependabot
* Ruff
* MyPy
* Pytest
* Bandit
* GitHub Actions

### Observability

* Prometheus
* Grafana
* OpenTelemetry

---

# Repository Structure

```text
backend/        FastAPI modular monolith, domain modules, repositories, tests
frontend/       Next.js SOC dashboard and typed API integration
infra/          Security scanners, observability, Docker, Semgrep configuration
docs/           Architecture, operations, security, and development standards
scripts/        Bootstrap, validation, and helper scripts
.github/        CI workflows, templates, automation, and security pipelines
```

---

# Operational Workflow Demonstrated

The current implementation demonstrates a realistic SOC operational path:

1. Security posture overview
2. Alert queue triage
3. Investigation context review
4. Event pivot analysis
5. Alert acknowledgement or closure
6. Audit-backed activity tracking
7. Detection and operational reporting

The dashboard intentionally behaves like an operational workbench rather than a marketing-oriented UI.

---

# Quick Start

## Prerequisites

* Python 3.12
* Node.js 24 LTS
* Docker and Docker Compose
* Git

## 1. Clone Repository

```bash
git clone <repository-url>
cd helix-sentinel
```

## 2. Backend Setup

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade "pip>=26.1"
python -m pip install -e ".[dev,security]"
cp .env.example .env
```

## 3. Start Infrastructure

```bash
docker compose up -d postgres redis
```

## 4. Run Database Migrations

```bash
alembic -c backend/alembic.ini upgrade head
```

## 5. Start Backend API

```bash
uvicorn helix_sentinel.main:create_app --factory --app-dir backend --reload
```

## 6. Start Frontend

```bash
cd frontend
npm ci
npm run dev
```

---

# Local URLs

| Service       | URL                                                                      |
| ------------- | ------------------------------------------------------------------------ |
| Frontend      | [http://localhost:3000](http://localhost:3000)                           |
| API Readiness | [http://localhost:8000/api/v1/ready](http://localhost:8000/api/v1/ready) |
| API Metrics   | [http://localhost:8000/metrics](http://localhost:8000/metrics)           |
| Prometheus    | [http://localhost:9090](http://localhost:9090)                           |
| Grafana       | [http://localhost:3001](http://localhost:3001)                           |

---

# Environment Notes

The frontend communicates with the backend from server-side routes.

When using protected API endpoints, configure:

```bash
frontend/.env.local
```

With:

```env
HELIX_API_TOKEN=<token>
```

Never commit:

* `.env`
* `.env.local`
* secrets
* tokens
* production credentials
* tenant identifiers
* private telemetry

---

# Validation and Quality Gates

Run the repository validation suite:

```bash
scripts/check.sh
```

Or execute targeted validations:

```bash
make test
make lint
make typecheck
make security
make frontend-lint
make frontend-typecheck
make release-check
```

Frontend-only validation:

```bash
cd frontend
npm run lint
npm run typecheck
```

---

# Development Commands

## Runtime

```bash
make up
make down
```

`make up` starts:

* PostgreSQL
* Redis
* Prometheus
* OpenTelemetry Collector
* Grafana

The API intentionally runs outside Docker during development to simplify:

* reload behavior;
* debugger attachment;
* structured logging visibility;
* local troubleshooting.

---

# Security Posture

Helix Sentinel includes:

* structured security logging;
* audit event persistence;
* dependency scanning;
* secret scanning;
* CI validation;
* RBAC-ready foundations;
* secure repository defaults;
* deterministic operational workflows.

The repository intentionally excludes:

* offensive tooling;
* exploit frameworks;
* malware functionality;
* attack automation;
* credential harvesting;
* weaponized payloads.

## Security Tooling

| Tool       | Purpose                  |
| ---------- | ------------------------ |
| Semgrep    | Static security analysis |
| Gitleaks   | Secret scanning          |
| Bandit     | Python security linting  |
| Dependabot | Dependency monitoring    |
| Ruff       | Python linting           |
| MyPy       | Static typing validation |

Report vulnerabilities privately through the process documented in:

```text
SECURITY.md
```

---

# Documentation

## Public Documentation

* [Showcase Guide](docs/showcase.md)
* [Demo Data Guidance](docs/demo-data.md)
* [Release Readiness](docs/release-readiness.md)
* [Contribution Guide](CONTRIBUTING.md)
* [Security Policy](SECURITY.md)

## Architecture Documentation

* [Architecture Overview](docs/architecture/overview.md)
* [SOC Analytics](docs/architecture/soc-analytics.md)
* [Detection Engineering](docs/architecture/detection-engineering.md)
* [Authentication and RBAC](docs/security/authentication-rbac.md)
* [Observability](docs/operations/observability.md)

## Development Standards

* [Local Setup](docs/development/local-setup.md)
* [Repository Standards](docs/development/repository-standards.md)

---

# Testing Philosophy

Every feature addition must include:

* automated tests;
* validation updates;
* type safety maintenance;
* security validation when applicable.

Feature additions without corresponding test updates are intentionally rejected.

---

# Current Scope Boundaries

Helix Sentinel intentionally remains a focused operational security platform.

The current repository does not attempt to provide:

* enterprise SIEM scale;
* realtime distributed ingestion;
* multi-cluster orchestration;
* compliance governance tooling;
* advanced graph investigation;
* autonomous response systems;
* ML training pipelines;
* customer multi-org tenancy.

Those exclusions are intentional architectural decisions, not missing features.

---

# Ideal Evaluation Path

For recruiters, reviewers, or engineering evaluators:

1. Run the backend and frontend locally
2. Open the SOC dashboard
3. Review executive posture visibility
4. Select an alert from the operational queue
5. Inspect the investigation context
6. Review bounded event pivots
7. Acknowledge or close an alert
8. Inspect audit-backed activity visibility
9. Review the architecture documentation
10. Run `make release-check`

This path demonstrates:

* persisted operational workflows;
* deterministic backend analytics;
* typed backend engineering;
* auditability;
* security-first architecture;
* observability;
* operational SOC UX design.

---

# Contribution

Contributions should preserve:

* typed boundaries;
* deterministic workflows;
* operational realism;
* security posture;
* architectural simplicity.

Before contributing, review:

* `CONTRIBUTING.md`
* `SECURITY.md`
* repository validation requirements

---

# License

This project is released under the [MIT License](LICENSE).

---

# Final Notes

Helix Sentinel is intentionally designed as a realistic engineering-focused security platform rather than a tutorial project or marketing demo.

The emphasis of the repository is:

* operational clarity;
* maintainable backend architecture;
* security engineering maturity;
* observability;
* realistic SOC workflows;
* deterministic analytics;
* practical DevSecOps discipline.
