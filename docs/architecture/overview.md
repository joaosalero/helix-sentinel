# Architecture Overview

Helix Sentinel deploys as one FastAPI application with a separate Next.js
dashboard. PostgreSQL is the system of record; Redis and observability services
are configured as supporting infrastructure. The modular-monolith design keeps
deployment and debugging manageable for an independently developed project.

## Authoritative runtime and namespace ownership

| Location | Current responsibility |
| --- | --- |
| `backend/helix_sentinel/main.py` | App factory, repository installation, middleware, and feature-router composition |
| `backend/helix_sentinel/db/base.py` | Shared SQLAlchemy `Base` metadata owner |
| `backend/app/api/routes/` | Active HTTP feature endpoints |
| `backend/app/{auth,audit,events,detections,analytics,threats,ai,enrichment,users}/` | Active feature schemas, services, models, and repositories |
| `backend/helix_sentinel/{core,db,observability,security,services}/` | Platform/foundation modules and supporting integrations |
| `backend/helix_sentinel/domains/` | Existing foundation/domain modules; not a second independently wired feature runtime |
| `frontend/` | Server-rendered workbench, typed API contracts, and server-side bearer-token handling |

Both Python namespaces belong to the same deployment. New contributors should
trace imports from the app factory before editing a similarly named domain.
Namespace consolidation is not required for the present scope.

The app factory installs PostgreSQL-backed repositories for users, audit events,
ingested events, detection rules, detection alerts, and IOCs. In-memory adapters
are also available for isolated tests and explicit overrides. The app-state AI
event adapter is initialized in memory; this should not be described as a
separate durable AI pipeline.

## Event-to-evidence path

1. The ingestion route validates and normalizes a JSON event and persists it.
2. An authenticated user imports a rule and explicitly executes an active rule
   over a bounded normalized-event query.
3. Matches produce persisted, de-duplicated rule/event alert records.
4. The dashboard displays alert detail and contextual event pivots.
5. An authorized acknowledgement or closure updates workflow fields and records
   an audit event. Security activity summarizes sanitized audit metadata.

See [the synthetic walkthrough](../demo-data.md#event-to-evidence-walkthrough)
and [detection architecture](detection-engineering.md) for request contracts.
Audit-backed review is not a claim of a certified forensic evidence system.

## Trust boundaries

- Protected feature routes use explicit permission guards and principal-based
  tenant scoping. The PostgreSQL user adapter currently maps users to
  `default`; full customer multi-organization tenancy is not implemented.
- Ingestion requires the `events:ingest` permission and resolves the submitted tenant against the authenticated principal before any event writes.
- The dashboard keeps its API token server-side. This does not replace API
  authorization or make arbitrary deployments safe.
- JWT refresh reissues tokens without persistent single-use/revocation state;
  logout records intent. Existing tokens remain valid until expiry.
- Sigma import uses safe YAML parsing. The bounded evaluator implements a small
  selector subset, not complete Sigma semantics or arbitrary rule execution.
- Deterministic analytics and local IOC matching require no outbound reputation
  calls or external model provider. Private integrations are optional and must
  remain outside public source and examples.

## Deliberate scope

The current workbench does not implement distributed streaming ingestion,
microservices, SIEM query translation, graph investigations, autonomous response,
or model training. Future work should be driven by verified requirements rather
than by adding infrastructure to the portfolio.
