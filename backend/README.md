# Helix Sentinel Backend

The authoritative app factory is `helix_sentinel.main:create_app` in
`backend/helix_sentinel/main.py`. Active feature modules live in `backend/app`;
platform wiring and shared database metadata live in `backend/helix_sentinel`.

## Security Foundation

The authentication foundation lives under `backend/app` and provides:

- Argon2 password hashing and verification.
- JWT access tokens signed separately from refresh tokens.
- Refresh-token `jti` claims prepared for rotation and revocation storage.
- RBAC roles: `admin`, `analyst`, `engineer`, and `viewer`.
- Permission guards for route protection.
- Structured audit events for login, refresh, logout, user-state rejection, and permission denial.
- Security middleware for correlation IDs, safe request logging, and baseline security headers.

## Token Strategy

Access tokens are short lived. Protected routes validate the access token, reload the current user, and resolve permissions from the stored principal. Refresh tokens are longer lived, signed with a separate secret, and include a token identifier so persistent rotation can be added without changing the API contract. Current refresh does not invalidate the old token, and logout records intent without revoking issued tokens.

## Audit Logging

Audit events are structured for future SIEM ingestion. Audit metadata is sanitized before persistence and must never contain passwords, password hashes, bearer tokens, authorization headers, or raw credentials.

## Event Ingestion

The event ingestion foundation accepts single JSON security events at `POST /api/v1/events/ingest`. Requests are strictly validated, size-limited, stored as raw telemetry, normalized into query-friendly fields, audited, and counted through Prometheus metrics.

Use a bearer access token from an account with `events:ingest`. The handler authenticates before reading the event and validates the tenant before creating raw or normalized records.

Example:

```json
{
  "source": {"name": "edr", "product": "endpoint", "vendor": "Acme"},
  "tenant_id": "default",
  "payload": {
    "event": {"action": "process started"},
    "severity": "medium",
    "host": {"name": "endpoint-01"}
  }
}
```

Supported event categories are `authentication`, `authorization`, `network`, `endpoint`, `ioc`, `audit`, `system`, and `generic`. The normalizer uses conservative heuristics when clients do not provide a category or severity.

## SOC Analytics

SOC analytics endpoints are available under `/api/v1/analytics` and require the `analytics:read` permission. They expose dashboard-ready aggregations without returning raw event payloads:

- `GET /overview`
- `GET /severity`
- `GET /categories`
- `GET /trends`
- `GET /sources`
- `GET /report`: combined operational report.
- `GET /events`: bounded normalized-event search for investigation context.
- `GET /security-activity`: sanitized audit-backed activity (also requires `audit:read`).

Filters include `start_time`, `end_time`, `tenant_id`, `source`, `category`, `severity`, `bucket`, `limit`, and `offset`. The operational report combines event analytics with persisted alert workflow state. MTTA/MTTR and disposition-based rates depend on available acknowledgement, closure, and disposition data and can be null when there is no relevant evidence. They are not independently measured detection-accuracy benchmarks.

## Detection Engineering

Detection Engineering endpoints live under `/api/v1/detections` and use the existing RBAC model. Listing and detail retrieval require `detections:read`; Sigma imports require `detections:write`.

- `POST /rules/sigma`: validate and import a Sigma YAML rule.
- `GET /rules`: list rules with lifecycle, severity, category, tag, ATT&CK, limit, and offset filters.
- `GET /rules/{rule_id}`: return normalized rule metadata.

The import parser uses safe YAML loading, extracts lifecycle metadata, normalizes severity/category, and maps ATT&CK tags such as `attack.t1059.001`. Import does not execute a rule. A separate synchronous execution endpoint evaluates active rules against bounded normalized-event history and persists matched rule/event alerts.

- `POST /rules/{rule_id}/execute`: requires `detections:read` and `analytics:read`.
- `GET /coverage`: operational rule/alert coverage with the same read permissions.
- `GET /alerts` and `GET /alerts/{alert_id}`: tenant-scoped queues and detail, with the same read permissions.
- `PATCH /alerts/{alert_id}`: acknowledgement or closure, requiring `detections:read` and `audit:read`.

Execution supports a small Sigma-style selector subset, not the full Sigma condition language or SIEM query translation. See the [detection architecture](../docs/architecture/detection-engineering.md) and [synthetic walkthrough](../docs/demo-data.md#event-to-evidence-walkthrough).

## Threat Analytics

Threat Analytics endpoints live under `/api/v1/threats` and require `analytics:read`. They generate deterministic, explainable insights from normalized security events:

- `GET /insights`: filtered and paginated threat insights.
- `GET /summary`: dashboard-ready threat insight counts.

The initial correlations cover repeated authentication failures, suspicious IP reuse, IOC-related events, repeated endpoint anomalies, and short-window event bursts. Risk scoring is additive and transparent, using severity, frequency, suspicious repetition, IOC relationships, and ATT&CK metadata when present.

## AI-Assisted Analytics

AI-assisted analytics endpoints live under `/api/v1/ai` and require `analytics:read`. The implementation is deterministic and explainable; it does not call external AI providers or run opaque models.

- `GET /anomalies`: frequency, severity, burst, and suspicious-classification findings.
- `GET /enrichments`: keyword extraction, suspicious term detection, and lightweight classification metadata.
- `GET /summary`: dashboard-ready counts for anomaly and enrichment outputs.

Scores are additive and capped at 100. Every output includes factor-level explanations so analysts can understand why a finding or classification was produced.

## IOC Enrichment

IOC enrichment endpoints live under `/api/v1/enrichment`. IOC creation requires `detections:write`; listing, detail retrieval, summaries, and enrichment execution require `analytics:read`.

- `POST /iocs`: create a locally managed IP, domain, URL, or hash IOC.
- `GET /iocs`: list IOCs with type, severity, source, tag, confidence, limit, and offset filters.
- `GET /iocs/{ioc_id}`: return IOC metadata.
- `GET /summary`: return IOC inventory metrics.
- `POST /execute`: deterministically match stored normalized events against active IOCs.

Validation is syntax-only and local. The service never resolves domains, fetches URLs, calls reputation APIs, or performs outbound network requests. Enrichment confidence is deterministic and includes factor-level rationale based on IOC confidence, source reliability, severity, indicator type, recency, and match context.

## Local Authentication Wiring

The authoritative runtime installs PostgreSQL-backed user, audit, event, rule, alert, and IOC repositories in application state. In-memory adapters remain for isolated tests and explicit overrides; they are not the default production persistence path.

Protected routes resolve permissions and tenant scope from the authenticated principal. The current PostgreSQL user adapter assigns the `default` tenant. This does not establish complete customer multi-tenant isolation. Account provisioning and persistent refresh-token revocation remain prerequisites for deployment beyond a trusted local preview.
