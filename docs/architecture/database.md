# Database Foundation

`helix_sentinel.db.base.Base` is the authoritative SQLAlchemy declarative base.
Alembic targets `helix_sentinel.db.models.Base.metadata`, which imports both
platform scaffold models and the active `app.*` feature persistence models.

The initial PostgreSQL model supports:

- RBAC and user identity.
- Append-oriented audit events.
- Normalized security events with JSONB raw and normalized payloads.
- Detection rules and validation test cases.
- Analytics pipelines and AI enrichment metadata.
- Threat indicators and enrichment context.
- Security validation runs.
- Raw and normalized security event ingestion tables.

Indexes prioritize realistic SOC access patterns: tenant and event time scans, source and event type filtering, JSONB payload search, audit resource lookup, detection lifecycle filtering, and enrichment entity lookup.

Event ingestion uses separate raw and normalized tables. Raw JSONB payloads preserve source telemetry for auditability and reprocessing. Normalized rows expose query-friendly category, severity, source, tenant, and timestamp columns for analytics and detection workflows.

SOC analytics queries should aggregate from normalized event columns first. JSONB lookups are reserved for targeted actor, asset, and enrichment filters where scalar columns are not sufficient.

Detection Engineering stores normalized rule metadata separately from ATT&CK mappings. Rule indexes support lifecycle, severity, category, update-time, and tag filtering. ATT&CK mapping indexes support technique and tactic coverage queries.

Threat Analytics prepares persisted insight and IOC reference tables for future historical analysis. Indexes support insight type/time, risk/time, temporal windows, IOC type/value filtering, and metadata JSONB search.

AI-assisted analytics prepares anomaly finding and event enrichment tables. Indexes support anomaly type/time, score/time, temporal windows, event lookup, classification filtering, and explainability metadata search.

IOC enrichment stores managed indicators separately from event-to-IOC matches. Indicator indexes support type, confidence, source, seen-time, expiration, tag, and metadata filtering. Match indexes support event lookup, IOC lookup, confidence filtering, status filtering, and future enrichment analytics.
