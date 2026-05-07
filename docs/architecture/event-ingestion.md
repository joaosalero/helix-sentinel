# Event Ingestion Architecture

Helix Sentinel ingests one JSON security event per API request. The first implementation deliberately avoids Kafka, stream processing, and external SIEM integrations. The goal is a maintainable foundation that supports future analytics and Detection Engineering without committing to distributed ingestion too early.

## Flow

1. The API receives `POST /api/v1/events/ingest`.
2. The request body is size-checked before JSON parsing.
3. JSON is decoded with the standard library and validated by strict Pydantic schemas.
4. The raw event is stored for traceability and future re-normalization.
5. The normalizer emits a query-friendly normalized event.
6. Audit and metric events are emitted for operational visibility.

## Normalization

The normalized schema captures source metadata, category, severity, timestamps, actor fields, asset fields, network metadata, IOC metadata, enrichment status, and a normalization version. Raw payloads remain available separately so future normalization improvements do not destroy original telemetry.

Categories are intentionally small: `authentication`, `authorization`, `network`, `endpoint`, `ioc`, `audit`, `system`, and `generic`.

## Validation Boundary

Payloads must be JSON objects. Empty payloads, unknown top-level request fields, excessive nesting, excessive arrays, excessive top-level keys, and oversized strings are rejected. The endpoint does not perform unsafe deserialization or dynamic parsing.

## Database Strategy

PostgreSQL stores raw and normalized events in separate tables. Raw events use JSONB for source payload retention. Normalized events use indexed scalar columns for common filters and JSONB fields for actor, asset, enrichment, network, and IOC metadata. Indexes prioritize tenant/time, category/time, severity/time, source/time, and targeted JSONB lookups.

## Observability

Ingestion emits audit events for accepted and rejected events. Prometheus counters track accepted events by category and severity, and rejected events by reason. All ingestion responses carry the correlation ID from middleware.

