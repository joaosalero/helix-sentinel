# SOC Analytics Architecture

Helix Sentinel's SOC analytics layer aggregates normalized security events into operational metrics for dashboards and reporting. It is intentionally built as a modular monolith component over PostgreSQL-ready normalized event records, not as a separate analytics engine.

## Metrics

The initial analytics service calculates:

- Total events.
- Severity distribution.
- Category distribution.
- Event volume trends.
- Authentication failure trends.
- Event source metrics.
- Operational KPI preparation fields.

The API does not expose raw event payloads. Aggregations operate on normalized fields such as tenant, source, category, severity, and event time.

## APIs

Analytics endpoints live under `/api/v1/analytics` and require `analytics:read`.

- `/overview`: dashboard-ready summary with distributions, trends, source metrics, and KPI fields.
- `/severity`: severity count and percentage summary.
- `/categories`: category count and percentage summary.
- `/trends`: event volume by hour or day.
- `/sources`: paginated source metrics.

## Filtering

Filters are validated through a dedicated schema. Supported filters are time range, tenant, source, category, severity, trend bucket, limit, and offset. Time ranges are capped at 366 days to keep queries operationally predictable.

## KPI Rationale

High-severity ratio, authentication failure ratio, and events per source are calculated from normalized events. MTTA, MTTR, true-positive rate, false-positive rate, and alert volume are nullable until alert and incident lifecycle data exists. This avoids inventing operational metrics before the platform has the required source data.

## Query Strategy

Database-backed analytics should use the existing normalized event indexes:

- tenant and event time
- category and event time
- severity and event time
- source and event time

JSONB fields remain available for targeted actor, asset, and enrichment filtering, but the first analytics APIs intentionally avoid expensive payload-level aggregations.

## Observability

Analytics endpoints emit request counters and query latency histograms. Service logs include correlation IDs, total event counts, and elapsed time without logging raw event data or sensitive payload fields.

