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
- `/events`: bounded normalized event retrieval for analyst investigations.

## Filtering

Filters are validated through dedicated schemas. Aggregation filters support time range, tenant, source, category, severity, trend bucket, limit, and offset. Normalized event retrieval adds source product/vendor, title contains, actor username/email/IP, asset hostname/IP, and IOC value filters. Aggregation time ranges are capped at 366 days; event search is capped at 90 days and returns newest events first.

## KPI Rationale

High-severity ratio, authentication failure ratio, and events per source are calculated from normalized events. MTTA, MTTR, true-positive rate, false-positive rate, and alert volume are nullable until alert and incident lifecycle data exists. This avoids inventing operational metrics before the platform has the required source data.

## Query Strategy

Database-backed analytics uses SQL aggregation over normalized event records for totals, distributions, trends, authentication failure trends, and source metrics. Queries use the existing normalized event indexes:

- tenant and event time
- category and event time
- severity and event time
- source and event time

JSONB fields are used only for targeted actor, asset, and IOC filters on bounded event retrieval. Aggregation APIs still avoid payload-level aggregation and operate on normalized scalar columns first.

## Observability

Analytics endpoints emit request counters and query latency histograms. Service logs include correlation IDs, total event counts, and elapsed time without logging raw event data or sensitive payload fields.
