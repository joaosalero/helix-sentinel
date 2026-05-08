# Threat Analytics Architecture

Helix Sentinel's Threat Analytics layer generates lightweight, deterministic threat insights from normalized security events. It is designed for SOC triage and future analytics expansion, not for realtime SIEM-scale correlation.

## Correlation Scope

The initial implementation identifies:

- Repeated authentication failures.
- Suspicious IP reuse across multiple actors.
- IOC-related events.
- Repeated endpoint anomalies.
- Short-window event frequency bursts.

The correlation logic is intentionally deterministic and explainable. There is no streaming engine, graph database, ML model, autonomous response, or external enrichment dependency.

## IOC Strategy

IOC metadata is extracted from normalized event fields and represented as typed references for IP, domain, URL, and hash indicators. Persisted IOC enrichment matches are aggregated for tenant-scoped activity reporting, including match volume, matched events, confidence, severity, trend, and top matched indicators. This keeps IOC visibility operationally useful without inventing external intelligence.

## Risk Scoring

Risk scores are additive and capped at 100. Factors include highest severity, event frequency, suspicious repetition, IOC relationships, and ATT&CK metadata when present. Every score includes factor-level explanations so analysts can understand why an insight was generated.

## Temporal Assumptions

Threat filters are capped to 90 days. Event bursts currently require at least five related events within one hour. Repeated authentication failures require at least three failures for the same actor identifier. These thresholds are conservative defaults that can become configurable once operational data exists.

## APIs

Threat Analytics endpoints are protected by `analytics:read`:

- `/api/v1/threats/insights`
- `/api/v1/threats/summary`
- `/api/v1/threats/ioc-activity`

Filters include time range, tenant, insight type, minimum risk score, minimum IOC match confidence, indicator type, indicator value, limit, and offset.

## Observability

Threat Analytics emits API usage counters, correlation counters by insight type, and correlation latency histograms. Logs include correlation IDs and aggregate counts only; raw payloads and sensitive metadata are not exposed.
