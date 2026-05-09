# AI-Assisted Security Analytics Architecture

Helix Sentinel's AI-assisted analytics layer provides deterministic anomaly scoring and lightweight enrichment over normalized security events. It is intentionally not an LLM agent, autonomous copilot, deep-learning system, or external AI integration.

## Scope

The initial implementation supports:

- Frequency anomaly scoring.
- Severity concentration scoring.
- Short-window event burst detection.
- Entity concentration and low-and-slow activity detection.
- Suspicious event classification.
- Keyword extraction and suspicious term detection.
- IOC-aware enrichment metadata.

All outputs include explainability factors with point values, rationale, and relevant metadata.

## Scoring Philosophy

Scoring is additive, deterministic, and capped at 100. Factors include frequency deviation, severity concentration, short-window bursts, entity repetition, multi-source/category context, extended temporal patterns, IOC metadata, URL/domain terms, email/phishing terms, process terms, severity context, and suspicious keywords. Confidence bands are derived from score and factor count.

This makes the system suitable for SOC triage preparation without introducing opaque black-box behavior.

## NLP Enrichment

NLP support is deliberately lightweight. The service extracts stable lowercase tokens from normalized titles, source metadata, categories, actor and asset metadata, network metadata, and IOC metadata. Suspicious terms are matched from a small security vocabulary. No external NLP models or providers are used.

## APIs

AI-assisted analytics endpoints are protected by `analytics:read`:

- `/api/v1/ai/anomalies`
- `/api/v1/ai/enrichments`
- `/api/v1/ai/summary`

Filters include time range, tenant, event category, anomaly type, classification, minimum score, limit, and offset. Query windows are capped at 90 days.

## Persistence Strategy

The database migration prepares anomaly and enrichment metadata tables for future historical retrieval. Current APIs compute results on demand from bounded repository-backed normalized event windows, which avoids premature background orchestration.

## Observability

The layer emits API usage counters, anomaly counters by type, and scoring latency histograms. Logs include correlation IDs and aggregate counts only; raw payloads and sensitive metadata are not logged.
