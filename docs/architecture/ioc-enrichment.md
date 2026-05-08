# IOC Enrichment

The IOC enrichment foundation manages locally curated indicators and matches them against normalized security events. It is intentionally deterministic and does not perform external reputation lookups, URL fetching, DNS resolution, malware analysis, or automated response actions.

## Supported Indicators

- `ip`: validated with Python IP address parsing.
- `domain`: normalized to lowercase and validated with a bounded domain pattern.
- `url`: limited to `http` and `https` syntax and rejects localhost, loopback, private, and link-local hosts.
- `hash`: accepts MD5, SHA1, and SHA256 hex values for metadata correlation only.

Validation is syntax-only and local. This avoids SSRF risk and keeps future intelligence provider integrations behind explicit, reviewed boundaries.

## Enrichment Flow

1. Analysts or engineers create validated IOCs with confidence, severity, source, reliability, tags, and expiration metadata.
2. The enrichment service loads active IOCs from the repository.
3. Normalized events are scanned for candidate values in actor, asset, network, and normalized IOC metadata fields.
4. Matches produce event-to-IOC relationships with matched fields and factor-level confidence explanations.
5. Audit events and Prometheus metrics record execution counts and match counts without raw payload exposure.

## Confidence Model

Confidence is additive and capped at 100. Factors include configured IOC confidence, source reliability, severity, indicator type specificity, recency, and event match context. Every match returns the contributing factors so SOC users can understand why the score was assigned.

## API Boundaries

IOC creation requires `detections:write`. IOC listing, detail retrieval, summary metrics, and enrichment execution require `analytics:read`. Responses expose curated IOC metadata and relationship summaries, not raw event payloads.

## Database Strategy

`ioc_indicators` stores normalized IOC records with indexes for type, confidence, source, expiration, seen timestamps, tags, and metadata. `event_ioc_matches` stores event relationships with confidence, status, matched fields, and explainability metadata. This supports future IOC trend analytics and source quality reporting without introducing distributed enrichment workers.

The authoritative runtime uses a PostgreSQL-backed IOC repository for indicator inventory and event-to-IOC match persistence. In-memory IOC repositories remain available for isolated tests and explicit local overrides.
