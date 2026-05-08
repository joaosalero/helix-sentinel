# Detection Engineering Architecture

Helix Sentinel's Detection Engineering layer manages detection rule metadata, Sigma imports, and bounded rule evaluation over normalized event history. It remains a modular monolith capability, not a distributed detection engine.

## Scope

The initial implementation supports:

- Sigma YAML validation with safe parsing.
- Normalized rule metadata.
- Lifecycle states: `draft`, `active`, and `deprecated`.
- Severity, category, tags, references, authorship, false-positive notes, tuning metadata, and operational notes.
- MITRE ATT&CK technique and tactic extraction from Sigma tags.
- Secure APIs for import, listing, filtering, pagination, and detail retrieval.
- Bounded active-rule execution over persisted normalized events.
- PostgreSQL-backed open alert records for matched rule/event pairs.

It intentionally does not implement realtime detection execution, SIEM query translation, XDR adaptation, correlation, simulation, or response orchestration.

## Sigma Parsing

Sigma parsing uses `yaml.safe_load` and accepts only YAML mappings with a non-empty `title` and `detection` section. Metadata extraction is pragmatic and focused on fields used by security teams during detection review. Unsupported Sigma engine semantics are preserved in `raw_rule` and `detection` fields for future adapters.

## Execution Lifecycle

Detection execution is synchronous and bounded by tenant, time range, optional source, and event limit. Only active rules produce matches. Evaluation uses normalized event fields and conservative Sigma-style selectors such as exact, contains, startswith, and endswith comparisons. Matched rule/event pairs create de-duplicated `open` alert records while execution remains synchronous. Execution emits audit events and Prometheus counters, but does not create incident records.

## ATT&CK Mapping

ATT&CK mappings are extracted from tags such as `attack.execution` and `attack.t1059.001`. The normalized mapping stores technique ID, optional technique name, and tactic. This keeps the data model ready for future coverage analytics and heatmaps without embedding the full ATT&CK corpus.

## Lifecycle and Quality Metadata

Rules carry status, false-positive notes, tuning metadata, quality metadata, and operational notes. Advanced quality scoring and false-positive analytics are intentionally deferred until alert and incident lifecycle data exists.

The authoritative runtime uses a PostgreSQL-backed detection rule repository for rule metadata and ATT&CK mappings. In-memory detection repositories remain available for isolated tests and explicit local overrides.

## Security Boundary

Upload handling accepts text content through JSON, not arbitrary files. The parser does not execute rule content, import Python objects, or deserialize unsafe YAML tags. APIs are protected by `detections:read` and `detections:write` permissions.

## Observability

Detection workflows emit counters for imports, parse failures, API usage, bounded rule executions, and created alerts. Import, parse failure, and execution flows emit audit events with correlation IDs and sanitized metadata.
