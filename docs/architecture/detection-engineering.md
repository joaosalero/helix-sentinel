# Detection Engineering Architecture

Helix Sentinel's Detection Engineering layer manages detection rule metadata and Sigma imports. It is a catalog and normalization foundation, not a rule execution engine.

## Scope

The initial implementation supports:

- Sigma YAML validation with safe parsing.
- Normalized rule metadata.
- Lifecycle states: `draft`, `active`, and `deprecated`.
- Severity, category, tags, references, authorship, false-positive notes, tuning metadata, and operational notes.
- MITRE ATT&CK technique and tactic extraction from Sigma tags.
- Secure APIs for import, listing, filtering, pagination, and detail retrieval.

It intentionally does not implement realtime detection execution, SIEM query translation, XDR adaptation, correlation, simulation, or response orchestration.

## Sigma Parsing

Sigma parsing uses `yaml.safe_load` and accepts only YAML mappings with a non-empty `title` and `detection` section. Metadata extraction is pragmatic and focused on fields used by security teams during detection review. Unsupported Sigma engine semantics are preserved in `raw_rule` and `detection` fields for future adapters.

## ATT&CK Mapping

ATT&CK mappings are extracted from tags such as `attack.execution` and `attack.t1059.001`. The normalized mapping stores technique ID, optional technique name, and tactic. This keeps the data model ready for future coverage analytics and heatmaps without embedding the full ATT&CK corpus.

## Lifecycle and Quality Metadata

Rules carry status, false-positive notes, tuning metadata, quality metadata, and operational notes. Advanced quality scoring and false-positive analytics are intentionally deferred until alert and incident lifecycle data exists.

## Security Boundary

Upload handling accepts text content through JSON, not arbitrary files. The parser does not execute rule content, import Python objects, or deserialize unsafe YAML tags. APIs are protected by `detections:read` and `detections:write` permissions.

## Observability

Detection workflows emit counters for imports, parse failures, and API usage. Import and parse failure flows emit audit events with correlation IDs and sanitized metadata.

