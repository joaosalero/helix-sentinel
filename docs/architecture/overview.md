# Architecture Overview

Helix Sentinel uses a modular monolith. The backend deploys as one FastAPI application while keeping domain modules explicit: identity, audit, events, detections, analytics, threat intelligence, and validation.

This approach keeps operational complexity low during early product development while preserving boundaries that can support future extraction if a domain develops independent scaling needs.

## Backend Boundaries

- `api`: HTTP transport and versioned route composition.
- `core`: configuration, middleware, logging, exception handling, and runtime wiring.
- `db`: SQLAlchemy base types, async session management, and repository primitives.
- `domains`: domain-owned persistence models and future domain services.
- `services`: integrations such as Redis and future notification or enrichment clients.
- `observability`: metrics and tracing integration.
- `security`: password and token primitives.
- `analytics`: SOC operational metrics and dashboard-ready aggregations over normalized events.
- `detections`: Detection Engineering catalog, Sigma metadata parsing, and ATT&CK mappings.
- `threats`: Deterministic threat correlations, IOC relationships, and explainable risk scoring.
- `ai`: Deterministic AI-assisted anomaly scoring, classification metadata, and NLP enrichment.
- `enrichment`: Managed IOC inventory, strict local IOC validation, and deterministic event-to-IOC matching.

## Data Architecture

PostgreSQL is the system of record. JSONB is used only for analytics payloads, enrichment metadata, and explainability context where flexible schema is justified. Core identity, RBAC, audit, and lifecycle entities remain normalized.

The schema is vector-ready: future pgvector columns can be introduced in AI enrichment or analytics metadata tables without changing domain boundaries.

## Frontend Boundary

The frontend scaffold prepares a Next.js application with TypeScript, TailwindCSS, and shadcn/ui conventions. No product pages are implemented yet; the structure is ready for dense operational dashboards, reusable layout primitives, accessible controls, and domain-specific feature folders.
