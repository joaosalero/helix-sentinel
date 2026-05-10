# Documentation

Start here when navigating the repository:

- [Architecture overview](architecture/overview.md)
- [Public showcase guide](showcase.md)
- [Public release readiness](release-readiness.md)
- [Local development setup](development/local-setup.md)
- [Repository standards](development/repository-standards.md)
- [Contribution guide](../CONTRIBUTING.md)
- [Security policy](../SECURITY.md)
- [Observability](operations/observability.md)
- [Security baseline](security/security-baseline.md)
- [Authentication and RBAC](security/authentication-rbac.md)

Core product areas:

- [Event ingestion](architecture/event-ingestion.md)
- [Detection engineering](architecture/detection-engineering.md)
- [SOC analytics](architecture/soc-analytics.md)
- [Threat analytics](architecture/threat-analytics.md)
- [AI-assisted analytics](architecture/ai-assisted-analytics.md)
- [IOC enrichment](architecture/ioc-enrichment.md)
- [Database architecture](architecture/database.md)

## Evaluator Path

The fastest way to understand the project is to review the operational SOC dashboard alongside the architecture overview:

- The dashboard shows executive posture, alert queue pressure, investigation context, ATT&CK coverage, and audit-backed security activity.
- Selecting an alert demonstrates the bounded investigation workflow: alert detail, triage readiness, source/category context timeline, evidence pivots, acknowledgement, and closure.
- The architecture docs explain why these surfaces stay inside a modular monolith with PostgreSQL-backed persistence and server-side API access instead of adding streaming, websocket, graph, or SIEM-query infrastructure.

For screenshot and walkthrough guidance, see the [public showcase guide](showcase.md).
