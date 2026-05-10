# Public Showcase Guide

Use this path when reviewing Helix Sentinel as a public portfolio project or engineering sample.

## Review Path

1. Read the repository overview in [README.md](../README.md), especially the at-a-glance summary and showcase surfaces.
2. Open the architecture overview to confirm the modular-monolith boundaries and explicit non-goals.
3. Run the API and frontend locally, then open the SOC dashboard.
4. Review the dashboard from top to bottom: executive posture, triage pressure, detection coverage, audit-backed security activity, priority findings, open alert queue, and selected-alert investigation detail.
5. Select an alert and follow the investigation panel through triage readiness, evidence pivots, context timeline, acknowledgement, and closure.
6. Run the publication validation gate in [release-readiness.md](release-readiness.md) before sharing the repository.

## What The Demo Should Show

- The product is an operational SOC workflow application, not a marketing page.
- Alerts are persisted lifecycle records with status, assignment, notes, disposition, and timestamps.
- Investigation context is bounded by source, category, and event time rather than an unbounded SIEM search language.
- Executive posture and dashboard KPIs are deterministic summaries over normalized events, alert workflow state, coverage analytics, threat analytics, AI-assisted analytics, and audit activity.
- API access from the frontend remains server-side, including bearer-token handling.

## Screenshot Targets

For public repository images or a portfolio walkthrough, capture:

- The full dashboard with executive posture and operational brief visible.
- The open alert queue with one selected alert.
- The investigation detail panel showing triage readiness, evidence pivots, and context timeline.
- The detection coverage and security activity panels.

## Demo Capture Checklist

- Use synthetic or sanitized seed data only.
- Capture the dashboard after selecting an alert so the investigation panel is populated.
- Prefer a desktop-width viewport so executive posture, operational brief, alert queue, and investigation detail are visible together.
- Verify the header shows a safe scope label such as `Aggregate demo` or `Tenant filtered`.
- Do not include browser address bars containing private `tenant_id` values.
- Do not include local tokens, private tenant identifiers, real customer data, or raw event payloads in screenshots.

## Scope Boundaries

Helix Sentinel intentionally avoids realtime streaming, websockets, graph engines, microservices, SIEM query languages, compliance management, and fake-enterprise governance workflows. The showcase should stay focused on pragmatic SOC operations, deterministic analytics, persisted investigation workflow, and maintainable security engineering.
