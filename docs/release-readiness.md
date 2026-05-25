# Public Release Readiness

Use this checklist before making the repository public or sharing it as an engineering sample.

## Validation Gate

Run the complete local validation suite:

```bash
make release-check
```

This runs backend linting, backend format checks, MyPy, pytest, Bandit, dependency auditing, frontend linting, and frontend type checking through the existing repository targets.

## Operational Review

- Start PostgreSQL and Redis, apply migrations, and run the authoritative FastAPI app.
- Start the Next.js dashboard with server-side API configuration.
- Use synthetic demo data only; see [demo-data.md](demo-data.md) for bounded payload examples.
- Confirm the dashboard loads executive posture, operational brief cards, detection coverage, security activity, open alert queue, and selected-alert investigation detail.
- Select an alert and verify the persisted workflow path: acknowledgement, closure, investigation note, disposition, and refreshed dashboard state.
- Check Prometheus metrics and Grafana availability when running the local observability stack.

## Security Review

- Confirm `.env` and `frontend/.env.local` are not committed.
- Rotate local secrets before sharing screenshots or recordings.
- Do not publish screenshots containing bearer tokens, private tenant identifiers, real customer data, raw event payloads, or private telemetry.
- Crop or hide browser address bars if they contain private query parameters such as `tenant_id`.
- Preserve server-side API token handling in the frontend.
- Preserve RBAC, tenant filtering, and audit behavior when changing demo data or workflows.

## Repository Review

- Keep the README, showcase guide, architecture overview, local setup, and security docs consistent.
- Avoid adding marketing-site behavior, realtime infrastructure, graph systems, SIEM query languages, or governance/compliance scope.
- Keep future changes small enough to review and include tests for behavior changes.
