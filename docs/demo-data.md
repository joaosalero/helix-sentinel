# Demo Data Guidance

Use deterministic, synthetic data when preparing screenshots or evaluator walkthroughs. Keep the scope small: one tenant, a few normalized event sources, one active detection rule, and one selected alert are enough to demonstrate the operational workflow.

## Recommended Scope

- Tenant: `default`
- Sources: `edr`, `identity`, and `firewall`
- Alert states: one `open`, one `acknowledged`, and one recently `closed`
- Event window: last 24 hours
- Payloads: synthetic hostnames, usernames, IPs, domains, and hashes only

## Quick Seed

After the backend is running and migrations have completed, seed the bounded synthetic events with:

```bash
python3 scripts/seed-demo-events.py
```

The helper posts to `http://localhost:8000/api/v1/events/ingest` by default. Override `HELIX_API_BASE_URL` or `HELIX_DEMO_TENANT_ID` only when exercising a different local API URL or tenant. Keep the target limited to local or trusted demo environments.

This seeds ingestion and investigation context only. Alert lifecycle views still depend on the configured detection rules and authenticated dashboard/API access.

## Alert Visibility

For screenshots that need a populated queue, use one active detection rule that matches one of the seeded events, execute it over the `default` tenant, then select the created alert in the dashboard. Keep the walkthrough bounded to one open alert plus one acknowledgement or closure action so the investigation panel, context timeline, and audit-backed workflow state remain easy to review.

## Minimal Event Payloads

These payloads exercise ingestion, normalization, analytics, and investigation context without exposing sensitive telemetry.

```json
{
  "source": {"name": "edr", "product": "endpoint", "vendor": "Helix Demo"},
  "tenant_id": "default",
  "severity": "high",
  "category": "endpoint",
  "payload": {
    "event": {"action": "process started"},
    "process": {"name": "powershell.exe", "command_line": "powershell -enc demo"},
    "host": {"name": "workstation-07", "ip": "10.20.30.40"},
    "user": {"name": "analyst.demo"}
  }
}
```

```json
{
  "source": {"name": "identity", "product": "sso", "vendor": "Helix Demo"},
  "tenant_id": "default",
  "severity": "medium",
  "category": "authentication",
  "payload": {
    "event": {"action": "login failed"},
    "user": {"name": "analyst.demo", "email": "analyst.demo@example.test"},
    "source": {"ip": "203.0.113.25"}
  }
}
```

```json
{
  "source": {"name": "firewall", "product": "network", "vendor": "Helix Demo"},
  "tenant_id": "default",
  "severity": "critical",
  "category": "network",
  "payload": {
    "event": {"action": "connection blocked"},
    "src_ip": "10.20.30.40",
    "dest_ip": "198.51.100.10",
    "ioc": {"domain": "malicious-demo.example"}
  }
}
```

## Showcase Notes

- Use a server-side `HELIX_API_TOKEN` for dashboard access; do not store tokens in browser storage.
- Capture the dashboard after selecting an alert so the investigation panel has context.
- Keep browser address bars and query strings out of public screenshots.
- Do not use real tenant IDs, user emails, hostnames, IPs, hashes, domains, or raw customer telemetry.
