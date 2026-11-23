# Demo Data Guidance

Use deterministic, synthetic data when preparing screenshots or evaluator walkthroughs. Keep the scope small: one tenant, a few normalized event sources, one active detection rule, and one selected alert are enough to demonstrate the operational workflow.

## Recommended Scope

- Tenant: `default`
- Sources: `edr`, `identity`, and `firewall`
- Alert states: one `open`, one `acknowledged`, and one recently `closed`
- Event window: last 24 hours
- Payloads: synthetic hostnames, usernames, IPs, domains, and hashes only

## Quick Seed

With migrations applied and a local engineer or admin signed in, make the access token available in the process environment as `HELIX_API_TOKEN`. Then run:

```bash
python3 scripts/seed-demo-events.py
```

The helper posts to `http://localhost:8000/api/v1/events/ingest` by default. Override `HELIX_API_BASE_URL` or `HELIX_DEMO_TENANT_ID` only when exercising a different local API URL or tenant. The helper accepts loopback destinations and never follows redirects.

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

## Event-to-Evidence Walkthrough

This is a manual local walkthrough with synthetic data, not a report of an
automated end-to-end run. Use a fresh demo database if exact counts matter.

### Prerequisites

- Start the authoritative API, apply migrations, and start the dashboard as
  described in [local setup](development/local-setup.md).
- Use an already provisioned local account in the `default` tenant. The quick
  start does not create an account.
- Obtain a valid bearer access token through `POST /api/v1/auth/login` using that
  account. Rule import requires `detections:write`; execution and alert reads
  require `detections:read` plus `analytics:read`; workflow updates require
  `detections:read` plus `audit:read`.
- Set the ignored server-side `HELIX_API_TOKEN` for the dashboard. Do not paste
  tokens into fixtures, screenshots, committed files, or shared terminal output.
- Ingestion requires `events:ingest`. Seed only a disposable local database with synthetic events.

Use a local HTTP client that can send JSON bodies and an `Authorization: Bearer`
header for the protected requests below. The route handlers parse several bodies
from the request directly, so the generated API documentation may not expose a
complete request editor. Keep the same account and tenant throughout.

### 1. Ingest the synthetic events

Run `python3 scripts/seed-demo-events.py` from the repository root. Each accepted
request returns a `normalized_event_id`; retain the identity/authentication event ID for
the walkthrough.

The helper prints the normalized event ID returned by ingestion, matching the
event identity used by detection matches. It only inserts events; it does not
create accounts, rules, or alerts,
and repeated runs insert additional events rather than resetting a database.

### 2. Import one deliberately simple active rule

Submit this JSON body to `POST /api/v1/detections/rules/sigma`:

```json
{
  "status": "active",
  "operational_notes": "Synthetic local walkthrough only.",
  "content": "title: Synthetic authentication review\nlevel: medium\nlogsource:\n  category: authentication\ndetection:\n  selection:\n    source: identity\n    category: authentication\n  condition: selection\n"
}
```

Record the response `id` as `rule_id`. The rule uses exact comparisons on
normalized fields that the current evaluator supports. It does not claim full
Sigma compatibility or identify a real attack.

### 3. Execute the rule and inspect the alert

Submit this body to
`POST /api/v1/detections/rules/{rule_id}/execute`, replacing `{rule_id}`
with the returned UUID:

```json
{"tenant_id": "default", "source": "identity", "limit": 10}
```

The omitted time range defaults to the previous 24 hours. The response includes
`evaluated_events`, `matched_events`, and matched event IDs. With one fresh
seed, the identity event should match; repeated seeds or older data change the
counts. A non-active rule does not produce matches.

Query
`GET /api/v1/detections/alerts?tenant_id=default&rule_id={rule_id}`.
Select the alert linked to the retained event ID and record its `id` as
`alert_id`. Re-executing the same rule over the same events should not create a
second alert for the same rule/event pair.

### 4. Investigate, acknowledge, and close

Open the dashboard with the server-side token configured and select the alert.
Review its source, severity, time, matched selection, contextual event timeline,
and bounded investigation pivots.

Submit this body to
`PATCH /api/v1/detections/alerts/{alert_id}?tenant_id=default`:

```json
{"status": "acknowledged", "investigation_note": "Synthetic identity event reviewed locally."}
```

Then close that same alert:

```json
{"status": "closed", "disposition": "false_positive", "investigation_note": "Expected synthetic fixture; no real incident."}
```

The returned alert should retain acknowledgement/closure timestamps, disposition,
and the investigation note. On acknowledgement, an unassigned alert is assigned
automatically to the authenticated actor; this request does not choose an arbitrary
assignee. This synthetic disposition demonstrates
workflow state; it is not a measurement of real detection accuracy.

### 5. Follow the evidence

| Observation | Where to inspect |
| --- | --- |
| Ingested event identity | Seeder response `normalized_event_id` and matched `event_id` |
| Rule and selection | Imported rule response and execution `matches` |
| Durable alert lifecycle | `GET /api/v1/detections/alerts/{alert_id}?tenant_id=default` |
| Operational investigation context | Selected-alert panel in the dashboard |
| Sanitized execution/workflow activity | Dashboard security activity or `GET /api/v1/analytics/security-activity?tenant_id=default` |

The final activity route requires `analytics:read` and `audit:read`. Audit
records support a reviewable workflow, not a certified chain of custody.
Do not publish real tokens, full raw telemetry, or private operational metadata
as walkthrough evidence.
