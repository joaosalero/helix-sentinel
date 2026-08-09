---
name: review-security-privacy
description: Review Helix Sentinel changes or proposals for security, privacy, tenant isolation, secret handling, network exposure, and public/private separation.
---

Use this skill for a security or privacy review of a Helix Sentinel diff, change,
proposal, release scope, or configuration.

1. Inspect the diff, affected paths, existing contracts, and applicable `AGENTS.md`
   rules before making conclusions.
2. Identify trust boundaries involving tenants, authentication, authorization,
   persistence, logs, dependencies, network exposure, WSL2/Windows, Docker, and
   private/local versus public/standalone operation.
3. Classify each item as a confirmed vulnerability, plausible risk, or preventive
   improvement. Do not report a vulnerability without file-based evidence.
4. Assign severity proportionate to impact and exploitability. Never print secrets,
   tokens, credentials, or unnecessary sensitive payloads.
5. Recommend the minimum safe correction and identify validation needed. Do not
   modify files unless the user explicitly requests implementation.
6. Report scope, findings with evidence, non-findings, residual risks, and checks
   considered or run.

Activate for: “review this diff for security”, “privacy audit”, or “check whether
this change leaks local AI data”. Do not activate for a general style review with
no security or privacy objective.
