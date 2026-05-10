# Security Policy

## Supported Versions

Helix Sentinel is pre-1.0. Security fixes are tracked against the default branch until release branches exist.

## Reporting a Vulnerability

Use GitHub private vulnerability reporting or a draft security advisory when available. Do not open public issues with exploit details, secrets, tokens, private tenant data, or proof-of-concept payloads.

Include:

- Affected component or endpoint.
- Reproduction steps with sanitized inputs.
- Expected and observed behavior.
- Impact assessment and any known mitigations.

If private vulnerability reporting is unavailable, open a minimal public issue stating that you have a security report to share, without technical details.

## Scope

In scope:

- Authentication, authorization, tenant isolation, audit integrity, API validation, dependency security, secret handling, and unsafe logging.

Out of scope:

- Social engineering, denial-of-service testing against hosted infrastructure, destructive testing, and attacks requiring access to secrets or systems you do not own.

## Local Security Expectations

- Copy `.env.example` to `.env`; never commit real `.env` files.
- Rotate `HELIX_SECRET_KEY`, `HELIX_AUTH_SECRET_KEY`, and `HELIX_AUTH_REFRESH_SECRET_KEY` outside local development.
- Do not log credentials, bearer tokens, authorization headers, password hashes, or raw sensitive telemetry.
- Keep tenant filters explicit and preserve existing authorization guards.

## Security Checks

The repository uses Bandit, pip-audit, Semgrep, Gitleaks, Ruff, MyPy, pytest, and frontend lint/typecheck workflows. Run `scripts/check.sh` before submitting security-sensitive changes. Local dependency audits skip the editable project package and audit installed dependencies.
