# Contributing

Helix Sentinel is a security-focused modular monolith. Keep changes small, explicit, and aligned with the existing domain boundaries.

## Before You Start

- Read [README.md](README.md), [docs/README.md](docs/README.md), and [docs/development/repository-standards.md](docs/development/repository-standards.md).
- Use feature branches.
- Keep unrelated cleanup out of feature changes.
- Do not add services, brokers, warehouses, or new infrastructure unless the existing workload clearly requires it.

## Development Flow

```bash
python -m pip install --upgrade "pip>=26.1"
python -m pip install -e ".[dev,security]"
npm --prefix frontend ci
scripts/check.sh
```

For focused validation, use `make test`, `make lint`, `make typecheck`, `make security`, `make frontend-lint`, and `make frontend-typecheck`.

## Pull Requests

PRs should include:

- A short summary of behavior or documentation changed.
- Tests or validation commands run.
- Security notes for auth, tenant isolation, audit logging, secrets, or raw telemetry.
- Observability notes when metrics, traces, logs, or correlation IDs are affected.

## Security-Sensitive Changes

- Preserve tenant isolation and RBAC behavior.
- Preserve audit event integrity and correlation IDs.
- Do not log secrets, tokens, authorization headers, password hashes, or sensitive raw event payloads.
- Do not include real customer, tenant, user, or production telemetry in tests or docs.

Report vulnerabilities through [SECURITY.md](SECURITY.md), not public issues.
