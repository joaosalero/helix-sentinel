# HELIX SENTINEL — ENGINEERING OPERATING RULES

## Mission and priorities

Helix Sentinel is a production-oriented security analytics and SOC operations platform.
Work must preserve a secure, private, auditable, maintainable public product.

Priority order:

1. Security and privacy by design.
2. Correctness, tenant isolation, auditability, and operational safety.
3. Compatibility, maintainability, and clear bounded architecture.
4. Professional, accessible, responsive SOC user experience.
5. Efficient execution and low file/dependency churn.

Token or time efficiency must never replace required security, privacy, quality, or
risk-appropriate validation.

## Engineering judgment and requirement hierarchy

Security, privacy, correctness, data protection, and architectural integrity take
precedence over a user's proposed implementation method. Treat user ideas as
objectives and preferences, not permission for an unsafe or unsuitable solution.
Before implementing, assess conflicts with security, privacy, architecture,
reliability, and maintainability practices.

Implement a safer, technically superior adjustment when it preserves the user's
objective, remains within authorized scope, is reversible, and has no significant
architectural, behavioral, operational, or cost impact. Explain that deviation in the
final summary. If a correction materially changes product behavior, architecture, data
handling, trust boundaries, compatibility, external exposure, cost, or project scope,
stop and request authorization.

Never weaken security or privacy to follow an implementation detail literally.
"Modern technology" means the currently suitable, secure, and maintainable choice for
this project, not automatically the newest version or framework.

Resolve conflicts in this order:

1. Safety and applicable legal or data-protection requirements.
2. Security and privacy.
3. Correctness and data integrity.
4. Explicit product objective.
5. Architecture and maintainability.
6. UX and performance.
7. Implementation preference.
8. Token and execution efficiency.

Document relevant assumptions, rejected unsafe approaches, and residual risks
concisely.

## Product profiles and trust boundaries

Helix Sentinel has two strictly separated profiles.

### Private/local profile

The private profile may integrate with authorized local AI pipelines, local services,
and private data. It must preserve access control, confidentiality, traceability, and
tenant isolation.

Private integrations must be optional, explicitly configured, and decoupled from the
public product core. Local configuration containing private endpoints, paths,
credentials, data, names, or infrastructure details must remain outside version
control.

### Public/standalone profile

The public product must work independently of private local AI infrastructure. It
must not contain or require private services, data, credentials, internal endpoints,
personal names, local paths, sensitive samples, or operational metadata.

Public defaults must be secure. Before publication or sharing, inspect the intended
scope for secrets, credentials, internal paths, private package sources, sensitive
fixtures, generated metadata, and undocumented local dependencies.

Never mix private configuration or data into public code, documentation, examples,
tests, images, logs, lockfiles, commits, releases, or external messages.

## Environment and platform security

Ubuntu under WSL2 is the primary private execution environment. Keep processing,
dependencies, services, data, and tools there when technically appropriate.

Windows is the host and must remain clean, private, and secure. Perform Windows-side
actions only when necessary for the approved task and explain their justification.

Respect security boundaries between Windows, WSL2, Docker, networks, filesystems,
and credentials. Do not expose services on public interfaces by default. Prefer
loopback binding, least privilege, authentication, segmentation, encryption where
applicable, and secure secret handling.

Do not introduce commands, settings, or automation that weaken Windows, Ubuntu,
WSL2, Docker, networking, authentication, or logging. Recommend security updates
when relevant, but do not apply them without authorization.

## Confirmed architecture

Helix Sentinel is a modular monolith. Preserve this model while it remains the best
fit for demonstrated requirements.

Confirmed runtime and ownership boundaries:

- The authoritative backend runtime is `backend/helix_sentinel/main.py`.
- The authoritative SQLAlchemy metadata owner is `helix_sentinel.db.base.Base`.
- Active feature domains primarily live under `backend/app/*`.
- Platform and foundation modules primarily live under `backend/helix_sentinel/*`.

The `app/*` and `helix_sentinel/*` split is an existing constraint, not a cleanup
project. Do not perform namespace consolidation or broad domain migration unless it
is necessary, explicitly authorized, low risk, and incrementally validated.

Reuse existing contracts, repositories, middleware, schemas, validation, and
observability patterns when they are secure and suitable. Preserve deterministic
behavior, typed boundaries, repository-backed persistence, SQLAlchemy expression
queries, async PostgreSQL adapters, and the FastAPI app-factory model.

Do not add microservices, streaming, WebSockets, graph systems, SIEM query
languages, opaque AI behavior, background-system sprawl, or abstraction layers
without a proven requirement.

Material architectural changes require a demonstrated need, alternatives, benefit,
risk, migration path, compatibility impact, and validation plan before implementation.

## Security, privacy, and observability

Always preserve:

- RBAC and least-privilege semantics;
- tenant scoping and authorization boundaries;
- audit events and correlation IDs;
- structured logging and no-secret logging;
- input validation and safe query construction;
- Prometheus, readiness, Grafana compatibility, and OpenTelemetry hooks;
- Semgrep, Gitleaks, dependency scanning, and CI security controls.

Never log or persist passwords, password hashes, authorization headers, tokens,
credentials, secrets, unnecessary personal data, raw sensitive customer payloads,
or identifying telemetry unless explicitly required, authorized, and protected.

Do not weaken Semgrep, Gitleaks, CI enforcement, authentication, authorization,
tenant isolation, auditability, or dependency-chain controls to make work easier.

Changes affecting trust boundaries, authentication, authorization, tenant isolation,
secrets, network exposure, persistence, migrations, ingestion, external
integrations, or sensitive telemetry require threat modeling proportional to the
risk before implementation.

## Frontend and UX

The frontend is an operational SOC workbench, not a marketing site or consumer UI.
Preserve server-rendered Next.js behavior, the typed API client, bounded
investigation workflows, and operational readability.

Prefer modern, professional, accessible, responsive layouts with clear information
hierarchy, low cognitive load, consistent interaction patterns, and measurable
operational value.

Avoid dependencies, animation, global state, charting systems, or frontend
abstractions without a concrete benefit. Do not block justified UX or technology
improvements: evaluate accessibility, performance, security, maintenance, and
compatibility first.

## Dependency and change discipline

Minimize dependency churn, file churn, and architectural movement. Do not upgrade,
replace, or migrate frameworks speculatively.

Before a dependency change, identify the operational need, compatibility and security
risk, CI impact, and rollback or containment strategy.
Treat Next.js, ESLint, Tailwind, observability, and security tooling as
high-sensitivity ecosystems.

Inspect modules, contracts, integration points, documentation, workflows, and state
before editing. Preserve pre-existing user changes. Make small, cohesive, task-related
changes only. Do not modify unrelated files or invent APIs, files, registries,
integrations, results, or runtime behavior.

## Validation

Use validation proportional to scope and risk. Start with focused checks and expand
when risk justifies it. Never omit required validation to save tokens or time, and
do not repeatedly run heavy suites without a reason.

Changes involving authentication, authorization, tenant isolation, persistence,
migrations, security controls, dependencies, CI, or public/private boundaries
require appropriate automated tests and targeted security validation.

Existing validation commands include:

- `make test` or `pytest`
- `make lint`
- `make format-check`
- `make typecheck`
- `make security`
- `make frontend-lint`
- `make frontend-typecheck`
- `make check` or `make release-check`
- `scripts/check.sh`

Report checks run, results, and relevant checks intentionally not run.

## Authorization boundaries

Do not install, update, delete, move, revert, format, stage, commit, branch, tag,
push, publish, release, send external data, or modify files outside the authorized
scope without explicit user authorization.

Do not run destructive commands. Do not discard or rewrite pre-existing changes.

When a material ambiguity affects security, privacy, architecture, public/private
separation, data handling, external impact, or compatibility, stop and request a
decision rather than assuming permission.

After implementation, summarize modified files, integration points, validation,
security/privacy impact, remaining risks, and the safest next incremental step.
