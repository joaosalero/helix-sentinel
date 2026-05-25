# Repository Standards

- Keep domain logic inside its owning domain module.
- Keep HTTP request/response concerns inside `api`.
- Do not introduce service boundaries, brokers, or infrastructure unless a concrete workload requires it.
- Use typed Python only and keep MyPy strictness intact.
- Use structured logging and avoid logging secrets, tokens, raw credentials, or unnecessary raw event payloads.
- Add tests with every behavior change.
- Prefer explicit functions and small classes over abstract frameworks.
- Keep dependency updates focused and review Dependabot PRs one ecosystem at a time.
- Preserve README, showcase, release-readiness, and security docs when changing operational workflows.
