# Security Baseline

Helix Sentinel follows an OWASP ASVS-oriented baseline:

- Input validation at API and domain boundaries.
- SQL injection prevention through SQLAlchemy expression APIs.
- Password hashing with Argon2.
- JWT-ready token creation with short-lived access token defaults.
- RBAC-ready identity model.
- Audit event foundation for security-relevant actions.
- CORS and security headers configured through middleware.
- Secret scanning, dependency scanning, and static security analysis prepared in CI.

Public vulnerability reporting is handled through the repository security policy. Reports should not be filed as public issues when they include exploit details, secrets, tokens, private tenant data, or proof-of-concept payloads.

The authentication foundation adds separate access and refresh token secrets,
Argon2 password verification, role and permission guards, token `jti` claims for
future refresh-token rotation, and structured audit events for authentication and
authorization decisions.

Tenant-aware analytics routes scope non-superuser requests to the authenticated
principal tenant. Explicit cross-tenant filters are rejected and audited unless
the principal is a superuser.

AI-assisted features must treat model inputs and outputs as untrusted. Prompt content, external enrichments, and model summaries require validation and safe logging controls before they influence detection logic or user-visible recommendations.
