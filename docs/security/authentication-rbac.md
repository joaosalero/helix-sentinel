# Authentication and RBAC

Helix Sentinel uses a compact security model aligned with a modular monolith:

- Passwords are hashed with Argon2.
- Access and refresh JWTs use separate secrets and expiration windows.
- Refresh tokens include `jti` values so rotation and revocation can be introduced without API changes.
- RBAC starts with four system roles: `admin`, `analyst`, `engineer`, and `viewer`.
- Permissions use `resource:action` names such as `analytics:read` and `detections:write`.

## Authorization Boundary

Routes should authorize with explicit role or permission checks. Superuser access is supported for break-glass administration, but normal access should use role-derived permissions.

## Account Enumeration

Login failures return a generic authentication error for missing users, invalid passwords, and inactive accounts. Missing-user login attempts still perform dummy password verification to reduce timing differences.

## Audit Events

Authentication and authorization flows emit structured audit events for:

- Login success and failure.
- Refresh-token use.
- Logout intent.
- Permission denial.
- Rejected user state.

Audit metadata is sanitized and must not include credentials, tokens, authorization headers, password hashes, or sensitive raw security telemetry.

