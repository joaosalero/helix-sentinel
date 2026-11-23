# Authentication and RBAC

Helix Sentinel uses a compact security model aligned with a modular monolith:

- Passwords are hashed with Argon2.
- Access and refresh JWTs use separate secrets and expiration windows.
- Refresh tokens include `jti` values so rotation and revocation can be introduced without API changes.
- RBAC starts with four system roles: `admin`, `analyst`, `engineer`, and `viewer`.
- Permissions use `resource:action` names such as `analytics:read` and `detections:write`.

## Authorization Boundary

Routes should authorize with explicit role or permission checks. Superuser access is supported for break-glass administration, but normal access should use role-derived permissions.

## Persistence

The authoritative runtime uses PostgreSQL-backed repositories for authentication user lookups and audit event persistence. In-memory repositories remain available for isolated tests and explicit local overrides.

## Session Lifecycle Limits

A refresh request validates the JWT and current user state, then issues a new pair.
It does not persist consumption or revocation of the previous refresh token.
Logout records an audit event; previously issued access and refresh tokens remain
valid until their expiry. The current implementation must not be presented as
replay-resistant refresh rotation or immediate session revocation.

## Tenant and Ingestion Limits

Protected query routes resolve tenant scope from the principal and reject an
explicit different tenant for non-superusers. The PostgreSQL user adapter
currently sets `tenant_id="default"`, so this does not provide complete customer
multi-organization tenancy.

`POST /api/v1/events/ingest` has no route-level authentication and accepts the
payload tenant identifier. Run it only inside a trusted ingestion boundary; the
permission guards on analytics and detection routes do not protect ingestion.

Account provisioning is not automatic in the quick start. Database migrations
create schema, not a working account or a dashboard bearer token.

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
