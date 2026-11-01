# Changelog

## 2.2.0 — Explicit Full Admin authorization

### Administration
- Added opt-in, revocable Full Admin bearer credentials issued only by the local root CLI. Credentials have no expiry, are stored as SHA-256 hashes, and are written once to a new private file.
- Added persistent Full Admin grants for an exact OAuth client and owner subject after an authenticated administrator session exists. Registration alone does not grant Full Admin.
- Core privileged operations can run without per-action approval IDs or tokens while a Full Admin authorization is active; existing OAuth scopes, validation, backups, and audit controls remain in force.
- Added CLI commands to create/list/revoke bearer credentials and grant/list/revoke OAuth Full Admin authorization.
- Restored generic system_service/system_environment aliases and bounded administrator journal tools.
- Password recovery, signing-key rotation and revoke-all also revoke permanent credentials; client revocation clears its Full Admin grant.
- Added current-principal Full Admin status to health_check and integration tests for execution and live-session revocation.

### OAuth lifecycle
- OAuth access tokens retain their one-hour expiry. While an explicit OAuth Full Admin grant remains active, its unrevoked refresh credential remains eligible for renewal beyond its normal expiry. Rotation and revocation checks remain enforced.
- Revoking an OAuth Full Admin grant immediately restores per-action approval requirements. It does not log the client out or cancel work already running.


## 2.1.0 — Security and hardening

### Security
- Removed static bearer authentication; MCP requests require OAuth access tokens.
- Enforced fail-closed scope authorization and immediate access-token invalidation on refresh-session revocation.
- Restricted Gemini persistent-refresh behavior to the configured Gemini Client ID.
- Redacted sensitive audit and diagnostic details.
- Bound network artifacts to the creating OAuth client and owner subject, with automatic expiry.
- Expanded SSRF blocking for reserved IPv4, IPv4-mapped IPv6, NAT64, 6to4, Teredo, and documentation ranges.
- Hardened project file reads and writes against symlink, hardlink, and TOCTOU risks.
- Required root and an interactive local terminal for sensitive CLI operations.

### Compatibility
- Minimum runtime is Node.js 22.
- Standard MCP clients use OAuth Authorization Code with PKCE S256 and Dynamic Client Registration.

### Operations
- Added a self-contained smoke test, syntax linting, and GitHub Actions CI.
- Install dependencies as a locked, unprivileged build account.