# Security Policy

ServerOps MCP provides privileged Linux host-management capabilities. Treat a successful compromise as a potential host-level compromise.

## Reporting a vulnerability

Do not publish exploit details, credentials, signing keys, tokens, or sensitive host information in a public issue. Use GitHub private vulnerability reporting or Security Advisories when available. Otherwise contact the repository maintainer and request a private disclosure channel.

## Supported release

Security fixes target the latest supported release. Upgrade promptly and rotate credentials that may have been exposed.

## Full Admin credentials

Full Admin in 2.2.0 is an explicit local-root delegation of continuing host administrator authority. Creation/grant requires an interactive root terminal and owner authentication. It is never granted by client registration alone. Dedicated Bearer tokens and OAuth client/owner grants do not expire automatically; protect them accordingly and use the dedicated CLI revocation commands. OAuth access tokens still expire after one hour. Removing an OAuth Full Admin grant restores approval requirements rather than logging the client out, and revocation does not stop already running jobs.

See the [Full Admin trust boundary](docs/SECURITY.md#full-admin-trust-boundary) for lifecycle and revocation differences.

## Scope

Reports are especially relevant to OAuth authentication and token revocation, owner approval and Full Admin grants, filesystem path traversal and link handling, command execution, SSRF and DNS pinning, secret storage and logging, and systemd sandboxing.

See [docs/SECURITY.md](docs/SECURITY.md) for the security model.
Recovery commands (`reset-password`, signing-key rotation and token revoke-all) also revoke permanent Full Admin credentials and persistent OAuth Full Admin grants. Revoking a single OAuth refresh session leaves the separate Full Admin grant in place, but the revoked session cannot authenticate.
