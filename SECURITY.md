# Security Policy

ServerOps MCP provides privileged Linux host-management capabilities. Treat a successful compromise as a potential host-level compromise.

## Reporting a vulnerability

Do not publish exploit details, credentials, signing keys, tokens, or sensitive host information in a public issue. Use GitHub private vulnerability reporting or Security Advisories when available. Otherwise contact the repository maintainer and request a private disclosure channel.

## Supported release

Security fixes target the latest supported release. Upgrade promptly and rotate credentials that may have been exposed.

## Scope

Reports are especially relevant to OAuth authentication and token revocation, owner approval grants, filesystem path traversal and link handling, command execution, SSRF and DNS pinning, secret storage and logging, and systemd sandboxing.

See [docs/SECURITY.md](docs/SECURITY.md) for the security model.