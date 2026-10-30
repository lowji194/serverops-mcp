# Changelog

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