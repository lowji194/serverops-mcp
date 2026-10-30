# Security Model and Threat Boundaries

ServerOps MCP is a host-administration service. The production systemd unit runs with host-level privileges so approved tools can manage files, processes, services, and deployments. Treat the endpoint as a privileged management plane, not a general public API.

## Critical deployment requirements

1. Expose the service through HTTPS only. Bind Node.js to loopback (127.0.0.1) and use a reverse proxy.
2. Prefer a VPN, private network, firewall allowlist, or reverse-proxy IP allowlist. Do not expose an unrestricted root-capable MCP endpoint to the public internet.
3. Grant system:read by default. system:admin is equivalent to root-level host access.
4. Use a long, unique owner password. Do not pass passwords, activation tokens, OAuth tokens, or Client Secrets in command-line arguments.
5. Keep /etc/serverops-mcp, /var/lib/serverops-mcp, and backups outside the Git working tree. Never commit .env files, SQLite databases, signing keys, or runtime artifacts.
6. Back up the data directory and test restore procedures before upgrades.

## Authentication and authorization

- Owner authentication uses scrypt with a unique salt and constant-time comparison.
- OAuth uses Authorization Code with PKCE S256. Access tokens are signed by a persistent server signing key and bound to the SHA-256 identifier of their refresh-token session. Refresh-token rotation or revocation invalidates associated access tokens immediately. Legacy access tokens without a session claim remain accepted only until their original expiry (maximum one hour).
- Public MCP clients can use Dynamic Client Registration (RFC 7591) where their metadata host and redirect URI are supported.
- The default requested scope is system:read; a client cannot request scopes outside its registered metadata.
- Gemini confidential-client credentials are optional and validated separately. Only the explicitly configured Gemini Client ID receives Gemini persistent-refresh behavior; a DCR client does not become a Gemini client by registering a Google redirect URI. Google credentials are not used for owner sign-in.
- Refresh tokens can be revoked individually, by client, or globally from the local CLI.

## Privileged operation approvals

Host mutations, arbitrary command execution, private-network requests, and production project publish/rollback use an out-of-band owner approval workflow:

1. The authenticated MCP client requests approval for an exact canonical action and payload. The server stores a pending request and returns only an approval ID.
2. The VPS owner connects locally and runs sudo serverops approvals list.
3. The owner reviews the target and payload preview, enters the owner password, and types the request-specific confirmation phrase.
4. The CLI issues a random, single-use grant valid for five minutes. The owner copies that token into the matching MCP operation.
5. The server verifies action, payload hash, expiry, request ID where applicable, and unused state before execution.

An MCP client cannot approve its own request or mint its own grant. Pending requests expire after ten minutes. Approval and consumption events are audited without storing plaintext grant tokens. Bootstrap, claim, password reset, client/token revocation, signing-key rotation, and approval operations require root privileges and an interactive local TTY. Destructive operations require owner authentication and a typed confirmation phrase. Activation tokens and passwords are accepted only through hidden interactive prompts, never command-line arguments. Do not expose shell access or the owner password to an AI client.

## Filesystem confidentiality

system:read is limited to non-sensitive diagnostics, metrics, and safe environment keys. Arbitrary host filesystem metadata, directory listings, file reads, and journal logs require system:admin because they may reveal credentials, tokens, configuration, or personal data. Project-scoped reads remain constrained by the project manager's path and sensitive-file deny rules.

## Project validation

The privileged service performs syntax checks and may run only the test command explicitly configured in the project allowlist, inside a temporary shadow workspace with a curated environment, timeout, and output limits. MCP requests cannot choose an arbitrary validation command. Treat every configured project root and test command as trusted code; do not add an untrusted repository to the allowlist.

Managed project publish and rollback use the same local owner approval queue. The review includes the project, change set or backup, and affected file list.

## Network protections

- DNS results are resolved and pinned for outbound HTTP requests.
- Private and loopback destinations are blocked by default.
- Private HTTP, non-idempotent requests, TCP, and UDP operations require elevated authorization and a matching owner-approved grant.
- Redirects are not followed automatically.
- Request/response sizes, timeouts, retry counts, and output sizes are bounded.
- HTTP response artifacts are stored with a default 24-hour TTL and can be read only by the OAuth client and owner subject that created them.
- Secret headers are referenced by filename from the protected secret directory; their values are not returned in tool output.

## Execution protections

- Child processes receive a curated environment rather than the full MCP/OAuth process environment.
- Execution concurrency, timeouts, process groups, and output byte limits are enforced.
- Jobs can be inspected and cancelled.
- The service uses systemd filesystem protections, a private temporary directory, a restrictive umask, and resource limits. Some kernel-level operations remain restricted by the unit's systemd sandbox.

## Data handling

- OAuth refresh tokens and authorization codes are stored as hashes.
- The signing key is generated into the private data directory with restrictive file permissions unless an operator explicitly configures an environment override.
- Diagnostic summaries expose allowlisted metadata and safe error categories, not raw audit detail, stderr, command text, file paths, or credentials. Audit records also redact bearer tokens and common password fields. Never put secrets inside shell command strings or arbitrary payloads.
- File mutations create recoverable backups where supported. Backups are sensitive and must be protected like the source files.

## Optional Gemini credentials

The optional Gemini confidential OAuth integration accepts a configured Client ID, Client Secret, and exact redirect URI. The configured token authentication method is client_secret_post. Keep the secret in /etc/serverops-mcp/serverops.env with mode 0600; never place it in source control.

## Vulnerability reporting

Please report vulnerabilities through a private GitHub Security Advisory for this repository. Include the affected version, reproduction steps, impact, and any suggested mitigation. Do not publish working exploit details before a fix is available.
