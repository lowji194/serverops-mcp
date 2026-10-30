# ServerOps MCP — Architecture

ServerOps MCP is a self-hosted Model Context Protocol server for Linux host administration and managed project deployment.

## Components

~~~text
AI client
  | OAuth 2.1 Authorization Code + PKCE S256
  v
HTTPS reverse proxy (Nginx)
  | loopback HTTP
  v
ServerOps MCP / Streamable HTTP
  +-- OAuth authorization server and DCR
  +-- Scope-checked MCP tools
  +-- Filesystem and systemd administration
  +-- Process execution and job management
  +-- DNS-pinned network engine
  +-- Managed-project staging / validation / publish / rollback
  |
  v
SQLite WAL database + private data, backup, artifact, and audit directories
~~~

## Runtime model

- Node.js 20 or newer runs the HTTP/MCP service.
- The production systemd unit runs as root because the service exposes host-administration tools.
- Nginx terminates TLS and proxies /mcp, /oauth/*, and /.well-known/* to the loopback listener.
- Persistent state is stored outside the source tree, normally under /var/lib/serverops-mcp.
- Configuration and secrets are stored outside the source tree, normally under /etc/serverops-mcp.

## Authentication

OAuth uses Authorization Code with PKCE S256, short-lived signed access tokens bound to a hashed refresh-session identifier, and revocable refresh tokens. Rotation or revocation invalidates associated access tokens immediately. Public clients can register through the RFC 7591 endpoint when their metadata and redirect URI match the supported policy. The optional Gemini confidential client is configured with a Google Cloud Client ID, Client Secret, and exact callback URI. Only that configured Client ID receives persistent-refresh behavior; a DCR client cannot opt into it through redirect metadata.

The authorization UI asks for the ServerOps owner password only. The owner identity is fixed by SERVEROPS_OWNER_SUBJECT; the client cannot select an arbitrary server identity.

## Authorization scopes

| Scope | Boundary |
|---|---|
| system:read | Diagnostics, metrics, safe environment keys, and non-sensitive service status |
| system:admin | Arbitrary host filesystem inspection, sensitive logs, root-level mutations, service lifecycle, process signals, command execution, elevated network requests, and job cancellation |
| project:read | Inspect configured managed projects and deployment state |
| project:edit | Stage changes inside configured project boundaries |
| project:preview | Diff, syntax checks, configured allowlisted tests in a shadow workspace, and preview staged project changes |
| project:publish | Request owner approval to publish validated project changes |
| project:rollback | Request owner approval to restore a project from a managed snapshot |

Scope checks are enforced in MCP tool handlers. system:admin must be treated as root access and should only be granted to trusted clients. Arbitrary host filesystem reads and journal logs are not available to system:read clients.

## Local owner approval workflow

Privileged host mutations, arbitrary command execution, elevated network requests, project publishing, and rollback use an out-of-band owner approval process:

1. An authenticated MCP client submits an exact action and canonical payload. The server stores a pending request and returns an approval ID only.
2. The VPS owner connects through a local interactive terminal and runs serverops approvals list.
3. The owner reviews the action and payload preview, enters the owner password, and types a request-specific confirmation phrase.
4. The CLI issues a random one-time grant valid for five minutes. The owner copies it into the matching MCP tool call.
5. The server verifies the action, payload hash, expiry, approval ID where applicable, and unused state before execution.

The MCP client cannot approve its own request or mint its own grant. Pending requests expire after ten minutes. Approval and consumption events are audited without storing plaintext grant tokens.

## Execution engine

The execution engine supports scripts and absolute executables with a curated child environment, explicit working directory, bounded timeout, concurrency limits, process-group cancellation, and pageable output artifacts. Secrets from the MCP process environment are not copied into child processes. Execution requests require local owner approval.

## Network engine

Outbound HTTP requests pin the resolved destination address, block private, reserved, mapped, and transition ranges by default, do not automatically follow redirects, and enforce per-request response/time limits. HTTP artifacts are isolated by client and owner subject and expire automatically. DNS lookup is read-only. TCP, UDP, private destinations, and state-changing HTTP requests require elevated scope and local owner approval.

## Managed project deployment

Managed projects are configured explicitly. File operations are restricted to configured project roots and reject symlink escapes. The workflow is stage, diff, syntax validation, configured allowlisted test execution in a temporary shadow workspace, preview, owner-approved publish, health-check, and owner-approved rollback. Validation commands are defined by the project allowlist, not by MCP request payloads; only trusted project roots and test commands may be configured.

## Persistence and recovery

SQLite runs in WAL mode. Refresh tokens and authorization codes are stored as hashes. File mutations and project deployments create recoverable backups where supported. Diagnostic summaries expose only allowlisted metadata and safe error categories; raw audit detail is not returned to MCP clients. Audit records also redact known credential patterns.

See [Security](SECURITY.md), [Deployment](DEPLOYMENT.md), and [Operations](OPERATIONS.md) for operational requirements.
