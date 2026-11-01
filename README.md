# ServerOps MCP

> Self-hosted, root-capable Model Context Protocol server for Linux administration, monitoring, deployment, and automation.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D22.0.0-green.svg)](https://nodejs.org/)
[![OAuth 2.1](https://img.shields.io/badge/OAuth-2.1%20%2B%20PKCE-purple.svg)](https://datatracker.ietf.org/doc/html/rfc7636)
[![CI](https://github.com/lowji194/serverops-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/lowji194/serverops-mcp/actions/workflows/ci.yml)

ServerOps MCP connects compatible AI clients to a Linux host through the standard [Model Context Protocol](https://modelcontextprotocol.io/). It provides scoped OAuth authorization, host diagnostics, filesystem operations, systemd management, an isolated execution engine, guarded network access, and a staged project deployment workflow.

## Security notice

**The production systemd service runs as root because its purpose is host administration.** A client authorized with the `system:admin` scope can perform root-level operations on the host, including executing commands. Treat this scope as equivalent to granting trusted remote administrator access.

- Put the service behind HTTPS and a reverse proxy.
- Prefer a VPN, private network, or IP allowlist; do not expose an unrestricted root-capable MCP endpoint.
- Grant `system:read` by default. Grant `system:admin` only to clients that genuinely need it.
- By default, privileged mutations, command execution, elevated network requests, project publishing, and rollback require a separate local owner approval. An owner can explicitly authorize a trusted principal for revocable Full Admin to avoid per-action grants. The MCP client receives only a pending request ID; the VPS owner reviews it, authenticates with the owner password, and issues the one-time grant from an interactive terminal.
- Keep the owner password, OAuth signing key, database, and backups outside the Git repository.

Read [Security & Threat Model](docs/SECURITY.md) before enabling remote administration.

## Highlights

- **OAuth 2.1 + PKCE S256** with RFC 7591 Dynamic Client Registration for compatible public MCP clients.
- **Password-only owner authorization** with scrypt password hashing and a local, one-time bootstrap claim.
- **Scoped access** separating host read operations, root administration, and managed-project permissions.
- **Out-of-band owner approval by default** for privileged filesystem, service, process, command, network, job-cancel, publish, and rollback operations. Approval grants are single-use and bound to the exact payload.
- **Optional Full Admin authorization** through a root-issued permanent bearer credential or an explicit grant for an already authenticated OAuth client. Each operation checks the current authorization; revocation takes effect on subsequent requests.
- **Root-capable systemd service** with filesystem protections, private temporary storage, resource limits, and restrictive file permissions.
- **Execution engine** for Bash, Python, Node.js, and absolute executables, with concurrency limits, timeouts, process-group cancellation, bounded output, and a sanitized child environment.
- **Network engine** with DNS pinning, private-address protection by default, bounded responses, secret-file references, and local owner approval for elevated requests.
- **Managed project workflow** with staging, SHA-256 conflict detection, shadow validation, deployment backups, health checks, and rollback.
- **Operational CLI** for activation, password reset, OAuth client/token revocation, signing-key rotation, and service status.
- **Optional Gemini confidential OAuth client** using a Google Cloud Client ID and Client Secret. It is not required for ChatGPT or public DCR clients.

## Architecture

```
AI Client
   |
   | OAuth 2.1 + PKCE
   v
HTTPS Reverse Proxy (Nginx)
   |
   v
ServerOps MCP (Streamable HTTP /mcp)
   |
   +-- OAuth authorization and token endpoints
   +-- Scope-checked MCP tools
   +-- Filesystem and systemd administration
   +-- Execution and network engines
   +-- Managed project staging / deployment
   |
   v
SQLite (WAL) + private data, audit, and backup directories
```

## Quickstart

### Prerequisites

- Linux with systemd (Ubuntu/Debian and other systemd distributions; see [supported platforms](docs/SUPPORTED_PLATFORMS.md)).
- Node.js 22 or newer; use a currently supported LTS line (22, 24 or 26).
- Nginx or an equivalent HTTPS reverse proxy.
- Git, Python 3, make, and a C/C++ toolchain if native SQLite bindings need to be built.

### 1. Clone the repository

The compiled authorization UI stylesheet is committed to the repository, so a standard installation does not need development dependencies or a CSS build step. If you change the authorization UI source, rebuild the stylesheet in a separate unprivileged development checkout before committing.

```bash
sudo git clone https://github.com/lowji194/serverops-mcp.git /opt/serverops-mcp
cd /opt/serverops-mcp
```

### 2. Install the systemd service

```bash
sudo ./deploy/install.sh
```

The installer creates a locked, unprivileged `serverops-build` account for dependency installation, installs production dependencies without running npm lifecycle scripts as root, creates protected directories, and writes `/etc/serverops-mcp/serverops.env`. Edit that file and replace `mcp.example.com` with your actual hostname:

```dotenv
SERVEROPS_BIND_HOST=127.0.0.1
SERVEROPS_PORT=8790
SERVEROPS_PUBLIC_BASE_URL=https://mcp.example.com
SERVEROPS_OAUTH_ISSUER=https://mcp.example.com
```

The OAuth signing key is generated automatically and stored in the private data directory. Do not set `SERVEROPS_OAUTH_SIGNING_KEY` unless you intentionally manage key rotation yourself.

### 3. Configure HTTPS and start the service

Use [deploy/nginx.conf](deploy/nginx.conf) as the reverse-proxy template. Configure the hostname and TLS certificate paths, then run:

```bash
sudo nginx -t
sudo systemctl enable --now serverops
sudo systemctl status serverops
```

The MCP endpoint is:

```text
https://mcp.example.com/mcp
```

### 4. Claim the installation

The installer creates a single-use activation token and prints it once. Keep that output private. Then run the CLI interactively:

```bash
sudo serverops claim
```

Enter the activation token and choose a strong owner password when prompted. If the installer did not print a token, press Enter at the token prompt to use the protected local token file. Do not put the token or password in shell arguments or command history.

If the token is lost, wait for its 15-minute expiry and run `sudo serverops bootstrap` to issue a replacement. The bootstrap token is only for the initial claim; it is not an MCP bearer token.

### 5. Authorize privileged operations locally

The MCP client can request an operation but cannot approve it. On the VPS, inspect the queue:

~~~bash
sudo serverops approvals list
~~~

Approve a specific request:

~~~bash
sudo serverops approvals approve <approval-id>
~~~

The CLI displays the action and payload preview, prompts for the owner password, and requires a request-specific confirmation phrase. It then prints a single-use token valid for five minutes. Copy that token into the matching MCP tool call. Reject requests with:

~~~bash
sudo serverops approvals deny <approval-id>
~~~

Approval is available only from a local interactive terminal. Alternatively, explicitly authorize a trusted client for Full Admin as described below.

### 6. Connect an MCP client

Add the MCP server URL in the MCP/connector settings of a compatible client:

```text
https://mcp.example.com/mcp
```

Use the OAuth authorization server endpoints:

- Authorization: `https://mcp.example.com/oauth/authorize`
- Token: `https://mcp.example.com/oauth/token`
- Discovery: `https://mcp.example.com/.well-known/oauth-authorization-server`

The default requested scope is `system:read`. Review the scopes shown on the authorization page before granting access.

## OAuth scopes

| Scope | Access |
|---|---|
| `system:read` | Diagnostics, resource metrics, safe environment keys, and non-sensitive service status |
| `system:admin` | Arbitrary host filesystem reads, sensitive logs, root-level mutations, service lifecycle, process signals, command execution, elevated network operations, and job cancellation. Mutations require local owner approval unless the principal has an active explicit Full Admin authorization. |
| `project:read` | Read configured managed projects and deployment state |
| `project:edit` | Stage changes inside configured project boundaries |
| `project:preview` | Diff, shadow validation, and deployment previews |
| `project:publish` | Publish a validated change set with local owner approval or active Full Admin |
| `project:rollback` | Restore a snapshot with local owner approval or active Full Admin |

## Full Admin for trusted clients

Full Admin is opt-in. A new installation and newly registered OAuth clients do not receive it automatically. The local root CLI can grant it to an exact OAuth client/owner pair only after that client has an active, authenticated `system:admin` refresh session:

```bash
sudo serverops full-admin oauth-grant <client-id>
sudo serverops full-admin oauth-list
sudo serverops full-admin oauth-revoke <client-id>
```

Granting access requires root, an interactive terminal and the owner password once. The grant has no expiry. The client still needs valid OAuth authentication and the required tool scopes. Access tokens expire after one hour and refresh normally; while the grant remains active, an unrevoked refresh credential can renew beyond its normal expiry. Revoking this grant restores per-action approval checks immediately, including in an existing MCP session. It does not log the client out or stop a running command.

For clients that support a custom Bearer credential, root can instead issue a dedicated non-expiring token:

```bash
sudo serverops full-admin create trusted-client /var/lib/serverops-mcp/trusted-client.token
sudo serverops full-admin list
sudo serverops full-admin revoke <token-id>
```

Creation requires root, an interactive terminal and the owner password. The output path must be absolute and must not exist. The secret is written once with mode `0600`; CLI output and the database contain only its identifier/hash, not the secret. Send the file content as `Authorization: Bearer <token>` to `/mcp`. Anyone holding it has administrator access until it is revoked. Use a separate token per trusted client. Signing-key rotation and OAuth refresh revocation do not replace explicit Full Admin token revocation.

Full Admin removes ServerOps per-action grants for core filesystem, execution, service, process, network and project publish/rollback tools. It preserves existing validation and operational protections; client-side confirmation policies and separate integration publication policies are unchanged. The MCP API provides no tool to mint a Full Admin credential or grant. See [CLI reference](docs/CLI_REFERENCE.md#full-admin) and [security model](docs/SECURITY.md#full-admin-trust-boundary).

The core-tools table below describes default approval requirements. An active Full Admin authorization satisfies the per-action approval gate.

## Core tools

| Category | Representative tools | Scope |
|---|---|---|
| Health and diagnostics | `health_check`, `system_diagnostics`, `system_resource_inspect` | `system:read` |
| Filesystem inspection | `root_stat`, `root_list`, `root_read`, `system_file_manage` | `system:admin` |
| Filesystem mutations | `root_write`, `root_mkdir`, `root_move`, `root_delete`, `system_file_manage` | `system:admin` + local owner approval |
| systemd | `system_services`, `system_service_status` | `system:read` |
| Sensitive service logs and lifecycle | `system_service_logs`, `system_service_action` | `system:admin`; lifecycle actions require local owner approval |
| Execution | `system_command_execute`, `system_execute`, `system_job_status`, `system_job_cancel` | `system:admin`; execution and cancellation require local owner approval |
| Network | `system_network` | `system:read`; elevated requests require `system:admin` + local owner approval |
| Projects | `project_list`, `project_file_put`, `project_validate`, `project_deploy_publish`, `project_rollback` | `project:*` |

## CLI reference

| Command | Purpose |
|---|---|
| `sudo serverops bootstrap` | Issue a bootstrap token on an unclaimed installation |
| `sudo serverops claim` | Claim the server and set the owner password interactively |
| `sudo serverops reset-password` | Reset the owner password locally |
| `sudo serverops status` | Show service configuration and OAuth counts |
| `sudo serverops token list` | List token fingerprints and expiry, never token secrets |
| `sudo serverops token revoke <fingerprint>` | Revoke one refresh token |
| `sudo serverops token revoke-all` | Revoke all active refresh tokens |
| `sudo serverops token rotate` | Rotate the signing key and revoke refresh tokens |
| `sudo serverops rotate-signing-key` | Rotate the signing key and revoke refresh tokens |
| `sudo serverops clients list` | List registered OAuth clients |
| `sudo serverops clients revoke <client_id>` | Revoke a client and its refresh tokens |
| `sudo serverops full-admin create <label> <absolute-new-file>` | Issue a non-expiring Full Admin token to a private file |
| `sudo serverops full-admin list` / `sudo serverops full-admin status` | List Full Admin token IDs and revocation state |
| `sudo serverops full-admin revoke <token-id>` | Revoke a Full Admin token immediately |
| `sudo serverops full-admin oauth-grant <client-id>` | Grant persistent Full Admin to an authenticated admin client |
| `sudo serverops full-admin oauth-list` | List OAuth Full Admin grants |
| `sudo serverops full-admin oauth-revoke <client-id>` | Restore approval requirements for the client |
| `sudo serverops approvals list` | List pending privileged operations |
| `sudo serverops approvals approve <approval-id>` | Locally approve one exact operation and issue a one-time grant |
| `sudo serverops approvals deny <approval-id>` | Deny a pending operation |

## Optional Gemini OAuth

Gemini products that require a confidential OAuth client can use a Google Cloud Web application Client ID/Secret. This configuration is optional and separate from ChatGPT DCR. See [Optional Gemini OAuth Setup](docs/GOOGLE_OAUTH.md).

## Development and verification

```bash
npm ci
npm run lint
npm run build:css
npm test
npm audit --omit=dev --audit-level=moderate
```

Run the read-only MCP smoke test. It starts an isolated temporary ServerOps instance on loopback, exercises the MCP endpoint, and removes its temporary data when finished:

```bash
npm run smoke
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Deployment](docs/DEPLOYMENT.md)
- [VPS deployment](docs/VPS_DEPLOYMENT.md)
- [Security & Threat Model](docs/SECURITY.md)
- [Operations & CLI](docs/OPERATIONS.md)
- [Supported Platforms](docs/SUPPORTED_PLATFORMS.md)
- [Optional Gemini OAuth](docs/GOOGLE_OAUTH.md)
- [CLI Reference](docs/CLI_REFERENCE.md)

## License

MIT. See [LICENSE](LICENSE).

Recovery commands (`reset-password`, signing-key rotation and token revoke-all) also revoke permanent Full Admin credentials and persistent OAuth Full Admin grants. Revoking a single OAuth refresh session leaves the separate Full Admin grant in place, but the revoked session cannot authenticate.
