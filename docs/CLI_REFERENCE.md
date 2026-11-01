# CLI Reference

The ServerOps CLI is the local owner interface. Run it with root privileges. The existing owner-credential, OAuth-client/session, signing-key and one-time approval commands require an interactive local terminal. Full Admin creation and OAuth grants also require an interactive terminal and owner authentication; read/list and emergency revocation commands require root.

## Status

~~~bash
sudo serverops status
~~~

## First-run activation

~~~bash
sudo serverops bootstrap
sudo serverops claim
~~~

- bootstrap creates a single-use activation token and prints it once.
- claim prompts for the activation token and a new owner password. Press Enter at the token prompt to read the protected local token file. The password is entered twice without echo.
- Do not pass activation tokens or passwords as command-line arguments.
- The activation token expires after 15 minutes and can be used once.

## Owner approvals

~~~bash
sudo serverops approvals list
sudo serverops approvals approve <approval-uuid>
sudo serverops approvals deny <approval-uuid>
~~~

Approval procedure:

1. Inspect the action, canonical payload, requester, and expiry printed by approvals list.
2. Run approvals approve with the exact request UUID.
3. Authenticate with the owner password.
4. Type the displayed confirmation phrase.
5. Copy the one-time approval token into the matching MCP operation.

Approval grants expire after five minutes and are bound to the approved action and payload hash. They cannot authorize a different request or be replayed.

## Full Admin

Full Admin management requires a trusted root shell. `create` and `oauth-grant` additionally require an interactive terminal and the owner password once. Read/list commands and emergency `revoke`/`oauth-revoke` commands remain root-only so an operator can remove access promptly. There is no corresponding MCP self-authorization tool.

```bash
sudo serverops full-admin create <label> /var/lib/serverops-mcp/trusted-client.token
sudo serverops full-admin list
sudo serverops full-admin status
sudo serverops full-admin revoke <token-id>
sudo serverops full-admin oauth-list
sudo serverops full-admin oauth-grant <client-id>
sudo serverops full-admin oauth-revoke <client-id>
```

- `create` requires a label and an absolute destination that does not already exist. It creates a mode-0600 file containing the secret once, and prints only token metadata. No plaintext token is stored in the database or returned by `list`.
- `list` and its alias `status` list permanent bearer token identifiers, labels, creation time and revocation state. `oauth-list` separately lists exact client/owner grants.
- Bearer tokens have no expiration. Configure the token as the MCP client's Bearer credential; protect the file as a root password. Revocation rejects the next request, including on an existing session.
- `oauth-grant` requires evidence of an active authenticated `system:admin` refresh session for the configured owner. Client registration alone is insufficient. The resulting grant has no expiry, and the client continues using OAuth and its existing scopes.
- OAuth access tokens retain their one-hour lifetime. While the explicit Full Admin grant is active, an unrevoked refresh credential can renew beyond its normal expiry. Rotated or revoked refresh credentials remain invalid.
- `oauth-revoke` removes Full Admin and restores per-action approval requirements immediately. It does not revoke the OAuth login; use the session/client commands separately when that is intended. Disconnecting OAuth does not erase its separately managed Full Admin grant.
- Neither kind of revocation cancels jobs already running or undoes completed changes. OAuth token/session revocation and signing-key rotation do not revoke dedicated Full Admin bearer tokens.
- Existing payload validation, filesystem protections, backups, resource limits and audit logs remain enforced. Client application confirmations are outside ServerOps control.

`health_check` reports `authorization.full_admin` and `authorization.per_action_approval_required` for the current authenticated principal.

## OAuth clients

~~~bash
sudo serverops clients list
sudo serverops clients revoke <client-id>
~~~

Revoking a client removes its registration, authorization codes, and active refresh sessions. Access tokens bound to those sessions become invalid immediately.

## Refresh sessions

~~~bash
sudo serverops token list
sudo serverops token revoke <fingerprint>
sudo serverops token revoke-all
sudo serverops revoke-all-tokens
~~~

The list command displays only a SHA-256 fingerprint prefix, client ID, scopes, and state. Use the fingerprint prefix with token revoke; the CLI rejects ambiguous prefixes. Revocation invalidates associated session-bound access tokens immediately.

## Signing key

~~~bash
sudo serverops rotate-signing-key
~~~

Key rotation requires the owner password and a typed confirmation. It creates the replacement key atomically and revokes all active refresh sessions. Restart the systemd service afterward; all MCP clients must authorize again.

## Owner password

~~~bash
sudo serverops reset-password
~~~

The CLI prompts for the new password twice. This operation requires root and an interactive local terminal. It revokes active refresh sessions and invalidates pending grants. If SERVEROPS_OWNER_PASSWORD_HASH is configured in the protected environment file, update that hash there and restart the service instead.

## Security requirements

- Never place passwords, activation tokens, refresh tokens, or signing keys in shell history or process arguments.
- Do not expose the local CLI or root shell to an MCP client.
- Keep the owner terminal under direct human control.
- Use a protected terminal session and avoid copying one-time approval tokens into logs or tickets.
