# CLI Reference

The ServerOps CLI is the local owner interface. Run it with root privileges. Commands that change owner credentials, clients, tokens, signing keys, or approvals also require an interactive local terminal.

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
