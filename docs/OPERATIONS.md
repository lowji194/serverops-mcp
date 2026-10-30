# ServerOps MCP — Operations and CLI Reference

Run these commands on the VPS. Use sudo for privileged owner operations.

## Service lifecycle

~~~bash
sudo systemctl status serverops
sudo systemctl restart serverops
sudo journalctl -u serverops -n 100 --no-pager
sudo serverops status
~~~

## First-run activation and password

~~~bash
sudo serverops bootstrap
sudo serverops claim
sudo serverops reset-password
~~~

The CLI prompts for passwords and activation tokens without echoing them. Do not pass secrets as command-line arguments. Bootstrap, claim, password reset, client/token revocation, and signing-key rotation require root and an interactive local terminal; destructive actions also require owner authentication and a typed confirmation phrase.

## Local owner approval queue

The MCP client can only create pending approval requests. It cannot issue its own approval token.

~~~bash
sudo serverops approvals list
sudo serverops approvals approve <approval-id>
sudo serverops approvals deny <approval-id>
~~~

Approval procedure:

1. Review the exact action, target, payload hash, and available payload preview.
2. Enter the configured owner password when prompted.
3. Type the approval-specific phrase shown by the CLI.
4. Copy the one-time grant token into the matching MCP tool call.

Requests expire after ten minutes. Issued grants expire after five minutes and can be used once. Approval is available only from a local interactive terminal.

## OAuth clients and tokens

~~~bash
sudo serverops clients list
sudo serverops clients revoke <client-id>
sudo serverops token list
sudo serverops token revoke <fingerprint>
sudo serverops token revoke-all
sudo serverops token rotate
~~~

The CLI displays token fingerprints only; it never prints stored OAuth refresh tokens.

## Diagnostics and audit

~~~bash
sudo serverops status
sudo journalctl -u serverops -n 100 --no-pager
~~~

MCP tools health_check and system_diagnostics provide read-only operational summaries. Arbitrary host file reads and service logs require system:admin.

## Backups and recovery

File mutations create recoverable backups where supported. Project deployments and rollbacks maintain per-project snapshots under the configured backup directory. Protect this directory as sensitive production data and test restore procedures regularly.
