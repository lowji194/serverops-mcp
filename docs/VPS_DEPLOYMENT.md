# Deploy ServerOps MCP on a Linux VPS

This guide covers a new, independent installation. Do not use it to overwrite an existing production MCP service without a separate migration plan for its OAuth database, signing keys, public URL, integrations, and rollback path.

## 1. Prepare the VPS

Use a supported Linux distribution with systemd, Node.js 22 or newer (supported LTS lines: 22, 24 and 26), Git, Nginx, and a valid public DNS record.

Use a dedicated hostname such as mcp.example.com. The Node.js service must bind to 127.0.0.1 and be reached through an HTTPS reverse proxy. Do not expose the root-capable Node.js listener directly to the internet.

## 2. Install the source and dependencies

The repository includes the compiled authorization UI stylesheet.

~~~bash
sudo git clone https://github.com/lowji194/serverops-mcp.git /opt/serverops-mcp
cd /opt/serverops-mcp
sudo ./deploy/install.sh
~~~

For local development or UI changes, install development dependencies and rebuild the stylesheet:

~~~bash
npm ci
npm run build:css
npm test
~~~

## 3. Configure the service

The installer installs production dependencies as a locked, unprivileged build user, creates `/etc/serverops-mcp/serverops.env` with mode 0600, and prepares the root-capable systemd service. Edit the file and set your public URL and issuer:

~~~dotenv
SERVEROPS_BIND_HOST=127.0.0.1
SERVEROPS_PORT=8790
SERVEROPS_PUBLIC_BASE_URL=https://mcp.example.com
SERVEROPS_OAUTH_ISSUER=https://mcp.example.com
SERVEROPS_OWNER_SUBJECT=serverops-owner
~~~

The OAuth signing key is generated automatically and stored in the private data directory. Do not commit the environment file, SQLite database, signing key, backups, or runtime data.

## 4. Claim the installation

The installer initializes a one-time activation token valid for 15 minutes. Claim the server interactively:

~~~bash
sudo serverops claim
~~~

Enter the activation token and choose a strong owner password when prompted. Do not place either value in shell arguments or command history.

## 5. Configure TLS and start the service

Use deploy/nginx.conf as the reverse-proxy template. Replace the hostname and certificate paths, then validate and start:

~~~bash
sudo nginx -t
sudo systemctl enable --now serverops
sudo systemctl status serverops
~~~

The public MCP endpoint is:

~~~text
https://mcp.example.com/mcp
~~~

## 6. Connect an MCP client

Use the OAuth Authorization Code with PKCE flow. Start with system:read and grant system:admin only to trusted clients that require host administration. Gemini confidential OAuth is optional; see GOOGLE_OAUTH.md for Google Cloud Client ID and Client Secret setup.

## 7. Approve privileged operations locally

The MCP client can request privileged work but cannot approve its own request. On the VPS:

~~~bash
sudo serverops approvals list
sudo serverops approvals approve <approval-id>
~~~

Review the action and payload preview, enter the owner password, and type the request-specific confirmation phrase. The CLI prints a single-use token valid for five minutes. Copy it into the matching MCP tool call.

Reject a request with:

~~~bash
sudo serverops approvals deny <approval-id>
~~~

Owner approval requires a local interactive terminal. It cannot be completed through the MCP connection.

## 8. Verify and maintain

~~~bash
sudo serverops status
sudo journalctl -u serverops -n 100 --no-pager
curl -fsS https://mcp.example.com/healthz
~~~

Back up /var/lib/serverops-mcp and /etc/serverops-mcp securely. Test restoration before upgrades. Review release tags and commits, run the test suite, and use a health-check gate before restarting a production instance.
