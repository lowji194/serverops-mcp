# ServerOps MCP — Deployment Guide

This guide describes production deployment on a Linux host with systemd.

## Prerequisites

- Linux with systemd (Ubuntu/Debian/RHEL-compatible distributions)
- Node.js 22 or newer (supported LTS lines: 22, 24 and 26)
- Nginx or an equivalent reverse proxy with a valid TLS certificate
- openssl and curl

## 1. Install

~~~bash
sudo git clone https://github.com/lowji194/serverops-mcp.git /opt/serverops-mcp
cd /opt/serverops-mcp
sudo ./deploy/install.sh
~~~

## 2. First-run activation

The installer initializes a single-use 256-bit activation token valid for 15 minutes.

~~~bash
sudo serverops claim
~~~

The installer prints a single-use activation token once when run from an interactive terminal. Run `sudo serverops claim`, enter the token and choose the owner password twice. If no token was printed, press Enter at the token prompt to read the protected local token file. The CLI never accepts activation tokens or passwords as command-line arguments. The password hash is stored in the protected application database.

## 3. Local owner approval for privileged operations

The MCP client can request a privileged operation, but cannot approve it or issue its own grant. On the VPS:

~~~bash
sudo serverops approvals list
sudo serverops approvals approve <approval-id>
~~~

The CLI displays the exact action and payload preview, prompts for the owner password, and requires a request-specific confirmation phrase. It then prints a single-use token valid for five minutes. Copy that token into the matching MCP tool call.

Reject a request with:

~~~bash
sudo serverops approvals deny <approval-id>
~~~

Owner approval requires a local interactive terminal and cannot be completed through the MCP connection itself.

## 4. Reverse proxy setup

Copy the Nginx template:

~~~bash
sudo cp deploy/nginx.conf /etc/nginx/sites-available/serverops.conf
sudo ln -s /etc/nginx/sites-available/serverops.conf /etc/nginx/sites-enabled/
~~~

Replace the example hostname and TLS certificate paths. Then run:

~~~bash
sudo nginx -t
sudo systemctl reload nginx
~~~

## 5. Connect AI clients

### ChatGPT

1. Open the Custom GPT editor and add an MCP connection using the supported ChatGPT connector flow.
2. Use the public MCP endpoint: https://mcp.example.com/mcp
3. Complete OAuth authorization in the ServerOps password-only authorization page.
4. Start with system:read. Grant system:admin only when the client needs host administration.

### Gemini and other confidential OAuth clients

Use the discovery endpoint at https://mcp.example.com/.well-known/oauth-authorization-server. Configure the optional Google OAuth Client ID, Client Secret, and exact redirect URI in the protected environment file. See GOOGLE_OAUTH.md.

## 6. Verify service

~~~bash
sudo systemctl status serverops
sudo serverops status
curl -fsS https://mcp.example.com/healthz
~~~

Keep the endpoint behind TLS and a VPN, firewall, or reverse-proxy IP allowlist whenever possible.
