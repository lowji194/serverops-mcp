# Gemini Confidential OAuth Client (Optional)

ServerOps MCP is its own OAuth 2.1 authorization server. The owner signs in to the ServerOps authorization page with the ServerOps owner password.

The optional Google Cloud OAuth credentials below are **client authentication credentials for Gemini**, not a Google Sign-In feature. ServerOps does not implement Google as an identity provider for owner login.

Most public MCP clients can use Dynamic Client Registration (DCR) and do not need a Google Cloud Client ID or Client Secret. Configure this optional integration only when the Gemini client setup explicitly requires a confidential OAuth client.

## 1. Create a Google Cloud OAuth client

1. Open Google Cloud Console and select or create a project.
2. Configure the OAuth consent screen according to Google's current requirements.
3. Open APIs & Services → Credentials.
4. Create an OAuth Client ID with application type **Web application**.
5. Add the exact redirect URI displayed by the Gemini MCP client setup. Gemini commonly uses a URI under oauth-redirect.googleusercontent.com, but use the exact value shown by your client.

Do not guess the redirect URI. OAuth redirect URI matching is exact.

## 2. Configure ServerOps

Edit the protected environment file on the VPS:

~~~bash
sudo nano /etc/serverops-mcp/serverops.env
sudo chmod 600 /etc/serverops-mcp/serverops.env
~~~

Set the Client ID, Client Secret, and exact redirect URI:

~~~dotenv
SERVEROPS_GEMINI_CLIENT_ID=your-google-cloud-client-id
SERVEROPS_GEMINI_CLIENT_SECRET=your-google-cloud-client-secret
SERVEROPS_GEMINI_REDIRECT_URI=https://oauth-redirect.googleusercontent.com/r/your-gemini-app-id
~~~

Keep the Client Secret out of Git, shell history, screenshots, logs, and MCP tool arguments.

## 3. Restart and verify

~~~bash
sudo systemctl restart serverops
sudo systemctl status serverops
~~~

The OAuth discovery document is available at:

~~~text
https://mcp.example.com/.well-known/oauth-authorization-server
~~~

The configured Gemini client is authenticated at the token endpoint using client_secret_post and is restricted to the configured redirect URI. Only this exact configured Client ID receives Gemini persistent-refresh behavior; a public DCR client with a Google-looking redirect URI does not. HTTP Basic client authentication is not accepted for this configured client.

## Secret rotation

If a Client Secret has ever been pasted into a chat, ticket, log, or public repository, treat it as exposed. Create a replacement secret in Google Cloud Console, update the protected environment file, restrict its permissions to mode 0600, and restart ServerOps. Never paste the replacement secret into an MCP request, shell argument, screenshot, or source file.

## 4. Troubleshooting

- invalid_client: verify the Client ID and Client Secret, and confirm the client authentication method is client_secret_post.
- redirect_uri_mismatch: the redirect URI in Gemini, Google Cloud, and ServerOps must match exactly, including path and trailing slash.
- invalid_scope: request only scopes supported by the registered client metadata.
- invalid_grant: restart the OAuth authorization flow; authorization codes are short-lived and single-use.

If the Gemini client supports public OAuth/DCR, remove the three SERVEROPS_GEMINI_* variables and use the standard public-client flow instead.
