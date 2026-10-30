#!/usr/bin/env bash
set -euo pipefail

# ServerOps MCP installer. Run from the repository root as root.
if [[ $EUID -ne 0 ]]; then
  echo "[Error] This installer must be run as root." >&2
  exit 1
fi

INSTALL_DIR="/opt/serverops-mcp"
CONFIG_DIR="/etc/serverops-mcp"
DATA_DIR="/var/lib/serverops-mcp"
LOG_DIR="/var/log/serverops-mcp"

if [[ ! -f "$INSTALL_DIR/package.json" ]]; then
  echo "[Error] ServerOps source is not installed at $INSTALL_DIR." >&2
  echo "Clone the repository to $INSTALL_DIR, then run this installer again." >&2
  exit 1
fi

NODE_BIN="$(command -v node || true)"
NPM_BIN="$(command -v npm || true)"
if [[ -z "$NODE_BIN" || -z "$NPM_BIN" ]]; then
  echo "[Error] Node.js and npm are required." >&2
  exit 1
fi
NODE_MAJOR="$("$NODE_BIN" -p 'Number(process.versions.node.split(".")[0])')"
if [[ "$NODE_MAJOR" -lt 22 ]]; then
  echo "[Error] Node.js 22 or newer is required (found $(node --version))." >&2
  exit 1
fi

echo "=== Installing ServerOps MCP ==="

# This service provides host-level administration and therefore runs as root.
# Privileged mutations require out-of-band local owner approval.
mkdir -p "$CONFIG_DIR/secrets" "$DATA_DIR" "$LOG_DIR"
chown -R root:root "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
chmod 700 "$CONFIG_DIR" "$CONFIG_DIR/secrets"
chmod 750 "$DATA_DIR" "$LOG_DIR"

# Create a safe default configuration without embedding signing keys or passwords.
if [[ ! -f "$CONFIG_DIR/serverops.env" ]]; then
  cat <<EOF > "$CONFIG_DIR/serverops.env"
SERVEROPS_BIND_HOST=127.0.0.1
SERVEROPS_PORT=8790
SERVEROPS_PUBLIC_BASE_URL=https://mcp.example.com
SERVEROPS_OAUTH_ISSUER=https://mcp.example.com
SERVEROPS_OWNER_SUBJECT=serverops-owner
SERVEROPS_DATA_DIR=$DATA_DIR
SERVEROPS_BACKUP_DIR=$DATA_DIR/backups
SERVEROPS_SECRET_DIR=$CONFIG_DIR/secrets
EOF
fi
chown root:root "$CONFIG_DIR/serverops.env"
chmod 600 "$CONFIG_DIR/serverops.env"

if [[ ! -f "$INSTALL_DIR/app/ui/dist/tailwind.css" ]]; then
  echo "[Error] Compiled authorization UI CSS is missing." >&2
  echo "Install development dependencies as an unprivileged user, run npm run build:css, then retry." >&2
  exit 1
fi

if [[ -z "$NPM_BIN" || -z "$NODE_BIN" ]] || ! command -v runuser >/dev/null 2>&1; then
  echo "[Error] npm and runuser are required to install dependencies without running lifecycle scripts as root." >&2
  exit 1
fi

BUILD_USER="serverops-build"
BUILD_HOME="/var/lib/serverops-build"
NOLOGIN="$(command -v nologin || printf '/usr/sbin/nologin')"
if ! getent group "$BUILD_USER" >/dev/null 2>&1; then
  groupadd --system "$BUILD_USER"
fi
if ! getent passwd "$BUILD_USER" >/dev/null 2>&1; then
  useradd --system --gid "$BUILD_USER" --home-dir "$BUILD_HOME" --create-home --shell "$NOLOGIN" "$BUILD_USER"
fi
# Enforce a locked, non-login identity with no supplementary group memberships.
usermod --gid "$BUILD_USER" --home "$BUILD_HOME" --shell "$NOLOGIN" --lock --groups "" "$BUILD_USER"
if [[ "$(id -u "$BUILD_USER")" -eq 0 ]]; then
  echo "[Error] Refusing to use a UID 0 account for dependency installation." >&2
  exit 1
fi
mkdir -p "$BUILD_HOME"
chown "$BUILD_USER:$BUILD_USER" "$BUILD_HOME"
chmod 700 "$BUILD_HOME"

echo "=== Installing production dependencies as the unprivileged build user ==="
chown -R "$BUILD_USER:$BUILD_USER" "$INSTALL_DIR"
restore_source_ownership() {
  chown -R root:root "$INSTALL_DIR"
}
trap restore_source_ownership EXIT
NPM_REGISTRY="${NPM_REGISTRY:-https://registry.npmjs.org}"
runuser -u "$BUILD_USER" -- env HOME="$BUILD_HOME" PATH="$(dirname "$NODE_BIN"):$PATH" "$NPM_BIN" ci --omit=dev --no-audit --no-fund --registry="$NPM_REGISTRY"
restore_source_ownership
trap - EXIT

if [[ ! -d "$INSTALL_DIR/node_modules/@modelcontextprotocol" || ! -d "$INSTALL_DIR/node_modules/better-sqlite3" ]]; then
  echo "[Error] Required production dependencies were not installed." >&2
  exit 1
fi

cp "$INSTALL_DIR/deploy/serverops.service" /etc/systemd/system/serverops.service
systemctl daemon-reload
ln -sf "$INSTALL_DIR/bin/serverops.mjs" /usr/local/bin/serverops

echo "=== Initializing first-run activation ==="
cd "$INSTALL_DIR"
if [[ -t 0 && -t 1 ]]; then
  ./bin/serverops.mjs bootstrap
else
  echo "Run 'sudo serverops bootstrap' from an interactive terminal to issue the one-time activation token."
fi

echo "=== ServerOps MCP installation completed ==="
echo "1. Edit $CONFIG_DIR/serverops.env and set your public hostname."
echo "2. Configure Nginx and TLS using deploy/nginx.conf."
echo "3. Start the service: sudo systemctl enable --now serverops"
echo "4. Check status: sudo serverops status"
echo "5. Claim the installation: sudo serverops claim"
