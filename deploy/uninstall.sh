#!/usr/bin/env bash
set -euo pipefail

# ServerOps MCP Uninstaller
if [[ $EUID -ne 0 ]]; then
   echo "[Error] This script must be run as root." >&2
   exit 1
fi

echo "=== Uninstalling ServerOps MCP ==="

# Stop and disable systemd service
if systemctl is-active --quiet serverops 2>/dev/null; then
    echo "Stopping serverops.service..."
    systemctl stop serverops
fi

if systemctl is-enabled --quiet serverops 2>/dev/null; then
    echo "Disabling serverops.service..."
    systemctl disable serverops
fi

rm -f /etc/systemd/system/serverops.service
systemctl daemon-reload

# Remove CLI link
rm -f /usr/local/bin/serverops

echo "Service removed."
echo "Note: Configuration (/etc/serverops-mcp) and data (/var/lib/serverops-mcp) were preserved."
echo "To completely purge data, run: rm -rf /etc/serverops-mcp /var/lib/serverops-mcp /opt/serverops-mcp"
