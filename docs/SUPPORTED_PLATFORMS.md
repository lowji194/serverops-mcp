# Supported Operating Systems

ServerOps MCP is designed for **Linux servers**. The primary deployment model uses Node.js, a systemd service, and a TLS-terminating reverse proxy.

| Operating system | Compatibility target | Notes |
| --- | --- | --- |
| Ubuntu Server 22.04 / 24.04 LTS | Linux deployment target | apt, systemd |
| Debian 12 / 13 | Linux deployment target | apt, systemd |
| AlmaLinux 9 / 10 | Linux deployment target | dnf, systemd, SELinux may require configuration |
| Rocky Linux 9 / 10 | Linux deployment target | dnf, systemd, SELinux may require configuration |
| Red Hat Enterprise Linux 9 / 10 | Linux deployment target | dnf, systemd, subscription and SELinux considerations |
| Fedora Server (supported releases) | Best-effort compatibility target | dnf, systemd |
| Other Linux distributions with systemd | Community/best-effort | May require package or service adjustments |
| Linux without systemd | Not supported by the standard service installer | Manual process supervision required |
| Windows / macOS | Not supported as managed production server platforms | May be usable as development clients, not Linux-management targets |

**Verification policy:** The entries above are deployment **targets**, not claims of completed distro certification. Do not mark an OS release as **tested** unless the actual installation and automated smoke tests have been run against that distribution and version. See release CI results for the verified test matrix.

## Runtime prerequisites

- A currently supported Node.js LTS runtime compatible with the published package.
- A compiler and Python build prerequisites if native SQLite modules must be compiled locally.
- A root-capable systemd service for host administration. The supplied unit runs as root with systemd sandbox restrictions; do not claim least-privilege daemon execution.
- HTTPS on the public endpoint, normally via Nginx or another supported reverse proxy.
- A private data directory and securely permissioned environment/secrets.
- systemd for the documented service-installation workflow.
- Administrative approvals and additional OS permissions for elevated operations.

## Linux package prerequisites

Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y git curl ca-certificates nginx python3 make g++
```

RHEL-compatible / Fedora:

```bash
sudo dnf install -y git curl ca-certificates nginx python3 make gcc-c++
```

Install Node.js LTS from an official supported distribution channel and verify `node --version` before running `npm ci`.

## Security model across platforms

SELinux, AppArmor, firewalls, reverse proxies, and filesystem permissions differ across distributions. The supplied systemd unit runs the host-administration daemon as root inside a filesystem and kernel sandbox. Keep loopback binding, enforce HTTPS, and review the unit's ReadWritePaths before deployment. The installer uses a separate locked `serverops-build` account only for npm dependency installation; that account does not run the daemon.

