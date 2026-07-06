#!/usr/bin/env bash
# Uninstall passivediscovery systemd service.
# Run with sudo: sudo ./deploy/uninstall.sh
# Optional: --purge to also remove binaries and data.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must run as root (use sudo)" >&2
    exit 1
fi

PURGE=false
if [[ "${1:-}" == "--purge" ]]; then
    PURGE=true
fi

echo "==> Stopping service"
if systemctl is-active --quiet passivediscovery.service; then
    systemctl stop passivediscovery.service
fi

echo "==> Disabling service"
systemctl disable passivediscovery.service 2>/dev/null || true

echo "==> Removing systemd unit"
rm -f /etc/systemd/system/passivediscovery.service
systemctl daemon-reload

if $PURGE; then
    echo "==> Removing binary & data (purge)"
    rm -rf /opt/passivediscovery
    rm -rf /var/lib/passivediscovery
    rm -rf /var/log/passivediscovery
    rm -f /etc/default/passivediscovery

    if getent passwd discovery >/dev/null; then
        userdel discovery || true
    fi
fi

echo "==> Done"
if $PURGE; then
    echo "Service, binary, data and user removed."
else
    echo "Service uninstalled. Data preserved at /var/lib/passivediscovery."
    echo "Run with --purge to remove everything."
fi
