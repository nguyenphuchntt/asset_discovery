#!/usr/bin/env bash
# Install passivediscovery as systemd service.
# Run with sudo: sudo ./deploy/install.sh

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must run as root (use sudo)" >&2
    exit 1
fi

if ! command -v go >/dev/null 2>&1; then
    echo "ERROR: Go is not installed. Install Go 1.21+ first: https://go.dev/doc/install" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

SERVICE_USER="discovery"
SERVICE_GROUP="discovery"
INSTALL_DIR="/opt/passivediscovery"
DATA_DIR="/var/lib/passivediscovery"
LOG_DIR="/var/log/passivediscovery"

echo "==> Building binary (CGO + libpcap)"
cd "$PROJECT_DIR"
CGO_ENABLED=1 go build -o "$INSTALL_DIR/discovery.tmp" ./cmd/discovery
chmod 0755 "$INSTALL_DIR/discovery.tmp"
mv -f "$INSTALL_DIR/discovery.tmp" "$INSTALL_DIR/discovery"

echo "==> Creating user & data directories"
if ! getent group "$SERVICE_GROUP" >/dev/null; then
    groupadd --system "$SERVICE_GROUP"
fi
if ! getent passwd "$SERVICE_USER" >/dev/null; then
    useradd --system \
        --gid "$SERVICE_GROUP" \
        --home "$DATA_DIR" \
        --no-create-home \
        --shell /usr/sbin/nologin \
        --comment "Passive discovery service" \
        "$SERVICE_USER"
fi

mkdir -p "$DATA_DIR"/{output,db}
mkdir -p "$LOG_DIR"
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$DATA_DIR" "$LOG_DIR"

# Copy OUI CSV from repo if present
if [[ -f "$PROJECT_DIR/internal/oui/oui.csv" ]]; then
    install -m 0644 -o "$SERVICE_USER" -g "$SERVICE_GROUP" \
        "$PROJECT_DIR/internal/oui/oui.csv" "$INSTALL_DIR/oui.csv"
fi

# Fix binary perms
chmod 0755 "$INSTALL_DIR/discovery"

echo "==> Installing systemd unit"
install -m 0644 "$SCRIPT_DIR/passivediscovery.service" \
    /etc/systemd/system/passivediscovery.service

if [[ ! -f /etc/default/passivediscovery ]]; then
    install -m 0644 "$SCRIPT_DIR/passivediscovery.default" \
        /etc/default/passivediscovery
fi

echo "==> Granting live capture capabilities (live mode)"
# Add NET_RAW only — keep service as non-root user.
# systemd still allows AmbientCapabilities via setcap on the binary.
if command -v setcap >/dev/null 2>&1; then
    setcap cap_net_raw,cap_net_admin+ep "$INSTALL_DIR/discovery" || \
        echo "  WARN: setcap failed — live mode will need NET_RAW reconfiguration"
fi

echo "==> Reloading systemd"
systemctl daemon-reload

echo "==> Enabling service (auto-start on boot)"
systemctl enable passivediscovery.service

echo "==> Starting service"
systemctl restart passivediscovery.service

sleep 1
if systemctl is-active --quiet passivediscovery.service; then
    echo "==> OK: service is running"
else
    echo "==> FAILED: service is not active. Tail of journal:"
    journalctl -u passivediscovery -n 30 --no-pager >&2
    exit 1
fi

cat <<EOF

============================================================
Installed at:    $INSTALL_DIR/discovery
Data directory:  $DATA_DIR
Config:          /etc/default/passivediscovery
Service:         /etc/systemd/system/passivediscovery.service
Log:             journalctl -u passivediscovery -f

Manage:
  systemctl status passivediscovery
  systemctl restart passivediscovery
  systemctl stop passivediscovery
  journalctl -u passivediscovery -f
============================================================
EOF
