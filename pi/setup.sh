#!/usr/bin/env bash
# pi/setup.sh -- Heartwood Pi setup script (multi-instance)
# Run on a fresh Raspberry Pi OS Lite installation.
#
# Usage:
#   ./setup.sh                          # install system deps + code only
#   ./setup.sh --instance personal      # also create a named instance
#   ./setup.sh --instance personal --port 3000
set -euo pipefail

INSTANCE=""
PORT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --instance) INSTANCE="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

echo "=== Heartwood Pi Setup ==="

# --- System user ---
sudo useradd -r -s /usr/sbin/nologin heartwood 2>/dev/null || true
sudo usermod -aG debian-tor heartwood 2>/dev/null || true
sudo mkdir -p /var/lib/heartwood /run/heartwood
sudo chown heartwood:heartwood /var/lib/heartwood /run/heartwood
sudo chmod 700 /var/lib/heartwood
sudo chmod 700 /run/heartwood

# --- Tor hostname copy drop-in ---
sudo mkdir -p /etc/systemd/system/tor@default.service.d
cat <<'DROPIN' | sudo tee /etc/systemd/system/tor@default.service.d/heartwood-hostname.conf >/dev/null
[Service]
ExecStartPost=/bin/sh -c 'for d in /var/lib/heartwood/*/; do cp /var/lib/tor/heartwood/hostname "$d/tor-hostname" 2>/dev/null && chown heartwood:heartwood "$d/tor-hostname"; done'
DROPIN

# --- Install heartwood binary ---
if [ -f "../target/release/heartwood-device" ]; then
    sudo cp ../target/release/heartwood-device /usr/local/bin/heartwood
    sudo chmod +x /usr/local/bin/heartwood
    echo "Installed heartwood binary"
else
    echo "Binary not found. Build with:"
    echo "  cargo build --release -p heartwood-device"
    echo "  cross build --release --target aarch64-unknown-linux-gnu -p heartwood-device"
    exit 1
fi

# --- Install bunker sidecar ---
if [ -d "../bunker" ]; then
    sudo mkdir -p /opt/heartwood/bunker
    sudo cp ../bunker/index.mjs ../bunker/lib.mjs ../bunker/package.json /opt/heartwood/bunker/
    cd /opt/heartwood/bunker && sudo npm install --omit=dev 2>/dev/null && cd -
    sudo chown -R heartwood:heartwood /opt/heartwood
    echo "Installed bunker sidecar"
fi

# --- Install template units ---
sudo cp heartwood@.service /etc/systemd/system/
sudo cp heartwood-bunker@.service /etc/systemd/system/
sudo systemctl daemon-reload
echo "Installed systemd template units"

# --- Create instance (optional) ---
if [ -n "$INSTANCE" ]; then
    echo "--- Creating instance: $INSTANCE ---"
    INST_DIR="/var/lib/heartwood/$INSTANCE"
    sudo mkdir -p "$INST_DIR"
    sudo chown heartwood:heartwood "$INST_DIR"
    sudo chmod 700 "$INST_DIR"

    if [ -n "$PORT" ]; then
        OVERRIDE_DIR="/etc/systemd/system/heartwood@${INSTANCE}.service.d"
        sudo mkdir -p "$OVERRIDE_DIR"
        cat <<EOF | sudo tee "$OVERRIDE_DIR/port.conf" >/dev/null
[Service]
Environment=HEARTWOOD_BIND=0.0.0.0:${PORT}
EOF
        echo "  Port: $PORT"
    fi

    sudo systemctl daemon-reload
    sudo systemctl enable --now "heartwood@${INSTANCE}"
    sudo systemctl enable --now "heartwood-bunker@${INSTANCE}"
    echo "  Instance $INSTANCE started"
fi

echo ""
echo "=== Heartwood installed ==="
echo ""
echo "Create instances with:"
echo "  ./setup.sh --instance personal --port 3000"
echo "  ./setup.sh --instance forgesworn --port 3001"
echo ""
echo "Or manually:"
echo "  sudo mkdir -p /var/lib/heartwood/<name>"
echo "  sudo chown heartwood:heartwood /var/lib/heartwood/<name>"
echo "  sudo systemctl enable --now heartwood@<name> heartwood-bunker@<name>"
echo ""
echo "View logs:"
echo "  sudo journalctl -u 'heartwood@*' -u 'heartwood-bunker@*' -f"
