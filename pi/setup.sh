#!/usr/bin/env bash
# pi/setup.sh -- Heartwood Pi setup script
# Run on a fresh Raspberry Pi OS Lite installation.
set -euo pipefail

echo "=== Heartwood Pi Setup ==="

# Create heartwood user and add to debian-tor group (for reading .onion address)
sudo useradd -r -s /usr/sbin/nologin heartwood || true
sudo usermod -aG debian-tor heartwood 2>/dev/null || true
sudo mkdir -p /var/lib/heartwood /run/heartwood
sudo chown heartwood:heartwood /var/lib/heartwood /run/heartwood
sudo chmod 700 /var/lib/heartwood
sudo chmod 700 /run/heartwood
# Install a systemd drop-in so Tor copies the .onion hostname to a path
# the heartwood user can read. Never loosen permissions on /var/lib/tor/ —
# Tor requires 0700 on hidden service directories and refuses to start otherwise.
sudo mkdir -p /etc/systemd/system/tor@default.service.d
cat <<'DROPIN' | sudo tee /etc/systemd/system/tor@default.service.d/heartwood-hostname.conf >/dev/null
[Service]
ExecStartPost=/bin/sh -c 'sleep 2 && cp /var/lib/tor/heartwood/hostname /var/lib/heartwood/tor-hostname && chown heartwood:heartwood /var/lib/heartwood/tor-hostname'
DROPIN

# Install heartwood binary
if [ -f "../target/release/heartwood-device" ]; then
    sudo cp ../target/release/heartwood-device /usr/local/bin/heartwood
    sudo chmod +x /usr/local/bin/heartwood
else
    echo "Binary not found. Build with: cargo build --release -p heartwood-device"
    echo "Or cross-compile: cross build --release --target aarch64-unknown-linux-gnu -p heartwood-device"
    exit 1
fi

# Install and enable systemd service
sudo cp heartwood.service /etc/systemd/system/

# Install bunker sidecar
if [ -d "../bunker" ]; then
    sudo mkdir -p /opt/heartwood/bunker
    sudo cp ../bunker/index.mjs ../bunker/package.json /opt/heartwood/bunker/
    cd /opt/heartwood/bunker && sudo npm install --omit=dev 2>/dev/null && cd -
    sudo chown -R heartwood:heartwood /opt/heartwood
fi
if [ -f "heartwood-bunker.service" ]; then
    sudo cp heartwood-bunker.service /etc/systemd/system/
fi

sudo systemctl daemon-reload
sudo systemctl enable heartwood
sudo systemctl start heartwood
if [ -f /etc/systemd/system/heartwood-bunker.service ]; then
    sudo systemctl enable heartwood-bunker
    sudo systemctl start heartwood-bunker
fi

echo "=== Heartwood installed ==="
echo "Check status: sudo systemctl status heartwood"
echo "Bunker:       sudo systemctl status heartwood-bunker"
echo "View logs:    sudo journalctl -u heartwood -u heartwood-bunker -f"
echo ""
echo "Open http://$(hostname).local:3000 in your browser to configure."
