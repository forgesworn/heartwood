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
# Allow heartwood to traverse the Tor dirs (read .onion hostname)
if [ -d /var/lib/tor ]; then
    sudo chmod 710 /var/lib/tor
fi
if [ -d /var/lib/tor/heartwood ]; then
    sudo chmod 710 /var/lib/tor/heartwood
fi

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
sudo systemctl daemon-reload
sudo systemctl enable heartwood
sudo systemctl start heartwood

echo "=== Heartwood installed ==="
echo "Check status: sudo systemctl status heartwood"
echo "View logs:    sudo journalctl -u heartwood -f"
echo ""
echo "Open http://$(hostname).local:3000 in your browser to configure."
