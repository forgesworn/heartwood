#!/usr/bin/env bash
# pi/setup.sh -- Heartwood Pi setup script
# Run on a fresh Raspberry Pi OS Lite installation.
set -euo pipefail

echo "=== Heartwood Pi Setup ==="

# Create heartwood user
sudo useradd -r -s /usr/sbin/nologin heartwood || true
sudo mkdir -p /var/lib/heartwood
sudo chown heartwood:heartwood /var/lib/heartwood
sudo chmod 700 /var/lib/heartwood

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
