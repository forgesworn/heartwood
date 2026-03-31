# Heartwood Developer Quickstart

Heartwood is a Nostr signing appliance that runs on a Raspberry Pi. It holds your nsec on the device, serves a local web UI for configuration, and acts as a NIP-46 remote signer (bunker) so your private key never leaves the Pi.

## Requirements

- Raspberry Pi with 1 GB+ RAM (tested on Pi 5; any model running 64-bit OS works)
- Raspberry Pi OS Bookworm (64-bit)
- Rust toolchain (stable, via rustup)
- Node.js >= 20

## Build

Install the Rust toolchain if you haven't already:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

Clone the repo and build:

```bash
git clone https://github.com/forgesworn/heartwood.git
cd heartwood
cargo build --release -p heartwood-device
```

Install the bunker sidecar dependencies:

```bash
cd bunker
npm install
```

If you are cross-compiling from another machine, use `cross`:

```bash
cargo install cross
cross build --release --target aarch64-unknown-linux-gnu -p heartwood-device
```

## Install

The quickest path is the setup script. Run it from the `pi/` directory on the Pi:

```bash
cd pi
sudo bash setup.sh
```

This creates a `heartwood` system user, copies the binary to `/usr/local/bin/heartwood`, installs the systemd unit, and starts the service.

### Manual installation

If you prefer to do it by hand:

```bash
# Create the heartwood user and data directory
sudo useradd -r -s /usr/sbin/nologin heartwood
sudo mkdir -p /var/lib/heartwood
sudo chown heartwood:heartwood /var/lib/heartwood
sudo chmod 700 /var/lib/heartwood

# Copy the binary
sudo cp target/release/heartwood-device /usr/local/bin/heartwood
sudo chmod +x /usr/local/bin/heartwood

# Install systemd units
sudo cp pi/heartwood.service /etc/systemd/system/
sudo cp pi/heartwood-bunker.service /etc/systemd/system/

# Copy the bunker sidecar
sudo mkdir -p /opt/heartwood/bunker
sudo cp -r bunker/* /opt/heartwood/bunker/

# Enable and start the web UI service
sudo systemctl daemon-reload
sudo systemctl enable heartwood
sudo systemctl start heartwood
```

## Configure

Open the web UI in a browser:

```
http://<hostname>.local:3000
```

Replace `<hostname>` with your Pi's hostname (e.g. `heartwood.local:3000`).

1. Select **Bunker** mode.
2. Paste your nsec (starts with `nsec1...`).
3. Review the relay list. Defaults are `wss://relay.damus.io`, `wss://relay.nostr.band`, `wss://nos.lol`, and `wss://relay.trotters.cc`. Add or remove relays as needed.
4. Set a password to protect the web UI.

## Start the Bunker

Enable and start the bunker sidecar:

```bash
sudo systemctl enable heartwood-bunker
sudo systemctl start heartwood-bunker
```

The bunker writes a `bunker://` URI to `/var/lib/heartwood/bunker-uri.txt` on startup. You can also retrieve it from the web UI or the API:

```bash
curl http://localhost:3000/api/bunker
```

## Connect a Client

Copy the `bunker://` URI and paste it into any NIP-46 client:

- **Amethyst** -- Settings > External Signer > Paste bunker URI
- **NostrHub** -- Login > Remote signer > Paste URI
- Any app that supports NIP-46 `bunker://` URIs

The client sends signing requests to Nostr relays. The bunker decrypts them with NIP-44, signs with your nsec, and returns the signed event. Your private key stays on the Pi.

## Verify

Check both services are running:

```bash
sudo systemctl status heartwood
sudo systemctl status heartwood-bunker
```

Tail the logs:

```bash
sudo journalctl -u heartwood -f
sudo journalctl -u heartwood-bunker -f
```

The bunker logs each signing request and response. You should see `Request <id>: sign_event` entries when a client asks for a signature.

## Security Notes

- **Set a password.** Without one, anyone on your local network can access the web UI and your nsec.
- **The nsec never leaves the device.** Only signatures and public keys are sent over relays. The bunker sidecar reads the nsec from `/var/lib/heartwood/master.secret` and holds it in memory; the file is mode 0700 and owned by the `heartwood` user.
- **Systemd hardening is on by default.** Both services run with `ProtectSystem=strict`, `NoNewPrivileges=true`, `PrivateTmp=true`, and restricted capabilities.
- **Consider Tor for remote access.** If you need to reach the web UI outside your LAN, configure a Tor hidden service rather than exposing port 3000 directly. See `pi/torrc` for the hidden service configuration.
- **No client allowlist yet.** Any Nostr user can send signing requests to your bunker. This is acceptable for personal use but be aware of it.
