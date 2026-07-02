# Run Your Own Heartwood

A step-by-step guide to running `heartwood-bridge` — the headless daemon that
connects Nostr relays to a USB-tethered hardware signer.

Heartwood no longer keeps any key material on your Linux box. The private
key lives only on a hardware signer (an ESP32 running the `heartwood-esp32`
firmware, plugged in over USB). The bridge is a keyless relay client: it
listens on Nostr relays for NIP-46 requests, forwards them over USB to the
signer, and republishes whatever the signer signs. It runs no web server and
opens no inbound ports.

## What you need

- A **hardware signer** — an ESP32 (or ESP8266) running the `heartwood-esp32`
  firmware, with its keys already provisioned (see Step 1)
- A **USB cable** to tether the signer to the box that will run the bridge
- A **Linux box** to run the bridge — a Raspberry Pi or any aarch64, x86_64,
  armv7, or riscv64 Linux machine
- A **browser**, if you're provisioning with Sapwood (the normal path)

## Step 1: Provision the signer's keys

Keys are generated (or restored) directly on the hardware signer — never on
the Linux box, never in a browser tab that touches the network. There are
two ways to do this:

**Sapwood (recommended)** — the normal path for almost everyone. Plug the
signer into a computer over USB, open [sapwood.forgesworn.dev](https://sapwood.forgesworn.dev)
in a Web-Serial-capable browser (Chrome or Edge), and follow the
provisioning wizard. This writes your master identity into the signer's own
storage and also writes a `bridge.secret` file — a shared session secret,
paired between the device and the bridge. You'll need this file in Step 3.

**`provision` CLI (air-gapped / high-security path)** — for anyone who wants
to provision entirely offline, without a browser. It lives in the
[`heartwood-esp32`](https://github.com/forgesworn/heartwood-esp32) repo, run
against the signer over USB on a machine with no network connection. It has
the same effect as the Sapwood wizard: keys onto the device, a `bridge.secret`
file onto your disk.

Either way, keep the resulting `bridge.secret` file — you'll copy it onto the
bridge's data directory before first start.

## Step 2: Install `heartwood-bridge`

On the Linux box that will stay tethered to the signer, pick one of:

**Install script** (installs a systemd service):

```bash
curl -sL https://github.com/forgesworn/heartwood/releases/latest/download/install.sh | sudo bash
```

This detects your architecture (aarch64, x86_64, armv7, or riscv64),
downloads the matching release binary, verifies its SHA-256 checksum,
creates a `heartwood` system user in the `dialout` group (for USB serial
access), creates `/var/lib/heartwood`, and installs (and enables, but does
not start) a `heartwood-bridge` systemd service. If it finds a
`/dev/ttyUSB*` or `/dev/ttyACM*` device already plugged in, it fills that in
as the serial port automatically.

**Docker** (multi-arch image, amd64/arm64/armv7):

```bash
docker pull ghcr.io/forgesworn/heartwood:<version>
```

Replace `<version>` with a released version tag (see the
[package page](https://github.com/forgesworn/heartwood/pkgs/container/heartwood))
or use `main` for the latest main-branch build.

## Step 3: Put the bridge secret in place

Copy the `bridge.secret` file from Step 1 into the bridge's data directory
(default `/var/lib/heartwood`, override with `HEARTWOOD_DATA_DIR`):

```bash
sudo cp bridge.secret /var/lib/heartwood/bridge.secret
sudo chown heartwood:heartwood /var/lib/heartwood/bridge.secret
sudo chmod 600 /var/lib/heartwood/bridge.secret
```

For Docker, bind-mount a host directory as the data dir so the same copy
works:

```bash
sudo mkdir -p /var/lib/heartwood
sudo cp bridge.secret /var/lib/heartwood/bridge.secret
```

## Step 4: Configure the serial port and relays

The bridge needs to know which serial device the signer enumerates on, and
which relays to use. Set these with:

- **Environment variables** — `HEARTWOOD_SERIAL_PORT` (e.g. `/dev/ttyUSB0`)
  and, optionally, `HEARTWOOD_RELAYS` (comma-separated relay URLs)
- **`config.json`** in the data directory:

  ```json
  {
    "serial_port": "/dev/ttyUSB0",
    "relays": ["wss://relay.damus.io", "wss://nos.lol"]
  }
  ```

If installed via the install script, edit the `Environment=` lines in
`/etc/systemd/system/heartwood-bridge.service`:

```bash
sudo nano /etc/systemd/system/heartwood-bridge.service
# adjust Environment=HEARTWOOD_SERIAL_PORT=... and add
# Environment=HEARTWOOD_RELAYS=wss://relay.damus.io,wss://nos.lol
sudo systemctl daemon-reload
```

If running under Docker, pass the USB device through and set the same
variables with `-e`:

```bash
docker run -d --name heartwood-bridge --restart unless-stopped \
  --device=/dev/ttyUSB0 \
  -e HEARTWOOD_SERIAL_PORT=/dev/ttyUSB0 \
  -e HEARTWOOD_RELAYS=wss://relay.damus.io,wss://nos.lol \
  -v /var/lib/heartwood:/var/lib/heartwood \
  ghcr.io/forgesworn/heartwood:<version>
```

`HEARTWOOD_SERIAL_PORT` is required — the bridge has nothing to talk to
without it. `HEARTWOOD_RELAYS` is optional; if you don't set it (via env or
`config.json`), the bridge falls back to a small default relay set.

## Step 5: Start the bridge

```bash
sudo systemctl start heartwood-bridge
sudo systemctl status heartwood-bridge
sudo journalctl -u heartwood-bridge -f
```

On start, the bridge opens the serial port, authenticates the session with
`bridge.secret`, asks the signer which master identities it holds, and then
subscribes to your configured relays for NIP-46 requests addressed to those
identities. Once you see log lines about relays connecting and the device
reporting its masters, it's ready. There's nothing to unlock — the daemon
has no key of its own to protect.

## Step 6: Connect a Nostr app

Which clients are trusted, and what each is allowed to sign, is a policy the
signer itself enforces — configure it via Sapwood, not on the Linux box.

1. In Sapwood, find the `bunker://` connection string for the identity you
   want to use
2. Open your Nostr client (Bark, Amethyst, etc.) and choose "Login with
   bunker" / "NIP-46 / Nostr Connect"
3. Paste the connection string
4. Approve the first connection on the signer itself, per the policy you set
   in Sapwood

The client then talks to relays as normal; the bridge relays each request to
the signer and republishes the signed response. Your key never leaves the
device.

## Updating

**Install script:** re-run it — it downloads the latest binary and restarts
the service, preserving your data directory:

```bash
curl -sL https://github.com/forgesworn/heartwood/releases/latest/download/install.sh | sudo bash
```

**Docker:** pull the new tag and recreate the container:

```bash
docker pull ghcr.io/forgesworn/heartwood:<new-version>
docker stop heartwood-bridge && docker rm heartwood-bridge
# re-run the docker run command from Step 4 with the new tag
```

## Troubleshooting

**Service won't start / logs show a `bridge.secret` error?**
- The bridge reads `bridge.secret` from the data directory at startup; if
  it's missing you'll see an error naming the expected path. Re-copy it from
  Step 3 and make sure the `heartwood` user can read it.

**Logs show "no serial port configured"?**
- Set `HEARTWOOD_SERIAL_PORT` (env or `config.json`) as in Step 4.

**Signer not found on the expected `/dev/ttyUSB*` or `/dev/ttyACM*` device?**
- List what's plugged in: `ls /dev/ttyUSB* /dev/ttyACM* 2>/dev/null`
- Confirm the service account is in the `dialout` group:
  `groups heartwood`

**Not sure the binary installed correctly?**
- `heartwood-bridge --version` and `heartwood-bridge --help` both work
  without a serial port or relay connection — useful as a first sanity
  check.

**Client stuck waiting for a signature?**
- Check the bridge is running and connected: `sudo systemctl status heartwood-bridge`
- Tail the logs for relay/serial errors: `sudo journalctl -u heartwood-bridge -f`
- Confirm the signer is powered on and still tethered over USB — the bridge
  reconnects and re-authenticates automatically if the serial connection
  drops, but it can't sign anything while the signer is unplugged

## Build from source

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Clone and build
git clone https://github.com/forgesworn/heartwood.git
cd heartwood
cargo build --release -p heartwood-bridge
```

Cross-compile for another architecture from your own machine:

```bash
cargo install cross
cross build --release --target aarch64-unknown-linux-gnu -p heartwood-bridge
```

## Security notes

- **No key material on the Linux box, ever.** `heartwood-bridge` forwards
  NIP-44 ciphertext to the signer and republishes whatever signed event
  comes back; it never sees a private key or plaintext request content.
- **`bridge.secret` is not a signing key.** It authenticates the USB session
  between the bridge and the signer — nothing more. Treat the file as a
  local secret (mode `0600`).
- **No inbound network ports.** The bridge only makes outbound connections
  to relays; there is no port to forward and no IP address exposed to
  client apps.
- **Policy enforcement lives on the signer**, not the bridge — NIP-44
  integrity, per-client kind restrictions, rate limits, and connection
  approval are all the device's job. The bridge only de-duplicates request
  ids across relays so it doesn't submit the same request twice.
