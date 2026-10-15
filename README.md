# Heartwood

[![CI](https://github.com/forgesworn/heartwood/actions/workflows/ci.yml/badge.svg)](https://github.com/forgesworn/heartwood/actions/workflows/ci.yml)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/TheCryptoDonkey?logo=githubsponsors&color=ea4aaa&label=Sponsor)](https://github.com/sponsors/TheCryptoDonkey)

Open-source Nostr signing built on [nsec-tree](https://github.com/forgesworn/nsec-tree). **`heartwood-bridge` is a headless, keyless daemon**: it connects Nostr relays to a USB-tethered hardware signer, so your private keys live on dedicated hardware and never touch a networked computer. The bridge holds no key material and never sees plaintext — every operation (NIP-44 decryption, request handling, signing) happens *on the device*, inline over USB. The bridge is just the device's relay connection, and nothing more.

The hardware signer is an ESP32 running the [heartwood-esp32](https://github.com/forgesworn/heartwood-esp32) firmware, or a Ledger running the [heartwood-ledger](https://github.com/forgesworn/heartwood-ledger) app (emulator-proven; select with `HEARTWOOD_TRANSPORT=ledger-tcp|ledger-hid` — same identity, same seed phrase, keys in a secure element). Most people configure the ESP over USB with [Sapwood](https://sapwood.forgesworn.dev); the air-gapped, no-browser path uses the `provision` CLI. The software-only signer (keys in a browser) lives at [lite.mysignet.app](https://lite.mysignet.app), not here.

## What it does

- **Keys stay on hardware, always.** The bridge is a dumb pipe — no seed, no PIN, no plaintext ever lives on the Linux box.
- **NIP-46 remote signing.** Compatible with Nostr Connect clients across desktop and mobile; the device answers, the bridge relays.
- **Reachable from anywhere, no open ports.** NIP-46 is relay-mediated: the bridge connects *out* to Nostr relays, so there's no port forwarding, no inbound listener, and your IP is never exposed to client apps.
- **Per-client permissions.** Control which event kinds each paired app can sign — enforced on the device.
- **Unlinkable personas.** One seed on the device derives unlimited separate identities (work, personal, anon). Nobody can link them unless you prove it.

## How it compares

| | Heartwood | nsecBunker | Amber | nsec.app | LNbits NSD |
|---|:-:|:-:|:-:|:-:|:-:|
| Multi-identity from one seed | Yes | No | No | No | No |
| Relay-mediated, no inbound listener | Yes | Yes | Yes | Yes | No |
| Per-client permissions | Yes | Yes | No | No | No |
| Works from any device/OS | Yes | Yes | Android only | Browser only | Desktop only |
| No server infrastructure | Yes | No (VPS) | Yes | Yes | Yes |
| Hardware-isolated keys | Yes | No | No | No | Yes |

## Hardware

Two pieces:

- **The signer**: holds the keys. One of:
  - an **ESP32** running the [heartwood-esp32](https://github.com/forgesworn/heartwood-esp32) firmware (the default `serial` transport). Provision it over USB with [Sapwood](https://sapwood.forgesworn.dev), or offline with the `provision` CLI (see [Provisioning](#provisioning)).
  - a **Ledger** running the [heartwood-ledger](https://github.com/forgesworn/heartwood-ledger) app, selected with `HEARTWOOD_TRANSPORT=ledger-tcp` (APDUs over TCP, to the Speculos emulator or a TCP-to-HID proxy) or `HEARTWOOD_TRANSPORT=ledger-hid` (a physical Ledger over Linux hidraw). Ledger transports use no `bridge.secret`: the Ledger authenticates its user and approves signing on the device. Real-device status: `ledger-tcp` is proven end to end against the emulator only. `ledger-hid` is implemented and its USB framing is unit-tested, but it has not been verified on a physical Ledger yet, so treat real Ledger hardware as untested.
- **The bridge host** — any cheap ARMv7/aarch64 Linux board (Raspberry Pi Zero 2 W, Orange Pi Zero, or similar) with a USB port for the signer. It runs `heartwood-bridge` and holds nothing sensitive. Multi-arch binaries ship for aarch64, x86_64, armv7 and riscv64.

The bridge host only needs a USB port and an outbound network connection — no display, no inbound ports.

## Quick start

### 1. Install

Install the bridge on your Linux/Pi box (systemd service):

```bash
curl -sL https://github.com/forgesworn/heartwood/releases/latest/download/install.sh | sudo bash
```

The installer creates the `heartwood` service user, `/var/lib/heartwood` (mode 0700) and an enabled but not started `heartwood-bridge` unit. It fills `HEARTWOOD_SERIAL_PORT` from the first `/dev/ttyUSB*` or `/dev/ttyACM*` device it finds, else `/dev/ttyUSB0`.

### 2. Configure

Set the serial port and, optionally, the relays in a systemd drop-in. Re-running the installer rewrites the unit file itself, but a drop-in survives that.

```bash
sudo systemctl edit heartwood-bridge
```

In the editor, add:

```ini
[Service]
Environment=HEARTWOOD_SERIAL_PORT=/dev/ttyUSB0
Environment=HEARTWOOD_RELAYS=wss://relay.damus.io,wss://nos.lol
```

`HEARTWOOD_RELAYS` is comma-separated. If it is unset (and `config.json` has no `relays`), the bridge falls back to the built-in `DEFAULT_RELAYS` list in `crates/heartwood-bridge/src/config.rs`. All settings are listed under [Configuration](#configuration).

### 3. Provision

For an ESP32, put `bridge.secret` in the data directory before first start. See [Provisioning](#provisioning).

### 4. Start

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now heartwood-bridge
sudo systemctl status heartwood-bridge
```

### 5. Pair a client

A client pairs with the signer by pasting a `bunker://` connection string. There are three places to get it:

- **Sapwood** shows it for each identity on the device.
- **The running bridge** logs it at startup, one line per master identity:

  ```bash
  sudo journalctl -u heartwood-bridge | grep 'client connection string'
  ```

- **`heartwood-bridge --bunker-uri`** connects to the signer once, prints one string per master identity and exits, without connecting to any relay. This is the route for the offline `provision` path, where Sapwood is never used. It reads the same configuration as the service, and the string embeds the relays it finds, so give it the same `HEARTWOOD_*` values as the service (or keep them in `config.json`, which both read):

  ```bash
  sudo -u heartwood env HEARTWOOD_SERIAL_PORT=/dev/ttyUSB0 \
    HEARTWOOD_RELAYS=wss://relay.damus.io,wss://nos.lol heartwood-bridge --bunker-uri
  ```

The string has the form `bunker://<master-pubkey-hex>?relay=<url>&relay=<url>`, with each relay URL percent-encoded. It carries no `secret` parameter. Which clients may connect, and what each may sign, is enforced on the signer.

### Docker instead of systemd

The multi-arch image (amd64, arm64, armv7) is `ghcr.io/forgesworn/heartwood`. Pass the USB device through and mount the data directory:

```bash
docker run -d --name heartwood-bridge --restart unless-stopped \
  --device /dev/ttyUSB0 \
  -e HEARTWOOD_SERIAL_PORT=/dev/ttyUSB0 \
  -e HEARTWOOD_RELAYS=wss://relay.damus.io,wss://nos.lol \
  -v /var/lib/heartwood:/var/lib/heartwood \
  ghcr.io/forgesworn/heartwood:<version>
```

Replace `<version>` with a release version (without the leading `v`; see the [package page](https://github.com/forgesworn/heartwood/pkgs/container/heartwood)) or use `main` for the latest main-branch build. Provision `bridge.secret` into the mounted directory as described below. See [docs/QUICKSTART.md](docs/QUICKSTART.md) for the full walkthrough.

### Provisioning

The signer's keys and the shared `bridge.secret` are written over USB by tools that live outside this repo:

- **[Sapwood](https://sapwood.forgesworn.dev)**: browser-based (Web Serial), the normal path.
- **`provision` CLI**: the offline, no-browser path. It lives in the [heartwood-esp32](https://github.com/forgesworn/heartwood-esp32) repo; its build and usage instructions are there, not here.

Both produce a `bridge.secret` file on the machine they run on. The bridge reads `<HEARTWOOD_DATA_DIR>/bridge.secret` at startup, as 64 hex characters (whitespace ignored) or exactly 32 raw bytes, and will not start without it. If you provisioned on another machine, copy the file across and install it with `0600` permissions, owned by the user that runs the bridge:

```bash
# systemd service (runs as the heartwood user)
sudo install -m 0600 -o heartwood -g heartwood bridge.secret /var/lib/heartwood/bridge.secret

# Docker (the image runs as uid 10001)
sudo install -m 0600 -o 10001 bridge.secret /var/lib/heartwood/bridge.secret
```

`bridge.secret` authenticates the USB session only; it is not a signing key. Ledger transports do not use it.

## Configuration

The bridge takes no arguments apart from `--version`, `--help` and `--bunker-uri`. Everything else comes from the environment or a `config.json` in the data directory (`{ "transport": "serial", "serial_port": "/dev/ttyUSB0", "relays": ["wss://relay.damus.io"] }`). An environment variable wins over `config.json`, and a missing or malformed `config.json` is ignored.

| Variable | Default | Description |
|----------|---------|-------------|
| `HEARTWOOD_SERIAL_PORT` | none (required) | Signer address. A serial device path such as `/dev/ttyUSB0` for `serial`; `host:port` for `ledger-tcp`; `/dev/hidrawN`, or `auto` to pick the first Ledger hidraw node, for `ledger-hid`. `config.json` key: `serial_port`. Without it the bridge exits with `no serial port configured` |
| `HEARTWOOD_TRANSPORT` | `serial` | `serial` (ESP32 over USB), `ledger-tcp` or `ledger-hid` (Ledger). `config.json` key: `transport`. Any other value fails with `unknown transport` |
| `HEARTWOOD_DATA_DIR` | `/var/lib/heartwood` | Directory holding `config.json` and `bridge.secret` |
| `HEARTWOOD_RELAYS` | built-in `DEFAULT_RELAYS` | Comma-separated relay URLs, e.g. `wss://relay.damus.io,wss://nos.lol`. `config.json` key: `relays` |

## Build from source

```bash
git clone https://github.com/forgesworn/heartwood && cd heartwood
cargo build --release -p heartwood-bridge
```

## Development

```bash
cargo test                     # Run all tests
cargo test -p nsec-tree-rs     # Core derivation tests only (crates/heartwood-core)
cargo run -p heartwood-bridge -- --help
```

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full internal architecture with diagrams.

```
heartwood-bridge   The product: headless, keyless relay-to-USB signing daemon
heartwood-frame    Serial frame codec (magic/type/len/CRC-32), pinned to the firmware's wire format
heartwood-core     nsec-tree derivation primitive (Cargo package nsec-tree-rs, on crates.io), standalone reference library
```

## Ecosystem

See [docs/ECOSYSTEM.md](docs/ECOSYSTEM.md) for the full ecosystem overview with cross-cutting diagrams.

Part of the [ForgeSworn](https://github.com/forgesworn) open-source ecosystem:

- [nsec-tree](https://github.com/forgesworn/nsec-tree) -- Deterministic identity derivation (TypeScript reference)
- [shamir-words](https://github.com/forgesworn/shamir-words) -- Mnemonic threshold backup
- [canary-kit](https://github.com/forgesworn/canary-kit) -- Dead man's switch
- [toll-booth](https://github.com/forgesworn/toll-booth) -- L402 API payments
- [bark](https://github.com/forgesworn/bark) -- Browser extension for NIP-07 signing via Heartwood
- [bray](https://github.com/forgesworn/bray) -- Nostr MCP server

## Part of the ForgeSworn Toolkit

[ForgeSworn](https://forgesworn.dev) builds open-source cryptographic identity, payments, and coordination tools for Nostr.

| Library | What it does |
|---------|-------------|
| [nsec-tree](https://github.com/forgesworn/nsec-tree) | Deterministic sub-identity derivation |
| [ring-sig](https://github.com/forgesworn/ring-sig) | SAG/LSAG ring signatures on secp256k1 |
| [range-proof](https://github.com/forgesworn/range-proof) | Pedersen commitment range proofs |
| [canary-kit](https://github.com/forgesworn/canary-kit) | Coercion-resistant spoken verification |
| [spoken-token](https://github.com/forgesworn/spoken-token) | Human-speakable verification tokens |
| [toll-booth](https://github.com/forgesworn/toll-booth) | L402 payment middleware |
| [geohash-kit](https://github.com/forgesworn/geohash-kit) | Geohash toolkit with polygon coverage |
| [nostr-attestations](https://github.com/forgesworn/nostr-attestations) | NIP-VA verifiable attestations |
| [dominion](https://github.com/forgesworn/dominion) | Epoch-based encrypted access control |
| [nostr-veil](https://github.com/forgesworn/nostr-veil) | Privacy-preserving Web of Trust |

## Licence

MIT
