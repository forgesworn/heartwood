# Heartwood

[![CI](https://github.com/forgesworn/heartwood/actions/workflows/ci.yml/badge.svg)](https://github.com/forgesworn/heartwood/actions/workflows/ci.yml)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/TheCryptoDonkey?logo=githubsponsors&color=ea4aaa&label=Sponsor)](https://github.com/sponsors/TheCryptoDonkey)

Open-source Nostr signing built on [nsec-tree](https://github.com/forgesworn/nsec-tree). **`heartwood-bridge` is a headless, keyless daemon**: it connects Nostr relays to a USB-tethered hardware signer, so your private keys live on dedicated hardware and never touch a networked computer. The bridge holds no key material and never sees plaintext — every operation (NIP-44 decryption, request handling, signing) happens *on the device*, inline over USB. The bridge is just the device's relay connection, and nothing more.

The hardware signer is an ESP32 running the [heartwood-esp32](https://github.com/forgesworn/heartwood-esp32) firmware. Most people configure it over USB with [Sapwood](https://sapwood.forgesworn.dev); the air-gapped, no-browser path uses the `provision` CLI. The software-only signer (keys in a browser) lives at [lite.mysignet.app](https://lite.mysignet.app), not here.

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

- **The signer** — an ESP32 running the [heartwood-esp32](https://github.com/forgesworn/heartwood-esp32) firmware. This holds the keys. Provision it over USB with [Sapwood](https://sapwood.forgesworn.dev), or offline with the `provision` CLI.
- **The bridge host** — any cheap ARMv7/aarch64 Linux board (Raspberry Pi Zero 2 W, Orange Pi Zero, or similar) with a USB port for the signer. It runs `heartwood-bridge` and holds nothing sensitive. Multi-arch binaries ship for aarch64, x86_64, armv7 and riscv64.

The bridge host only needs a USB port and an outbound network connection — no display, no inbound ports.

## Quick start

Install the bridge on your Linux/Pi box (systemd service):

```bash
curl -sL https://github.com/forgesworn/heartwood/releases/latest/download/install.sh | sudo bash
```

Point it at your USB signer and start it:

```bash
# in /etc/systemd/system/heartwood-bridge.service (or via Docker -e):
#   Environment=HEARTWOOD_SERIAL_PORT=/dev/ttyUSB0
sudo systemctl start heartwood-bridge
```

The `bridge.secret` is provisioned onto the box over USB (Sapwood or the `provision` CLI) before first start. See [docs/QUICKSTART.md](docs/QUICKSTART.md) for the full walkthrough, including Docker.

Build from source instead:

```bash
git clone https://github.com/forgesworn/heartwood && cd heartwood
cargo build --release -p heartwood-bridge
```

## Development

```bash
cargo test                     # Run all tests
cargo test -p heartwood-core   # Core derivation tests only
cargo run -p heartwood-bridge -- --help
```

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full internal architecture with diagrams.

```
heartwood-bridge   The product: headless, keyless relay-to-USB signing daemon
heartwood-frame    Serial frame codec (magic/type/len/CRC-32), pinned to the firmware's wire format
heartwood-core     nsec-tree derivation primitive (nsec-tree-rs) — standalone reference library
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
