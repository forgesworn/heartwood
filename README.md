# Heartwood

[![CI](https://github.com/forgesworn/heartwood/actions/workflows/ci.yml/badge.svg)](https://github.com/forgesworn/heartwood/actions/workflows/ci.yml)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/TheCryptoDonkey?logo=githubsponsors&color=ea4aaa&label=Sponsor)](https://github.com/sponsors/TheCryptoDonkey)

Open-source Nostr signing software built on [nsec-tree](https://github.com/forgesworn/nsec-tree). Runs on any cheap ARM Linux board: Raspberry Pi Zero 2 W, Orange Pi Zero, Rock Pi S, Banana Pi M2 Zero, or a repurposed Android phone running postmarketOS. Holds your master identity on a dedicated device, derives unlimited unlinkable personas, signs events via NIP-46, reachable from anywhere via Tor. Private keys never leave the device.

## What it does

- **One mnemonic, all identities.** 12 words recover everything.
- **NIP-46 remote signing.** Compatible with Nostr Connect clients across desktop and mobile.
- **Reachable over Tor by default.** Hidden service configured during install. No port forwarding, no router configuration, no IP address exposed to clients.
- **Per-client permissions.** Control which event kinds each paired app can sign.
- **Unlinkable personas.** Derive separate identities for work, personal, anon. Nobody can link them unless you prove it.

## How it compares

| | Heartwood | nsecBunker | Amber | nsec.app | LNbits NSD |
|---|:-:|:-:|:-:|:-:|:-:|
| Multi-identity from one seed | Yes | No | No | No | No |
| Inbound Tor hidden service by default | Yes | No | No | No | No |
| Per-client permissions | Yes | Yes | No | No | No |
| Works from any device/OS | Yes | Yes | Android only | Browser only | Desktop only |
| No server infrastructure | Yes | No (VPS) | Yes | Yes | Yes |
| Hardware-isolated keys | Yes | No | No | No | Yes |

## Hardware

Minimum bar: any ARMv7 or aarch64 Linux board with 256MB+ RAM and ~200MB storage. No soldering, no custom silicon, just an SD card to flash and a power supply.

Two reference targets:

| | Raspberry Pi Zero 2 W | Orange Pi Zero |
|---|:-:|:-:|
| Architecture | aarch64 (64-bit) | ARMv7 (32-bit) |
| RAM | 512MB | 256-512MB |
| Price | ~GBP 15 | ~GBP 25 |
| OS | Raspberry Pi OS Lite (64-bit) | Armbian |

Other working boards: Banana Pi M2 Zero, Rock Pi S, Le Potato, or any ARMv7/aarch64 Linux board with 256MB+ RAM. Old Android phones running postmarketOS also work.

You'll also need a micro SD card (8GB+) and a power supply for whatever board you pick. Total for a Pi Zero 2 W setup: ~GBP 24.

## Quick start

On an ARM Linux board (Raspberry Pi OS Lite, Armbian, or other Debian-based ARM Linux — Pi is the production-verified path today, Armbian and postmarketOS support is in active development):

```bash
curl -sL https://github.com/forgesworn/heartwood/releases/latest/download/install.sh | sudo bash
```

Then open `http://<hostname>.local:3000` in your browser and follow the setup wizard. See [docs/QUICKSTART.md](docs/QUICKSTART.md) for the full walkthrough.

Build from source instead:

```bash
git clone https://github.com/forgesworn/heartwood && cd heartwood
cargo build --release -p heartwood-device
cd bunker && npm install && cd ..
cd boards/pi && sudo bash setup.sh
```

## Development

```bash
cargo test                    # Run all tests (55)
cargo test -p heartwood-core  # Core crypto tests only
cargo run -p heartwood-device # Run device binary (terminal mode)
```

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full internal architecture with diagrams.

```
heartwood-core     Pure crypto: nsec-tree derivation, signing, proofs, personas
heartwood-nip46    NIP-46 protocol: method dispatch, permissions, sessions
heartwood-device   Device binary: Tor, web UI, storage, optional OLED
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
