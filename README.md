# Heartwood

Open-source Nostr signing software built on [nsec-tree](https://github.com/forgesworn/nsec-tree). Runs on a Raspberry Pi. Holds your master identity in hardware, derives unlimited unlinkable personas, signs events via NIP-46, reachable from anywhere via Tor. Private keys never leave the device.

## What it does

- **One mnemonic, all identities.** 12 words recover everything.
- **NIP-46 remote signing.** Works with every Nostr client that supports Nostr Connect.
- **Tor by default.** No clearnet exposure. No router configuration.
- **Per-client permissions.** Control which event kinds each paired app can sign.
- **Unlinkable personas.** Derive separate identities for work, personal, anon. Nobody can link them unless you prove it.

## Hardware

Runs on any Raspberry Pi (Pi 4 for development, Pi Zero 2 W for dedicated deployment).

| Item | Price |
|------|-------|
| Raspberry Pi Zero 2 W | ~GBP 15 |
| Micro SD card (8GB+) | ~GBP 4 |
| USB-C power supply | ~GBP 5 |
| **Total** | **~GBP 24** |

No soldering. No custom hardware. Flash an SD card and go.

## Quick start

```bash
# On a fresh Raspberry Pi OS Lite
git clone https://github.com/forgesworn/heartwood
cd heartwood
cargo build --release -p heartwood-device
cd pi && bash setup.sh
```

Wait ~60 seconds for Tor, then:

```bash
sudo cat /var/lib/tor/heartwood/hostname
```

Scan the .onion address with your Nostr client to pair.

## Development

```bash
cargo test                    # Run all tests (40+)
cargo test -p heartwood-core  # Core crypto tests only
cargo run -p heartwood-device # Run device binary (terminal mode)
```

## Architecture

```
heartwood-core     Pure crypto: nsec-tree derivation, signing, proofs, personas
heartwood-nip46    NIP-46 protocol: method dispatch, permissions, sessions
heartwood-device   Device binary: Tor, web UI, storage, OLED
```

## Ecosystem

Part of the [ForgeSworn](https://github.com/forgesworn) open-source ecosystem:

- [nsec-tree](https://github.com/forgesworn/nsec-tree) -- Deterministic identity derivation (TypeScript reference)
- [shamir-words](https://github.com/forgesworn/shamir-words) -- Mnemonic threshold backup
- [canary-kit](https://github.com/forgesworn/canary-kit) -- Dead man's switch
- [toll-booth](https://github.com/forgesworn/toll-booth) -- L402 API payments
- [bray](https://github.com/forgesworn/bray) -- Nostr MCP server

## Licence

MIT
