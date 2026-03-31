# Heartwood -- Hardware Signing Appliance for nsec-tree

**Date:** 2026-03-31
**Status:** Design
**Repo:** https://github.com/forgesworn/heartwood

## Overview

Heartwood is a ~GBP 32 open-source signing appliance that turns nsec-tree's deterministic identity model into plug-and-play hardware. It holds a master secret on a Raspberry Pi Zero 2 W, derives unlimited unlinkable Nostr identities, signs events via NIP-46 remote signing, and is reachable from anywhere via Tor. Private keys never leave the device. The only human-readable secret is a 12-word mnemonic displayed on the device's OLED screen.

Heartwood serves two audiences simultaneously:

1. **Nostr power users today** -- replaces nsecBunker VPSes, eliminates nsec pasting, provides hardware-backed multi-persona signing with Tor by default. Works with every existing NIP-46 client.
2. **RenegAid normies tomorrow** -- as users of Fathom, Heritage, Goer, and other RenegAid platforms accumulate identity value, Heartwood is the upgrade path. Signet handles identity portability; Heartwood holds the keys.

## Problems Solved

### Documented community pain points

| Problem | Evidence | Heartwood answer |
|---------|----------|-----------------|
| Key management is the #1 adoption blocker | Bitcoin Magazine, Nasdaq, hodlbod long-form, Stacker News threads | One mnemonic recovers all identities deterministically |
| Nsec pasting into web apps | Universal complaint, clipboard hijacking, XSS, supply chain risk | Keys never leave the device. NIP-46 remote signing. |
| No iOS signer | Amber is Android-only, nsec.app is a browser workaround | Platform-agnostic. Any NIP-46 client on any OS connects. |
| Relay public-key substitution attacks | Academic paper (Kimura et al., 2025, ePrint 2025/1459) | Events signed on-device. Relays cannot re-sign. |
| Multiple identities = multiple backups | No good solution exists | One backup recovers everything. Unlimited personas from one seed. |
| No key rotation on Nostr | Fundamental protocol limitation | Derive new child, publish linkage proof. Practical rotation with provenance. |
| Remote signers need always-on infrastructure | nsecBunker requires a VPS | Heartwood IS the infrastructure. GBP 32 box, plugged into a router. |
| Home network complexity (mDNS, VLANs, NAT) | Common user complaint with local-network devices | Tor by default. `.onion` address works from anywhere, any network. No router config. |

### What no other device offers

- **Unlinkable-by-default multi-identity from hardware.** The LNbits NSD is one-key-one-device. Bitcoin hardware wallets think in addresses, not personas.
- **Tor by default.** No clearnet exposure. No IP address. No port forwarding.
- **Per-client kind permissions.** Not just "can this client sign" but "this client can sign kind-1 notes but NOT kind-0 profile updates."
- **Migration proofs.** Existing Nostr users create a fresh hardware identity and prove the link to their old npub without ever exposing an nsec.

## Hardware

### Bill of Materials

| Item | Purpose | Price |
|------|---------|-------|
| Raspberry Pi Zero 2 W | Compute, Tor, signing | ~GBP 15 |
| Micro SD card (8GB+) | OS + firmware | ~GBP 4 |
| SSD1306 0.96" OLED (I2C, 4-pin) | Mnemonic display, QR codes, status | ~GBP 5 |
| USB-C power supply | Power | ~GBP 5 |
| Ethernet cable (optional) | Wired network | ~GBP 3 |

**Total: ~GBP 32.** No soldering required. OLED connects to GPIO header via female-to-female jumper wires (I2C: SDA, SCL, VCC, GND).

### Why Pi Zero 2 W

- **Tor runs natively.** C Tor uses ~23MB RAM; the Pi has 512MB. No companion device needed.
- **Rust runs natively.** Standard `aarch64-unknown-linux-gnu` target. No embedded toolchain, no `no_std`, no cross-compilation.
- **Single board, single SD image.** Flash and go. The normie experience.
- **Dev speed.** Prototype on a Mac, deploy to Pi. No JTAG, no flash tools.
- **The community knows it.** Every Nostr dev has a Pi. "Flash this SD card" is universally understood.

### Connectivity

- **Ethernet** via USB gadget mode or USB-to-Ethernet adapter
- **WiFi** built-in (2.4GHz), configurable during SD flash
- **Tor** is the default and expected transport. `.onion` address generated on first boot.
- **Local network** available for initial setup and as a fallback, disabled by default in production mode

## Architecture

```
+-----------------------------------------+
|          Web UI (Preact SPA)            |  Setup, persona management, audit log
+-----------------------------------------+
|        NIP-46 Server (Rust)             |  Standard + Heartwood extensions
+-----------------------------------------+
|        nsec-tree Core (Rust)            |  Derivation, signing, proofs, personas
+-----------------------------------------+
|           Tor (C Tor daemon)            |  Hidden service, .onion address
+-----------------------------------------+
|      Linux (Raspberry Pi OS Lite)       |  LUKS encryption, OLED driver, mDNS
+-----------------------------------------+
```

### nsec-tree Core (Rust)

A faithful port of the TypeScript nsec-tree library to Rust:

- `k256` crate for secp256k1 (Schnorr BIP-340 + ECDSA)
- `hmac` + `sha2` crates for HMAC-SHA256 derivation
- `zeroize` crate for deterministic secret cleanup on drop
- `bip32` + `bip39` crates for mnemonic path (`m/44'/1237'/727'/0'/0'`)
- Must pass all frozen test vectors from the TypeScript implementation
- Private key material stays in this layer, never exposed upward

### NIP-46 Server (Rust)

**Standard NIP-46 methods** (works with any existing Nostr client):

| Method | Description |
|--------|-------------|
| `get_public_key` | Returns the active identity's npub |
| `sign_event` | Signs a Nostr event, returns signature |
| `nip44_encrypt` / `nip44_decrypt` | NIP-44 encryption |
| `nip04_encrypt` / `nip04_decrypt` | NIP-04 legacy support |

**Heartwood extension methods** (for clients that understand nsec-tree):

| Method | Description |
|--------|-------------|
| `heartwood_derive` | Derive a child identity by purpose + index |
| `heartwood_derive_persona` | Named persona derivation (two-level hierarchy) |
| `heartwood_list_identities` | List all derived identities and personas |
| `heartwood_switch` | Switch active signing identity |
| `heartwood_create_proof` | Generate blind or full linkage proof |
| `heartwood_verify_proof` | Verify a linkage proof |
| `heartwood_recover` | Scan and recover identities for given purposes |

`heartwood_switch` changes which identity responds to standard NIP-46 calls. A user switches persona and their regular Nostr client works with the new identity without reconfiguration.

### Web UI

- Tiny SPA served from the Pi (Preact or vanilla JS, under 100KB gzipped)
- Communicates with firmware over local REST API
- HTTPS with self-signed certificate
- No external dependencies, no CDN, no phoning home
- Features: setup wizard, persona management, client permissions, audit log, Tor settings

### Tor

- C Tor daemon, auto-configured on first boot
- Hidden service generated automatically
- `.onion` address displayed on OLED as QR code for pairing
- All NIP-46 traffic routed through Tor by default
- Local network access available but disabled by default

## Security Model

### Threat mitigations

| Threat | Mitigation |
|--------|-----------|
| Key extraction from storage | LUKS full-disk encryption (AES-256), unlocked by PIN on boot |
| Key extraction from memory | Rust `zeroize` crate wipes secrets from RAM on drop |
| Network eavesdropping | NIP-46 messages are NIP-44 encrypted end-to-end. Tor hides transport. |
| Rogue client signing | NIP-46 auth requires shared secret established during QR pairing |
| Physical theft | Without PIN, device won't unlock. LUKS protects data at rest. |
| Compromised child key | Blast radius is one identity. Derive new child, publish linkage proof. |
| Compromised master | Generate new mnemonic, migrate via linkage proofs. |
| Firmware tampering | Reproducible builds, signed releases, sha256 checksums |
| Coercion / duress | Duress PIN triggers decoy persona + silent wipe of real master |

### Security features

| Layer | Features |
|-------|----------|
| Physical | LUKS encryption at rest, PIN to unlock on boot |
| Network | Tor by default, NIP-44 encrypted NIP-46, QR-only pairing (no clearnet, no clipboard) |
| Authorisation | Per-client kind permissions, rate limiting, auto-lock timeout |
| Forensics | Audit log (ring buffer), OLED alerts on anomalous signing patterns |
| Duress | Duress PIN triggers decoy persona and silent wipe |

### What Heartwood does NOT protect against

- Side-channel attacks (power analysis, EM emissions) -- not hardened to smartcard level
- A compromised machine that already has the NIP-46 connection secret
- Physical attacks with unlimited time and resources

### Key hygiene principle

**No user ever sees or touches an nsec.** The only human-readable secret is the 12-word mnemonic, displayed on the OLED, written on paper. No "paste your nsec" field. No "export nsec" button. No nsec in QR codes, logs, or debug output. Like a Bitcoin hardware wallet: words in, signatures out.

## User Experience

### Audience 1: Nostr power user (today)

**Setup:**

1. Download Heartwood image, flash to micro SD card (Raspberry Pi Imager)
2. Insert SD, plug in power + Ethernet (or configure WiFi during flash)
3. Wait ~60 seconds. OLED shows `HEARTWOOD` then a QR code.
4. Scan QR with Nostr client (contains `.onion` address + NIP-46 connection string)
5. Set PIN via web UI (accessible through Tor or initial local connection)
6. Generate mnemonic: OLED displays 12 words, one at a time. Write them down.
7. Confirm: web UI asks for 3 random words to verify backup.
8. Done. Client is connected. Signing works.

**Day-to-day:**

- Device is plugged in, always on
- Nostr client signs events through it transparently via NIP-46
- Visit web UI to manage personas, switch active identity, set per-client permissions
- View audit log to see what's been signed and by which client
- OLED shows current identity (truncated npub) and signing counter

**Recovery:**

1. New Heartwood or factory reset
2. Choose "Import" at setup
3. Enter 12 words
4. Device derives all identities deterministically
5. Recovery scan finds all previously used purposes
6. Everything is back -- same npubs, same personas

### Audience 2: RenegAid normie (tomorrow)

**Phase 1 -- Using the app (no Heartwood):**

- User finds a RenegAid platform (Fathom, Heritage, Goer, etc.)
- Taps "Get started"
- Signet creates a Nostr identity silently. User sees a name and avatar, not keys.
- App handles signing in software. User has no idea they're "on Nostr."

**Phase 2 -- Identity has value:**

- Parent has months of learning journals on Fathom
- Stonemason has Tier 3 professional verification on Heritage
- Terminal patient has encrypted letters for family on LastChapter
- App prompts: "Your account holds important data. Back it up."
- User writes down 12 words (generated in-app, still software signing)

**Phase 3 -- Heartwood upgrade:**

- App offers: "Upgrade to Heartwood for hardware security"
- User gets device, plugs in, scans QR from OLED
- App triggers migration automatically:
  - Old Signet software key signs migration event
  - Heartwood signs acceptance event
  - Both published to relays as cryptographic proof of migration
  - Old software key retired
- User sees: "Identity secured." No crypto decisions. No nsecs. One tap.

**Post-migration:**

- All RenegAid apps sign through Heartwood via NIP-46
- One device holds identities for every app:
  - `derive("fathom-parent", 0)` -- parent identity
  - `derive("fathom-child-emma", 0)` -- child's identity (parent-held)
  - `derive("heritage-pro", 0)` -- professional identity
  - `derive("goer", 0)` -- social identity
- Identities are unlinkable by default (parent and professional identities cannot be correlated by an observer)
- All recoverable from one 12-word backup

### Migration from existing Nostr identity

Existing Nostr users create a fresh Heartwood identity and prove the link to their old npub:

1. Heartwood generates new mnemonic (new master, clean chain of custody)
2. Old signer (Amber, nsec.app, whatever) signs: "I'm migrating to [new npub]"
3. Heartwood signs: "I accept migration from [old npub]"
4. Both events published to relays
5. Old key retired. New key was born in hardware.
6. Clients that understand migration events transfer follower/reputation data.

The old nsec never touches Heartwood. It stays in whatever signer it was in, signs one migration event, and is retired.

## Ecosystem Integration

Heartwood is a **signing appliance**. It does one thing: keep keys safe and sign when asked. Everything else talks to it over NIP-46.

### ForgeSworn ecosystem

| Component | Integration |
|-----------|-------------|
| **nsec-tree** | Heartwood is nsec-tree made physical. The Rust port is a second reference implementation. |
| **Signet** | Signet handles identity and cross-app portability. Heartwood holds the signing keys. Signet talks NIP-46. |
| **bray** (Nostr MCP) | AI agents sign Nostr events through Heartwood instead of holding nsecs |
| **toll-booth / L402** | Per-service signing identities for API access. `derive("toll-booth-api", 0)` |
| **canary-kit** | Duress persona pairs with canary-kit's dead man's switch |
| **shamir-words** | Mnemonic backup splitting into threshold shares (Phase 2) |
| **TROTT** | Fleet operators derive driver keys. Per-journey rider privacy. Agent signing keys isolated from human keys. |
| **nostr-attestations** | Hardware-backed attestation signing (kind 31000) strengthens the trust chain |

### What Heartwood does NOT do

- Signet identity management (that's Signet's job)
- RenegAid app logic (that's the apps' job)
- Cross-app identity portability (that's Signet's job)
- Verification tiers (that's Signet's job)
- Dominion encryption management (that's Dominion's job)

## Phases

### Phase 1 -- Working prototype (3 months)

- Rust port of nsec-tree core, passing all frozen test vectors
- NIP-46 server with standard methods + Heartwood extensions
- Tor hidden service, auto-configured on first boot
- Web UI for setup, persona management, client permissions
- OLED driver (status, QR code, mnemonic word-by-word display)
- LUKS encryption, PIN unlock
- QR-only pairing (connection secret never displayed as text)
- Per-client kind permissions
- Rate limiting and auto-lock timeout
- Audit log (ring buffer in local storage)
- Flashable SD card image (one-step setup)
- Documentation and build guide

### Phase 2 -- Hardening and ecosystem (3 months)

- Independent security audit of Rust crypto and firmware
- Shamir backup integration via shamir-words
- Duress persona + silent wipe
- Audit log anomaly detection and OLED alerts
- Migration proof protocol (for existing Nostr users upgrading to Heartwood)
- RenegAid integration protocol (app-initiated migration via Signet)
- Family/team provisioning (derive child Heartwoods from one master)
- Custom PCB hat (OLED + status LED, plugs onto Pi GPIO header)
- 3D-printed case design (open source STL files)
- "Build your own Heartwood" workshop materials

## Budget

| Phase | Duration | Estimate |
|-------|----------|----------|
| Phase 1 -- Working prototype | 3 months | GBP 15,000-20,000 |
| Phase 2 -- Hardening and ecosystem | 3 months | GBP 15,000-20,000 |
| **Total** | **6 months** | **GBP 30,000-40,000** |

## Grant targets

| Funder | Fit | Ask |
|--------|-----|-----|
| **OpenSats (Nostr Fund)** | Best fit. Key management is the #1 blocker. Open hardware, FOSS, privacy-first. | Phase 1 (GBP 15-20K) |
| **NLnet (NGI Zero Commons Fund)** | Identity sovereignty, privacy, open hardware. Next call ~June 2026. | Full project (EUR 30-50K) |
| **HRF (Bitcoin Dev Fund)** | Privacy tools for activists. Unlinkable personas + Tor. | Supplementary (GBP 10-15K) |

## Licence

All firmware, hardware designs, PCB files, case STLs, and documentation: **MIT**.
