# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- **`heartwood-bridge`** — relay-to-serial signing bridge for HSM mode: a sidecar daemon that pumps NIP-46 requests between Nostr relays and a USB-tethered ESP32/ESP8266 signing device over `ENCRYPTED_REQUEST` (0x10) / `SIGN_ENVELOPE_RESPONSE` (0x35) frames; all cryptography happens inline on the device, so the bridge never holds key material or sees plaintext; ships with a `heartwood-bridge@.service` systemd unit
- **`heartwood-frame`** — shared serial frame codec crate (magic/type/length/CRC-32 framing), extracted from the duplicated copies in `heartwood-bridge` and `heartwood-device` so the wire format can no longer drift between them
- **Per-identity bunker URIs** — the bunker sidecar resolves each NIP-46 request by its `#p` target, giving the master identity and every derived persona its own `bunker://` URI and signing key instead of one global active identity; sidecar writes `bunker-uris.json` (`[{label, pubkey, npub, uri}]`); device web UI adds `GET /api/identities` and `/api/identities/qr`, an Identities list with copy/QR/auto-approve links, and connection slots scoped to a chosen identity
- Design note and threat model for the relay-serial bridge (`docs/2026-06-25-relay-serial-bridge.md`)
- Expanded test coverage: a hardware-free end-to-end bridge test, `SerialSession` protocol and `read_frame` edge cases, the bridge's relay message handler, and a real-client interop test (`nostr-tools`'s `BunkerSigner` over a live relay) proving per-identity routing

### Changed
- Reachability documentation reframed as relay-mediated by default; Tor is opt-in and fronts only the web management UI
- `Cargo.lock` now committed so the multi-arch Docker build resolves
- Pre-commit hook and CI job enforcing the project's single allowed commit identity

### Fixed
- Bridge serial writes now paced in small chunks with a short delay between them — large NIP-46 frames arriving as one burst could overrun classic ESP32 boards' small UART receive buffers
- `heartwood-device` web serial CRC excluded the 2-byte magic preamble (matching the firmware), fixing a wire-incompatible `/api/hsm/pin` path
- `heartwood-device` serial `read_frame` payload offset corrected

## [0.6.0] - 2026-06-21

### Added
- **Encryption at rest** — master secret sealed with AES-256-GCM and an Argon2id-derived key; versioned KDF params; intermediate secret material zeroised
- **Boot PIN** — PIN management with brute-force protection and alphanumeric support
- **Mnemonic UX** — hardware-wallet-style 24-word BIP-39 generation and recovery flow (`/api/generate-mnemonic`, `/api/wordlist`)
- **Multi-instance bunker** — identity tree with persistent per-client keys, systemd template units, multi-instance `setup.sh`; `HEARTWOOD_DATA_DIR` / `--authorized-keys` support
- **Connection slots** — reusable secrets for named client pairing; `/api/derive-client-key`, `/api/client-keys`, `/api/pair` (Bark pairing)
- **ESP32 HSM mode** — web setup flow integration, PIN management, and auto-detected serial port
- **`heartwood_lsag_sign`** NIP-46 method (linkable ring signatures); NIP-44 v2 and NIP-04 encrypt/decrypt
- **Multi-architecture support** — `pi/`→`boards/pi/` rename, multi-arch container image with CI verification, armv7 and riscv64 release targets, ARM-general README
- Relay-mediated management design (kind 24134) for WiFi-standalone signers

### Changed
- Crates renamed for crates.io publishing (`nsec-tree-rs`, `nip46-signer`); auto-published on release
- nsec-tree bumped to 1.4.4 (proof-layer hardening)
- MIT licence; documentation, ecosystem overview, and architecture diagrams reworked

### Fixed
- Multiple security-audit rounds (critical/high/medium findings): input validation, XSS prevention, PIN/password hardening, infrastructure hardening, secret zeroisation
- KDF param versioning to prevent silent unlock failures; resume unlocked state from cached payload on restart

## [0.3.0] - 2026-04-01

### Added
- Relay connection status indicators in the web UI (green/red/grey dots, connection summary)
- Client labels — name your NIP-46 clients when approving (e.g. "NostrHub", "My phone")
- Client metadata display — shows truncated pubkeys, attempt counts, and timestamps
- Bunker sidecar writes relay status to `bunker-status.json` every 15 seconds
- `GET /api/bunker/status` endpoint for relay connection state
- Heartwood persona derivation in the bunker bridge (nsec-tree integration)
- Bunker sidecar installation in the one-line installer and setup script

### Fixed
- Bunker subscription used `pool.subscribeMany` with a single filter instead of `pool.subscribe` — caused NIP-46 client timeouts
- Bunker URI now recalculates when relays are changed via the web UI
- Allowed `get_public_key` for unapproved clients (required for NIP-46 login handshake)
- Tor hidden service directory permissions (`chmod 710`) for onion hostname access
- Tor port mismatch in the one-line installer (was forwarding to 8080 instead of 3000)
- Installer now includes systemd hardening and `HEARTWOOD_BIND` environment variable

### Changed
- Bunker status file uses async `writeFile` instead of blocking `writeFileSync`
- Bunker status writer skips no-op writes when relay state hasn't changed (SD card wear reduction)
- Device status endpoint uses `tokio::fs` for non-blocking file reads
- Improved client management section — clearer explanatory text, better visual hierarchy

## [0.2.0] - 2026-03-31

### Added
- NIP-46 bunker sidecar (Node.js) with relay subscription and encrypted messaging
- Web UI client management — approve, revoke, and view pending NIP-46 clients
- Per-client rate limiting (sliding window, 30 requests/minute default)
- Per-client kind restrictions (allowlists for which event kinds a client can sign)
- Relay configuration in the web UI (add, remove, save)
- Bunker URI display and copy button
- Tor toggle and .onion address display
- Device password (Argon2id-hashed HTTP Basic Auth)
- PIN encryption for master secret (AES-256-GCM via Argon2id key derivation)
- Lock/unlock flow with runtime payload for the bunker sidecar
- GitHub Actions release workflow with one-line installer

## [0.1.0] - 2026-03-30

### Added
- Rust port of nsec-tree core (derivation, signing, proofs, personas, recovery)
- NIP-46 server with standard methods and Heartwood extensions
- Tor hidden service auto-configuration
- Web UI setup wizard (bunker mode, nsec-tree mnemonic, nsec-tree nsec)
- OLED display driver (terminal fallback for development)
- Encrypted storage with PIN protection
- Signing audit log
- Pi deployment files (systemd, Tor config, setup script)
- GitHub Actions CI (check, test, clippy, fmt)
- Cross-compile release workflow for aarch64 + x86_64
- 55 tests with frozen cross-implementation protocol vectors
