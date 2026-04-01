# Changelog

All notable changes to this project will be documented in this file.

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
