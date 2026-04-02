# Heartwood

Heartwood is a Nostr signing appliance: a Rust workspace that runs on a Raspberry Pi Zero 2 W. It holds a master secret derived from a BIP-39 mnemonic, derives unlinkable child identities via HMAC-SHA256 (the nsec-tree protocol), serves NIP-46 remote signing over Tor, and exposes a local web UI.

The workspace has three crates:
- `heartwood-core` — pure crypto (nsec-tree derivation, signing, linkage proofs, recovery). No I/O.
- `heartwood-nip46` — NIP-46 protocol types, session management, per-client permissions. No I/O.
- `heartwood-device` — Tokio binary: Axum HTTP server, Tor management, OLED driver, storage.

## Build & Test

| Command | Purpose |
|---------|---------|
| `cargo build` | Debug build (all crates) |
| `cargo build --release -p heartwood-device` | Release binary for Pi deployment |
| `cargo test` | Full test suite (55 tests) |
| `cargo test -p heartwood-core` | Core crypto tests only |
| `cargo run -p heartwood-device` | Run device binary locally (terminal mode) |
| `cargo clippy --all-targets` | Lint |
| `cargo fmt` | Format |
| `cargo deny check` | Dependency audit |
| `cd bunker && npm test` | Bunker unit tests (56 tests) |
| `node tools/derive-client-key.mjs` | Derive NIP-46 client key from nsec-tree |

Cross-compile for Pi: `cross build --release --target aarch64-unknown-linux-gnu -p heartwood-device`

## Structure

```
Cargo.toml                    Workspace root
crates/
  heartwood-core/
    src/
      lib.rs                  Public re-exports
      types.rs                TreeRoot, Identity, Persona, LinkageProof, HeartwoodError
      root.rs                 from_mnemonic(), from_nsec(), from_nsec_bytes()
      derive.rs               derive(), derive_from_identity()
      persona.rs              derive_persona(), derive_from_persona()
      proof.rs                create_blind_proof(), create_full_proof(), verify_proof()
      recover.rs              recover()
      encoding.rs             encode_npub/nsec, decode_npub/nsec, bytes_to_hex
      validate.rs             validate_purpose()
    tests/                    Integration tests with frozen protocol vectors
  heartwood-nip46/
    src/
      methods.rs              Nip46Request enum, Nip46Response struct
      permissions.rs          ClientPermissions (kind allowlists, rate limiting)
      session.rs              ClientSession, SessionManager
      server.rs               HeartwoodServer struct
  heartwood-device/
    src/
      main.rs                 Entry point (Tokio)
      web.rs                  Axum router, HTTP handlers
      audit.rs                AuditLog (ring buffer)
      storage.rs              Persistent storage (master secret, sessions)
      tor.rs                  TorManager (start Tor, wait for .onion)
      oled.rs                 OLED display driver (SSD1306)
bunker/
  index.mjs                   NIP-46 bunker sidecar (Node.js)
  lib.mjs                     Pure logic functions (testable, no I/O)
  test/lib.test.mjs           Bunker unit tests (56 tests)
  package.json                Bunker dependencies (nostr-tools, nsec-tree, ws)
tools/
  derive-client-key.mjs       Standalone CLI for persistent NIP-46 client keys
  package.json                Tool dependencies (nsec-tree, nostr-tools)
pi/
  setup.sh                    Pi deployment script (multi-instance)
  heartwood@.service          systemd template (Rust device)
  heartwood-bunker@.service   systemd template (Node.js bunker)
  torrc                       Tor hidden service config
web/
  index.html                  Bundled web UI (served by heartwood-device)
docs/
  specs/                      Design documents (private, not for public consumption)
  plans/                      Phase plans (private)
```

## Conventions

- British English in all prose and doc comments
- Amounts in satoshis (SAT) if any monetary values appear
- Git commits: `type: description` (feat:, fix:, docs:, refactor:, test:, chore:)
- No `Co-Authored-By` lines in commits
- Private keys and secrets must use `zeroize::Zeroizing<[u8; 32]>` — never plain `[u8; 32]`
- No nsec exposed in logs, debug output, QR codes, or API responses

## Frozen Protocol Vectors

`crates/heartwood-core/tests/full_vectors_test.rs` and `tests/derive_test.rs` contain frozen test vectors that MUST match the TypeScript nsec-tree implementation byte-for-byte. **Never change expected values in these tests.** If a refactor causes them to fail, the refactor broke the protocol.

## Common Pitfalls

- The `heartwood-device` crate is a binary, not a library — do not add it as a dependency
- `TreeRoot::secret()` is `pub(crate)` by design — the raw secret must not be exposed outside `heartwood-core`
- `from_nsec_bytes` applies an HMAC intermediate; `create_tree_root` does not — they are not interchangeable
- The OLED driver (`oled.rs`) is a stub on non-Pi targets; `oled.show_qr()` is a no-op in terminal mode
- Tor takes ~60 seconds to establish a hidden service on first boot — `TorManager::wait_for_onion` has a 120-second timeout
- `cross` (not `cargo`) is required for Pi cross-compilation: `cargo install cross`
- The `HEARTWOOD_DATA_DIR` env var controls where each instance reads/writes data. Falls back to `/var/lib/heartwood` when unset.
- Systemd template units use `%i` for the instance name — `heartwood@personal.service` reads from `/var/lib/heartwood/personal/`
- Identity tree names use `/` as a namespace separator: `persona/forgesworn`, `client/bray`, `agent/dispatch`

## Key Dependencies

| Crate | Why |
|-------|-----|
| `k256` | secp256k1 (BIP-340 Schnorr + ECDSA) — same curve Nostr uses |
| `hmac` + `sha2` | HMAC-SHA256 child key derivation |
| `zeroize` | Deterministic secret cleanup on drop |
| `bip32` + `bip39` | Mnemonic parsing, BIP-32 HD derivation for the root path |
| `bech32` | npub/nsec bech32 encoding (Nostr standard) |
| `axum` + `tokio` | Async HTTP server for web UI |
| `serde_json` | NIP-46 JSON message encoding |
