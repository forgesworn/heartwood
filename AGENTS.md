# Heartwood

Heartwood is `heartwood-bridge`, a headless Rust daemon that connects Nostr relays to a USB-tethered hardware signer (ESP32 running heartwood-esp32, or a Ledger running heartwood-ledger). It relays NIP-46 requests over the wire; it holds no key material and never sees plaintext, since every cryptographic operation happens on the tethered device.

## Build & Test

| Command | Purpose |
|---------|---------|
| `cargo build` | Build the workspace |
| `cargo build --release -p heartwood-bridge` | Build the bridge binary |
| `cargo test --workspace` | Run all tests |
| `cargo test -p heartwood-core` | Reference derivation tests only |
| `cargo test -p heartwood-bridge` | Bridge tests (mock device + relay e2e) |
| `cargo clippy --workspace --all-targets -- -D warnings` | Lint |
| `cargo fmt --all` | Format source files |
| `cargo deny check` | Dependency audit (advisories, licences, sources) |

## Structure

```
crates/heartwood-bridge/   The product: relay tasks, de-dup, serial + Ledger transports
crates/heartwood-frame/    Serial frame codec, mirrors the firmware's no_std codec
crates/heartwood-core/     Reference nsec-tree derivation library; not used by any
                            binary here, kept for its frozen cross-implementation
                            test vectors
docs/                       QUICKSTART.md, ECOSYSTEM.md, ROADMAP.md, dated notes
```

## Conventions

- British English in all prose and doc comments.
- Every public function and type has a doc comment (`///`).
- Private key material uses `zeroize::Zeroizing<[u8; 32]>`, never plain arrays.
- No nsec in logs, debug output, or API responses, ever; the bridge additionally
  must never hold key material or see plaintext at all.
- Conventional commits (`type: description`): `feat:`, `fix:`, `docs:`,
  `refactor:`, `test:`, `chore:`.
- `cargo fmt` is enforced; unformatted changes will not pass CI.

## Key Files

| File | Purpose |
|------|---------|
| `crates/heartwood-bridge/src/config.rs` | Bridge configuration: transport, device address, relays, `bridge.secret` |
| `ARCHITECTURE.md` | Full internal architecture with diagrams |
| `docs/QUICKSTART.md` | Install and run walkthrough, including Docker |
| `docs/ECOSYSTEM.md` | Cross-repo ecosystem overview |
| `SECURITY.md` | Responsible disclosure process and scope |

## Common Pitfalls

- The NIP-46 dispatch, policy engine and all signing happen on the device, not
  in this repo. New NIP-46 methods or policy behaviour belong in
  `heartwood-esp32` (the shared `common` crate); this repo only changes when
  the transport contract does, and the serial frame codec in the firmware repo
  is authoritative.
- `crates/heartwood-core/tests/full_vectors_test.rs` holds cross-implementation
  test vectors that must match the TypeScript nsec-tree implementation exactly.
  Do not change the expected values; a mismatch is a breaking protocol change
  and needs explicit discussion.
- The bridge must never hold key material or see plaintext; do not add code
  that reads or logs decrypted content in `heartwood-bridge`.
