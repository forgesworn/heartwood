# Contributing to Heartwood

## Setup

Prerequisites: Rust stable toolchain (`rustup`), `cargo`. On Linux,
`libudev-dev` for the serial port dependency.

```bash
git clone https://github.com/forgesworn/heartwood
cd heartwood
cargo build
cargo test
```

## Development Commands

| Command | Purpose |
|---------|---------|
| `cargo test --workspace` | Run all tests |
| `cargo test -p heartwood-core` | Reference crypto tests only |
| `cargo test -p heartwood-bridge` | Bridge tests (mock device + relay e2e) |
| `cargo clippy --workspace --all-targets -- -D warnings` | Lint |
| `cargo fmt --all` | Format source files |
| `cargo deny check` | Dependency audit (advisories, licences, sources) |

To run the bridge itself: it takes no flags (other than `--version`,
`--help`, `--bunker-uri`) and is configured entirely from the environment —
see the README and `crates/heartwood-bridge/src/config.rs`. For a
device-free smoke test, point `HEARTWOOD_TRANSPORT=ledger-tcp` at a
[Speculos](https://github.com/LedgerHQ/speculos) instance running the
[heartwood-ledger](https://github.com/forgesworn/heartwood-ledger) app.

## Making Changes

1. Create a branch: `git checkout -b feat/short-description` or `fix/short-description`
2. Make your changes
3. Ensure all tests pass: `cargo test --workspace`
4. Run clippy: `cargo clippy --workspace --all-targets -- -D warnings`
5. Format: `cargo fmt --all`
6. Commit using conventional commits: `type: description`
   - `feat:` — new feature
   - `fix:` — bug fix
   - `docs:` — documentation only
   - `refactor:` — no behaviour change
   - `test:` — tests only
   - `chore:` — build, deps, CI
7. Open a pull request against `main`

## Code Style

- British English in all prose and doc comments
- Every public function and type must have a doc comment (`///`)
- Private key material must use `zeroize::Zeroizing<[u8; 32]>` — never plain arrays
- No nsec in logs, debug output, or API responses — ever; the bridge
  additionally must never hold key material or see plaintext at all
- `cargo fmt` is enforced; unformatted PRs will not be merged

## Project Structure

```
crates/heartwood-bridge/   The daemon: relay tasks, de-dup, serial + Ledger transports
crates/heartwood-frame/    Serial frame codec (mirrors the firmware's no_std codec)
crates/heartwood-core/     Reference nsec-tree derivation library (used by no binary here;
                           kept for its frozen cross-implementation test vectors)
```

## Where Protocol Changes Live

The NIP-46 dispatch, policy engine and all signing happen **on the device**,
not in this repo. New NIP-46 methods or policy behaviour belong in
[heartwood-esp32](https://github.com/forgesworn/heartwood-esp32) (the shared
`common` crate, which also powers
[heartwood-ledger](https://github.com/forgesworn/heartwood-ledger)). This
repo only ever changes when the transport contract does — and the serial
frame codec in the firmware repo is authoritative.

## Frozen Test Vectors

`crates/heartwood-core/tests/full_vectors_test.rs` contains cross-implementation
test vectors that must match the TypeScript nsec-tree implementation exactly.
Do not change the expected values in these tests. If a change causes these
tests to fail, it is a breaking protocol change and needs explicit discussion.

## Security Issues

Please do not file public GitHub issues for security vulnerabilities. See
`SECURITY.md` for the responsible disclosure process.
