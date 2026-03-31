# Contributing to Heartwood

## Setup

Prerequisites: Rust stable toolchain (`rustup`), `cargo`.

```bash
git clone https://github.com/forgesworn/heartwood
cd heartwood
cargo build
cargo test
```

For Pi deployment: install `cross` for cross-compilation.

```bash
cargo install cross
cross build --release --target aarch64-unknown-linux-gnu -p heartwood-device
```

## Development Commands

| Command | Purpose |
|---------|---------|
| `cargo test` | Run all tests (40+) |
| `cargo test -p heartwood-core` | Core crypto tests only |
| `cargo run -p heartwood-device` | Run device binary in terminal mode |
| `cargo clippy --all-targets` | Lint |
| `cargo fmt` | Format source files |
| `cargo deny check` | Dependency audit |

## Making Changes

1. Create a branch: `git checkout -b feat/short-description` or `fix/short-description`
2. Make your changes
3. Ensure all tests pass: `cargo test`
4. Run clippy: `cargo clippy --all-targets -- -D warnings`
5. Format: `cargo fmt`
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
- No nsec in logs, debug output, or API responses — ever
- `cargo fmt` is enforced; unformatted PRs will not be merged

## Project Structure

```
crates/heartwood-core/     Pure crypto — no I/O, no async
crates/heartwood-nip46/    NIP-46 protocol types — no I/O
crates/heartwood-device/   Binary: HTTP server, Tor, OLED, storage
pi/                        Raspberry Pi setup scripts
web/                       Web UI (served by heartwood-device)
```

## Frozen Test Vectors

`crates/heartwood-core/tests/full_vectors_test.rs` contains cross-implementation test vectors that must match the TypeScript nsec-tree implementation exactly. Do not change the expected values in these tests. If a change causes these tests to fail, it is a breaking protocol change and needs explicit discussion.

## Adding a New Heartwood Extension Method

1. Add a variant to `Nip46Request` in `heartwood-nip46/src/methods.rs`
2. Add the handler logic in `heartwood-nip46/src/server.rs`
3. Add a doc comment to the variant explaining params and return value
4. Add a test in `heartwood-nip46/tests/` or inline `#[cfg(test)]` module
5. Update `llms.txt` to document the new method

## Security Issues

Please do not file public GitHub issues for security vulnerabilities. See `SECURITY.md` for the responsible disclosure process.
