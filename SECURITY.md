# Security Policy

## Reporting a Vulnerability

Please do **not** file public GitHub issues for security vulnerabilities.

Send a DM via Nostr to the ForgeSworn team. Our public key is listed at [github.com/forgesworn](https://github.com/forgesworn). Use NIP-44 encryption.

Alternatively, email the address in the ForgeSworn GitHub org profile.

We aim to acknowledge reports within 48 hours and provide a timeline within 7 days.

## Scope

In scope:
- `heartwood-bridge` — the keyless relay↔device daemon: relay/WebSocket
  handling, cross-relay de-duplication, the serial and Ledger (APDU) device
  transports, and the invariant that the bridge must hold no key material and
  see no plaintext (all cryptography happens on the tethered signer)
- The serial frame codec in `heartwood-frame` (parsing robustness against a
  hostile device or host)
- Key derivation logic in `heartwood-core` (HMAC-SHA256 child derivation,
  BIP-39/32 path, encoding) and linkage proof construction/verification — the
  reference implementation the firmware's `no_std` port must match

Out of scope here (report to the right repo):
- The device firmware and its policy engine —
  [heartwood-esp32](https://github.com/forgesworn/heartwood-esp32)
- The Ledger app — [heartwood-ledger](https://github.com/forgesworn/heartwood-ledger)
- The web flasher/console — sapwood
- Side-channel attacks (power analysis, EM emissions) — Heartwood signers are
  not hardened to smartcard level and do not claim to be, with the exception
  of what the Ledger's secure element provides on that tier
- Physical attacks with unlimited time and resources

## Trust Model

The bridge is deliberately boring: ciphertext in, signed events out, both
forwarded verbatim. It authenticates its serial session with `bridge.secret`
(constant-time compared on-device; not a signing key) and makes outbound
relay connections only — no inbound listener, no web UI, no stored keys.
Anything that would make the bridge see plaintext, hold key material, or sign
anything is a vulnerability by definition.

## Cryptographic Primitives

| Function | Algorithm | Where it runs |
|----------|-----------|---------------|
| Child key derivation | HMAC-SHA256 (nsec-tree) | On the device; `heartwood-core` is the host-side reference (`hmac` + `sha2`) |
| Root key from mnemonic | BIP-39 PBKDF2 + BIP-32 (`m/44'/1237'/727'/0'/0'`) | On the device / provision tooling |
| Signing | BIP-340 Schnorr (secp256k1) | On the device only |
| NIP-46 message encryption | NIP-44 (secp256k1 ECDH + ChaCha20 + HMAC-SHA256) | On the device only |
| Serial session auth | 32-byte shared secret, constant-time compare | Device NVS ↔ `bridge.secret` file |
| Secret memory hygiene | Zeroise on drop | `zeroize` |

## Known Limitations

- The bridge trusts the device's NACK semantics: a rejected request is
  reported but not diagnosed (the bridge cannot see why, by design).
- NIP-42 AUTH is unsupported — the bridge holds no key, so it cannot sign
  relay auth challenges.
- Request timing/metadata is visible to relays regardless of the bridge.
- No independent security audit has been completed yet.

## Frozen Test Vectors

`crates/heartwood-core/tests/full_vectors_test.rs` contains cross-implementation
conformance vectors shared with the TypeScript nsec-tree implementation and the
device firmware. Any change that causes these to fail is a protocol-breaking
change, not a refactor.
