# Security Policy

## Reporting a Vulnerability

Please do **not** file public GitHub issues for security vulnerabilities.

Send a DM via Nostr to the ForgeSworn team. Our public key is listed at [github.com/forgesworn](https://github.com/forgesworn). Use NIP-44 encryption.

Alternatively, email the address in the ForgeSworn GitHub org profile.

We aim to acknowledge reports within 48 hours and provide a timeline within 7 days.

## Scope

In scope:
- Key derivation logic in `heartwood-core` (HMAC-SHA256, BIP-39/32 path, encoding)
- The serial frame codec in `heartwood-frame`
- `heartwood-bridge` — the relay-to-USB signing bridge: relay/serial handling,
  de-duplication, and the fact that it must hold no key material and see no
  plaintext (all signing happens on the USB-tethered hardware device)
- Linkage proof construction and verification

Out of scope:
- Side-channel attacks (power analysis, EM emissions) — Heartwood is not hardened to smartcard level and does not claim to be
- Physical attacks with unlimited time and resources

> Note: the former key-holding Pi signer (`heartwood-device`, its web UI, and
> the bunker sidecar) has been **retired** — keys now stay on the hardware
> signer and the bridge is a keyless relay↔USB daemon. The software-signer use
> case lives at lite.mysignet.app.

## Cryptographic Primitives

| Function | Algorithm | Crate |
|----------|-----------|-------|
| Child key derivation | HMAC-SHA256 (RFC 2104) | `hmac` + `sha2` |
| Root key derivation from mnemonic | BIP-39 PBKDF2 + BIP-32 HD derivation | `bip39` + `bip32` |
| Signing | BIP-340 Schnorr (secp256k1) | `k256` |
| NIP-46 message encryption | NIP-44 (secp256k1 ECDH + ChaCha20-Poly1305) | downstream |
| Disk encryption | LUKS AES-256 | Linux kernel |
| Secret memory hygiene | Zeroize on drop | `zeroize` |

## Known Limitations

- Heartwood is not a hardware security module (HSM). The Pi has no secure enclave. A physical attacker with sufficient time and resources could extract the key from the SD card if the LUKS PIN is known or guessed.
- The OLED driver is a stub on non-Pi builds. The mnemonic display flow is only enforced in hardware deployment.
- No independent security audit has been completed yet (planned for Phase 2).

## Frozen Test Vectors

`crates/heartwood-core/tests/full_vectors_test.rs` contains cross-implementation conformance vectors. Any change that causes these to fail is a protocol-breaking change, not a refactor.
