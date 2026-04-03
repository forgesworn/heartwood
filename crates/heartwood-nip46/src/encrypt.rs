// crates/heartwood-nip46/src/encrypt.rs
//! NIP-44 v2 and NIP-04 (deprecated) encryption and decryption.
//!
//! Both operations share the same ECDH shared-secret derivation step:
//! the caller's secp256k1 private key is multiplied by the peer's public key
//! to produce a shared point, and the x-coordinate of that point is used as
//! key material.
//!
//! **NIP-04** (deprecated) — AES-256-CBC with a random 16-byte IV.
//! Wire format: `base64(ciphertext)?iv=base64(iv)`
//!
//! **NIP-44 v2** — XChaCha20 stream cipher, HKDF-SHA256 key derivation, and
//! HMAC-SHA256 authentication.  Wire format: base64 of
//! `version(1) || nonce(32) || padded_ciphertext || mac(32)`.

use aes::Aes256;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use chacha20::cipher::{KeyIvInit as ChaChaKeyIvInit, StreamCipher};
use chacha20::XChaCha20;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use k256::{
    ecdh::diffie_hellman,
    PublicKey, SecretKey,
};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

// ── ECDH ─────────────────────────────────────────────────────────────────────

/// Perform secp256k1 ECDH and return the 32-byte x-coordinate of the shared
/// point.
///
/// `private_key` is a raw 32-byte scalar.  `peer_pubkey_hex` is either a
/// 64-char compressed-x-only (Nostr) or 66-char SEC1 hex pubkey.
fn ecdh_shared_x(private_key: &[u8; 32], peer_pubkey_hex: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let secret =
        SecretKey::from_bytes(private_key.into()).map_err(|e| format!("invalid private key: {e}"))?;

    // Nostr conventionally uses 64-hex-char x-only pubkeys (32 bytes).
    // Expand to 33-byte compressed SEC1 (02-prefixed) before parsing.
    let peer_pubkey: PublicKey = if peer_pubkey_hex.len() == 64 {
        let prefixed = format!("02{peer_pubkey_hex}");
        let bytes = hex::decode(&prefixed)
            .map_err(|e| format!("invalid peer pubkey hex: {e}"))?;
        PublicKey::from_sec1_bytes(&bytes)
            .map_err(|e| format!("invalid peer pubkey: {e}"))?
    } else if peer_pubkey_hex.len() == 66 {
        let bytes = hex::decode(peer_pubkey_hex)
            .map_err(|e| format!("invalid peer pubkey hex: {e}"))?;
        PublicKey::from_sec1_bytes(&bytes)
            .map_err(|e| format!("invalid peer pubkey: {e}"))?
    } else {
        return Err(format!(
            "peer pubkey must be 64- or 66-char hex; got {} chars",
            peer_pubkey_hex.len()
        ));
    };

    let shared_point = diffie_hellman(secret.to_nonzero_scalar(), peer_pubkey.as_affine());
    let mut x: [u8; 32] = (*shared_point.raw_secret_bytes()).into();
    let result = Zeroizing::new(x);
    x.zeroize();
    Ok(result)
}

// ── NIP-44 v2 ────────────────────────────────────────────────────────────────

/// Minimum padded plaintext length (32 bytes, per spec).
const NIP44_MIN_PADDED_LEN: usize = 32;

/// Derive the NIP-44 conversation key from the ECDH shared x-coordinate.
///
/// HKDF-SHA256, no salt, info = b"nip44-v2".
fn nip44_conversation_key(shared_x: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, shared_x);
    let mut ck = Zeroizing::new([0u8; 32]);
    hk.expand(b"nip44-v2", ck.as_mut()).expect("HKDF expand cannot fail for 32-byte output");
    ck
}

/// Derive the three per-message keys from the conversation key and nonce.
///
/// Returns `(chacha_key[32], chacha_nonce[24], hmac_key[32])`.
fn nip44_message_keys(
    conversation_key: &[u8; 32],
    nonce: &[u8; 32],
) -> (Zeroizing<[u8; 32]>, [u8; 24], Zeroizing<[u8; 32]>) {
    let hk = Hkdf::<Sha256>::new(Some(nonce), conversation_key);
    let mut keys = Zeroizing::new([0u8; 88]); // chacha_key(32) + chacha_nonce(24) + hmac_key(32)
    hk.expand(b"", keys.as_mut()).expect("HKDF expand cannot fail for 88-byte output");

    let mut chacha_key = Zeroizing::new([0u8; 32]);
    chacha_key.copy_from_slice(&keys[..32]);

    let mut chacha_nonce = [0u8; 24];
    chacha_nonce.copy_from_slice(&keys[32..56]);

    let mut hmac_key = Zeroizing::new([0u8; 32]);
    hmac_key.copy_from_slice(&keys[56..88]);

    (chacha_key, chacha_nonce, hmac_key)
}

/// Calculate the padded length for a plaintext of `n` bytes, per NIP-44 spec.
///
/// The spec pads to the next power-of-two-adjacent chunk size to mask the
/// true message length.
fn nip44_padded_len(n: usize) -> usize {
    if n <= NIP44_MIN_PADDED_LEN {
        return NIP44_MIN_PADDED_LEN;
    }
    // NIP-44 spec: chunk = max(32, next_power_of_two(n) / 4)
    // where next_power_of_two is the smallest power of 2 that is >= n.
    // `(n - 1).next_power_of_two()` gives 2^ceil(log2(n)) for n > 1.
    let next_power = (n - 1).next_power_of_two();
    let chunk = (next_power / 4).max(NIP44_MIN_PADDED_LEN);
    let remainder = n % chunk;
    if remainder == 0 { n } else { n + chunk - remainder }
}

/// NIP-44 v2 encrypt.
///
/// `private_key` accepts `Result<&[u8; 32], &str>` so that callers can pass
/// the output of `resolve_encryption_key()` directly.
///
/// Returns the base64-encoded ciphertext blob ready to send over the wire.
pub fn nip44_encrypt(private_key: Result<&[u8; 32], &'static str>, peer_pubkey_hex: &str, plaintext: &str) -> Result<String, String> {
    let private_key = private_key.map_err(|e| e.to_string())?;
    let shared_x = ecdh_shared_x(private_key, peer_pubkey_hex)?;
    let conversation_key = nip44_conversation_key(&shared_x);

    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);

    let (chacha_key, chacha_nonce, hmac_key) = nip44_message_keys(&conversation_key, &nonce);

    // Pad the plaintext: 2-byte big-endian length prefix + plaintext + zero padding.
    let pt_len = plaintext.len();
    let padded_len = nip44_padded_len(pt_len);
    let mut padded = Zeroizing::new(vec![0u8; 2 + padded_len]);
    let len_bytes = (pt_len as u16).to_be_bytes();
    padded[0] = len_bytes[0];
    padded[1] = len_bytes[1];
    padded[2..2 + pt_len].copy_from_slice(plaintext.as_bytes());
    // Remaining bytes are already zero.

    // XChaCha20 encrypt in place.
    // chacha20 0.10 uses hybrid-array; pass typed references directly.
    let mut cipher = XChaCha20::new(&(*chacha_key).into(), &chacha_nonce.into());
    cipher.apply_keystream(&mut padded[..]);

    // HMAC-SHA256 of (nonce || ciphertext).
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&*hmac_key)
        .expect("HMAC accepts any key length");
    mac.update(&nonce);
    mac.update(&padded[..]);
    let mac_bytes: [u8; 32] = mac.finalize().into_bytes().into();

    // Assemble: version(1) || nonce(32) || ciphertext || mac(32).
    let mut payload = Vec::with_capacity(1 + 32 + padded.len() + 32);
    payload.push(2u8); // NIP-44 v2
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&padded[..]);
    payload.extend_from_slice(&mac_bytes);

    Ok(B64.encode(&payload))
}

/// NIP-44 v2 decrypt.
///
/// `private_key` accepts `Result<&[u8; 32], &str>` so that callers can pass
/// the output of `resolve_encryption_key()` directly.
///
/// `ciphertext` is the base64-encoded blob returned by `nip44_encrypt`.
pub fn nip44_decrypt(private_key: Result<&[u8; 32], &'static str>, peer_pubkey_hex: &str, ciphertext: &str) -> Result<String, String> {
    let private_key = private_key.map_err(|e| e.to_string())?;
    let payload = B64.decode(ciphertext.trim()).map_err(|e| format!("nip44_decrypt: invalid base64: {e}"))?;

    // Minimum length: version(1) + nonce(32) + padded_min(32) + mac(32) = 97 bytes.
    if payload.len() < 97 {
        return Err("nip44_decrypt: payload too short".into());
    }
    if payload[0] != 2 {
        return Err(format!("nip44_decrypt: unsupported version {}", payload[0]));
    }

    let nonce: [u8; 32] = payload[1..33].try_into().unwrap();
    let mac_offset = payload.len() - 32;
    let ciphertext_bytes = &payload[33..mac_offset];
    let mac_bytes = &payload[mac_offset..];

    let shared_x = ecdh_shared_x(private_key, peer_pubkey_hex)?;
    let conversation_key = nip44_conversation_key(&shared_x);
    let (chacha_key, chacha_nonce, hmac_key) = nip44_message_keys(&conversation_key, &nonce);

    // Verify HMAC before decrypting (encrypt-then-MAC).
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&*hmac_key)
        .expect("HMAC accepts any key length");
    mac.update(&nonce);
    mac.update(ciphertext_bytes);
    mac.verify_slice(mac_bytes).map_err(|_| "nip44_decrypt: MAC verification failed")?;

    // Decrypt in place (XChaCha20 is a stream cipher — same operation as encrypt).
    let mut plaintext_buf = Zeroizing::new(ciphertext_bytes.to_vec());
    let mut cipher = XChaCha20::new(&(*chacha_key).into(), &chacha_nonce.into());
    cipher.apply_keystream(&mut plaintext_buf[..]);

    // Read the 2-byte length prefix and extract the actual plaintext.
    if plaintext_buf.len() < 2 {
        return Err("nip44_decrypt: decrypted buffer too short".into());
    }
    let pt_len = u16::from_be_bytes([plaintext_buf[0], plaintext_buf[1]]) as usize;
    if 2 + pt_len > plaintext_buf.len() {
        return Err("nip44_decrypt: length prefix exceeds buffer".into());
    }

    let result = std::str::from_utf8(&plaintext_buf[2..2 + pt_len])
        .map_err(|e| format!("nip44_decrypt: plaintext is not valid UTF-8: {e}"))?
        .to_string();

    Ok(result)
}

// ── NIP-04 ───────────────────────────────────────────────────────────────────

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

/// NIP-04 (deprecated) encrypt.
///
/// `private_key` accepts `Result<&[u8; 32], &str>` so that callers can pass
/// the output of `resolve_encryption_key()` directly.
///
/// Uses the raw ECDH shared x-coordinate directly as the AES-256-CBC key.
/// Returns `base64(ciphertext)?iv=base64(iv)`.
pub fn nip04_encrypt(private_key: Result<&[u8; 32], &'static str>, peer_pubkey_hex: &str, plaintext: &str) -> Result<String, String> {
    let private_key = private_key.map_err(|e| e.to_string())?;
    let shared_x = ecdh_shared_x(private_key, peer_pubkey_hex)?;

    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);

    // AES-256-CBC with PKCS7 padding via the `cbc` crate.
    let cipher = Aes256CbcEnc::new((&*shared_x).into(), &iv.into());
    let ciphertext = cipher.encrypt_padded_vec_mut::<cbc::cipher::block_padding::Pkcs7>(plaintext.as_bytes());

    let result = format!("{}?iv={}", B64.encode(&ciphertext), B64.encode(iv));
    Ok(result)
}

/// NIP-04 (deprecated) decrypt.
///
/// `private_key` accepts `Result<&[u8; 32], &str>` so that callers can pass
/// the output of `resolve_encryption_key()` directly.
///
/// Expects `ciphertext_b64?iv=iv_b64` wire format.
pub fn nip04_decrypt(private_key: Result<&[u8; 32], &'static str>, peer_pubkey_hex: &str, ciphertext: &str) -> Result<String, String> {
    let private_key = private_key.map_err(|e| e.to_string())?;
    // Split on "?iv=" — the IV is appended after the ciphertext.
    let (ct_b64, iv_b64) = ciphertext
        .split_once("?iv=")
        .ok_or("nip04_decrypt: expected 'ciphertext?iv=iv' format")?;

    let ct = B64.decode(ct_b64.trim()).map_err(|e| format!("nip04_decrypt: invalid ciphertext base64: {e}"))?;
    let iv_bytes = B64.decode(iv_b64.trim()).map_err(|e| format!("nip04_decrypt: invalid IV base64: {e}"))?;

    if iv_bytes.len() != 16 {
        return Err(format!("nip04_decrypt: IV must be 16 bytes, got {}", iv_bytes.len()));
    }
    let iv: [u8; 16] = iv_bytes.try_into().unwrap();

    let shared_x = ecdh_shared_x(private_key, peer_pubkey_hex)?;

    let cipher = Aes256CbcDec::new((&*shared_x).into(), &iv.into());
    let plaintext_bytes = cipher
        .decrypt_padded_vec_mut::<cbc::cipher::block_padding::Pkcs7>(&ct)
        .map_err(|e| format!("nip04_decrypt: AES-CBC decryption failed: {e}"))?;

    String::from_utf8(plaintext_bytes).map_err(|e| format!("nip04_decrypt: plaintext is not valid UTF-8: {e}"))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Two test keypairs — generated offline; private keys are NOT real secrets.
    // Alice: private key, peer = Bob's pubkey (x-only, 64 hex chars).
    // Bob:   private key, peer = Alice's pubkey.
    //
    // Derived from known test vectors to keep the suite self-contained.
    const ALICE_PRIV: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    // pubkey for scalar=1 on secp256k1 (the generator point x-coord)
    const ALICE_PUB_HEX: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    const BOB_PRIV: &str = "0000000000000000000000000000000000000000000000000000000000000002";
    // pubkey for scalar=2
    const BOB_PUB_HEX: &str = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

    fn alice_key() -> [u8; 32] {
        hex::decode(ALICE_PRIV).unwrap().try_into().unwrap()
    }

    fn bob_key() -> [u8; 32] {
        hex::decode(BOB_PRIV).unwrap().try_into().unwrap()
    }

    // ── NIP-44 round-trip ────────────────────────────────────────────────────

    #[test]
    fn nip44_round_trip_short() {
        let ct = nip44_encrypt(Ok(&alice_key()), BOB_PUB_HEX, "hello").unwrap();
        let pt = nip44_decrypt(Ok(&bob_key()), ALICE_PUB_HEX, &ct).unwrap();
        assert_eq!(pt, "hello");
    }

    #[test]
    fn nip44_round_trip_long() {
        let msg = "A".repeat(200);
        let ct = nip44_encrypt(Ok(&alice_key()), BOB_PUB_HEX, &msg).unwrap();
        let pt = nip44_decrypt(Ok(&bob_key()), ALICE_PUB_HEX, &ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn nip44_round_trip_empty() {
        let ct = nip44_encrypt(Ok(&alice_key()), BOB_PUB_HEX, "").unwrap();
        let pt = nip44_decrypt(Ok(&bob_key()), ALICE_PUB_HEX, &ct).unwrap();
        assert_eq!(pt, "");
    }

    #[test]
    fn nip44_tampered_mac_rejected() {
        let mut ct_b64 = nip44_encrypt(Ok(&alice_key()), BOB_PUB_HEX, "secret").unwrap();
        // Flip the last byte of the base64 payload.
        let mut bytes = B64.decode(&ct_b64).unwrap();
        let last = bytes.last_mut().unwrap();
        *last ^= 0xff;
        ct_b64 = B64.encode(&bytes);

        let result = nip44_decrypt(Ok(&bob_key()), ALICE_PUB_HEX, &ct_b64);
        assert!(result.is_err(), "tampered MAC should be rejected");
    }

    // ── NIP-04 round-trip ────────────────────────────────────────────────────

    #[test]
    fn nip04_round_trip() {
        let ct = nip04_encrypt(Ok(&alice_key()), BOB_PUB_HEX, "hello NIP-04").unwrap();
        assert!(ct.contains("?iv="), "wire format must include ?iv= separator");
        let pt = nip04_decrypt(Ok(&bob_key()), ALICE_PUB_HEX, &ct).unwrap();
        assert_eq!(pt, "hello NIP-04");
    }

    #[test]
    fn nip04_round_trip_unicode() {
        let msg = "こんにちは 🌏";
        let ct = nip04_encrypt(Ok(&alice_key()), BOB_PUB_HEX, msg).unwrap();
        let pt = nip04_decrypt(Ok(&bob_key()), ALICE_PUB_HEX, &ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn nip04_wrong_iv_fails() {
        let ct = nip04_encrypt(Ok(&alice_key()), BOB_PUB_HEX, "test").unwrap();
        // Corrupt the IV portion.
        let (ct_part, _iv_part) = ct.split_once("?iv=").unwrap();
        let bad = format!("{ct_part}?iv=AAAAAAAAAAAAAAAAAAAAAA==");
        let result = nip04_decrypt(Ok(&bob_key()), ALICE_PUB_HEX, &bad);
        assert!(result.is_err(), "wrong IV should cause decryption failure");
    }

    // ── NIP-44 padding ───────────────────────────────────────────────────────

    #[test]
    fn padded_len_boundaries() {
        assert_eq!(nip44_padded_len(0), 32);
        assert_eq!(nip44_padded_len(1), 32);
        assert_eq!(nip44_padded_len(32), 32);
        assert_eq!(nip44_padded_len(33), 64);
        assert_eq!(nip44_padded_len(64), 64);
        assert_eq!(nip44_padded_len(65), 96);
        assert_eq!(nip44_padded_len(100), 128);
    }
}
