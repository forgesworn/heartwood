// crates/heartwood-core/src/encoding.rs
use crate::types::HeartwoodError;
use bech32::{Bech32, Hrp};
use zeroize::Zeroizing;

/// Encode a 32-byte key as a bech32 string with the given human-readable part.
fn encode_bech32(hrp_str: &str, bytes: &[u8; 32]) -> String {
    let hrp = Hrp::parse(hrp_str).expect("valid hrp");
    bech32::encode::<Bech32>(hrp, bytes).expect("valid encoding")
}

/// Decode a bech32 string, verifying the expected human-readable part.
fn decode_bech32(expected_hrp: &str, encoded: &str) -> Result<[u8; 32], HeartwoodError> {
    let (hrp, data) = bech32::decode(encoded).map_err(|_| HeartwoodError::InvalidNsec)?;
    if hrp.as_str() != expected_hrp {
        return Err(HeartwoodError::InvalidNsec);
    }
    let bytes: [u8; 32] = data.try_into().map_err(|_| HeartwoodError::InvalidNsec)?;
    Ok(bytes)
}

/// Encode a 32-byte private key as a Nostr `nsec1...` bech32 string.
pub fn encode_nsec(private_key: &[u8; 32]) -> String {
    encode_bech32("nsec", private_key)
}

/// Decode an `nsec1...` bech32 string to the raw 32-byte private key.
///
/// Returns `Zeroizing<[u8; 32]>` so the secret is automatically zeroed on drop.
pub fn decode_nsec(nsec: &str) -> Result<Zeroizing<[u8; 32]>, HeartwoodError> {
    decode_bech32("nsec", nsec).map(Zeroizing::new)
}

/// Encode a 32-byte public key as a Nostr `npub1...` bech32 string.
pub fn encode_npub(public_key: &[u8; 32]) -> String {
    encode_bech32("npub", public_key)
}

/// Decode an `npub1...` bech32 string to the raw 32-byte public key.
pub fn decode_npub(npub: &str) -> Result<[u8; 32], HeartwoodError> {
    decode_bech32("npub", npub)
}

/// Convert a byte slice to a lowercase hex string.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Decode a hex string to bytes. Returns `HeartwoodError::InvalidNsec` on invalid hex.
pub fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, HeartwoodError> {
    hex::decode(hex_str).map_err(|_| HeartwoodError::InvalidNsec)
}
