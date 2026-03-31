// crates/heartwood-core/src/encoding.rs
use bech32::{Bech32, Hrp};
use crate::types::HeartwoodError;

fn encode_bech32(hrp_str: &str, bytes: &[u8; 32]) -> String {
    let hrp = Hrp::parse(hrp_str).expect("valid hrp");
    bech32::encode::<Bech32>(hrp, bytes).expect("valid encoding")
}

fn decode_bech32(expected_hrp: &str, encoded: &str) -> Result<[u8; 32], HeartwoodError> {
    let (hrp, data) = bech32::decode(encoded)
        .map_err(|_| HeartwoodError::InvalidNsec)?;
    if hrp.as_str() != expected_hrp {
        return Err(HeartwoodError::InvalidNsec);
    }
    let bytes: [u8; 32] = data
        .try_into()
        .map_err(|_| HeartwoodError::InvalidNsec)?;
    Ok(bytes)
}

pub fn encode_nsec(private_key: &[u8; 32]) -> String {
    encode_bech32("nsec", private_key)
}

pub fn decode_nsec(nsec: &str) -> Result<[u8; 32], HeartwoodError> {
    decode_bech32("nsec", nsec)
}

pub fn encode_npub(public_key: &[u8; 32]) -> String {
    encode_bech32("npub", public_key)
}

pub fn decode_npub(npub: &str) -> Result<[u8; 32], HeartwoodError> {
    decode_bech32("npub", npub)
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, HeartwoodError> {
    hex::decode(hex_str).map_err(|_| HeartwoodError::InvalidNsec)
}
