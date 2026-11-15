//! Reference implementation of nsec-tree WRAPPED-NSEC.md. Not a bridge operation.
use crate::{encode_npub, HeartwoodError, TreeRoot};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hkdf::Hkdf;
use k256::schnorr::SigningKey;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

const MAGIC: &[u8] = b"NSTW\x01\x01\x01";
const INFO: &[u8] = b"nsec-tree/wrapped-nsec/v1";
const HEADER_LEN: usize = 51;
const RECORD_LEN: usize = 131;

/// Imported raw key, with no derivation provenance. Secret zeroises on drop.
pub struct UnwrappedNsec {
    /// Exact imported secret, never an HMAC tree root.
    pub private_key: Zeroizing<[u8; 32]>,
    /// BIP-340 x-only public key.
    pub public_key: [u8; 32],
    /// NIP-19 public address.
    pub npub: String,
}

fn public_key(raw: &[u8]) -> Result<[u8; 32], HeartwoodError> {
    let raw: &[u8; 32] = raw.try_into().map_err(|_| HeartwoodError::InvalidWrappedNsec)?;
    let signing =
        SigningKey::from_bytes(raw.into()).map_err(|_| HeartwoodError::InvalidWrappedNsec)?;
    Ok(signing.verifying_key().to_bytes().into())
}

fn cipher(root: &TreeRoot, salt: &[u8]) -> Result<Aes256Gcm, HeartwoodError> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), root.secret())
        .expand(INFO, key.as_mut())
        .map_err(|_| HeartwoodError::InvalidWrappedNsec)?;
    Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| HeartwoodError::InvalidWrappedNsec)
}

fn wrap_with_entropy(
    root: &TreeRoot,
    raw: &[u8; 32],
    salt: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<String, HeartwoodError> {
    let public = public_key(raw)?;
    let mut payload = Zeroizing::new([0u8; 64]);
    payload[..32].copy_from_slice(raw);
    payload[32..].copy_from_slice(&public);
    let mut header = [0u8; HEADER_LEN];
    header[..7].copy_from_slice(MAGIC);
    header[7..39].copy_from_slice(salt);
    header[39..].copy_from_slice(nonce);
    let encrypted = cipher(root, salt)?
        .encrypt(Nonce::from_slice(nonce), Payload { msg: payload.as_ref(), aad: &header })
        .map_err(|_| HeartwoodError::InvalidWrappedNsec)?;
    let mut record = Vec::with_capacity(RECORD_LEN);
    record.extend_from_slice(&header);
    record.extend_from_slice(&encrypted);
    Ok(format!("nstw1:{}", URL_SAFE_NO_PAD.encode(record)))
}

/// Encrypt an existing raw key. Recovery requires this record AND the same root.
pub fn wrap_nsec(root: &TreeRoot, raw: &[u8; 32]) -> Result<String, HeartwoodError> {
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 12];
    OsRng.try_fill_bytes(&mut salt).map_err(|_| HeartwoodError::InvalidWrappedNsec)?;
    OsRng.try_fill_bytes(&mut nonce).map_err(|_| HeartwoodError::InvalidWrappedNsec)?;
    wrap_with_entropy(root, raw, &salt, &nonce)
}

/// Authenticate and restore the exact raw key, optionally checking its expected npub.
pub fn unwrap_nsec(
    root: &TreeRoot,
    record: &str,
    expected_npub: Option<&str>,
) -> Result<UnwrappedNsec, HeartwoodError> {
    if record.len() != 181 || !record.starts_with("nstw1:") {
        return Err(HeartwoodError::InvalidWrappedNsec);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(&record.as_bytes()[6..])
        .map_err(|_| HeartwoodError::InvalidWrappedNsec)?;
    if bytes.len() != RECORD_LEN
        || bytes[..7] != *MAGIC
        || URL_SAFE_NO_PAD.encode(&bytes) != record[6..]
    {
        return Err(HeartwoodError::InvalidWrappedNsec);
    }
    let payload = Zeroizing::new(
        cipher(root, &bytes[7..39])?
            .decrypt(
                Nonce::from_slice(&bytes[39..51]),
                Payload { msg: &bytes[HEADER_LEN..], aad: &bytes[..HEADER_LEN] },
            )
            .map_err(|_| HeartwoodError::InvalidWrappedNsec)?,
    );
    if payload.len() != 64 {
        return Err(HeartwoodError::InvalidWrappedNsec);
    }
    let public = public_key(&payload[..32])?;
    let npub = encode_npub(&public);
    if payload[32..] != public || expected_npub.is_some_and(|expected| expected != npub) {
        return Err(HeartwoodError::InvalidWrappedNsec);
    }
    let mut private_key = Zeroizing::new([0u8; 32]);
    private_key.copy_from_slice(&payload[..32]);
    Ok(UnwrappedNsec { private_key, public_key: public, npub })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn matches_shared_vector_in_both_directions() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/wrapped-nsec-v1.json")).unwrap();
        let root = crate::from_nsec_bytes(&[0x11; 32]).unwrap();
        let salt = core::array::from_fn(|i| i as u8);
        let nonce = core::array::from_fn(|i| (32 + i) as u8);
        assert_eq!(wrap_with_entropy(&root, &[0x22; 32], &salt, &nonce).unwrap(), v["record"]);
    }
}
