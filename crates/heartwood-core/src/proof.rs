// crates/heartwood-core/src/proof.rs
use k256::schnorr::{SigningKey, Signature, VerifyingKey};
use k256::ecdsa::signature::{Signer, Verifier};

use crate::encoding::bytes_to_hex;
use crate::types::{HeartwoodError, Identity, LinkageProof, TreeRoot};

/// Create a blind linkage proof (no purpose/index revealed).
///
/// Attestation format: `nsec-tree:own:{master_hex}:{child_hex}`
/// Signed with the master (root) secret key using BIP-340 Schnorr.
pub fn create_blind_proof(
    root: &TreeRoot,
    child: &Identity,
) -> Result<LinkageProof, HeartwoodError> {
    let signing_key = SigningKey::from_bytes(root.secret())
        .map_err(|e| HeartwoodError::Derivation(format!("invalid root key: {e}")))?;

    let master_hex = bytes_to_hex(&signing_key.verifying_key().to_bytes());
    let child_hex = bytes_to_hex(&child.public_key);

    let attestation = format!("nsec-tree:own:{master_hex}:{child_hex}");

    let sig: Signature = signing_key.sign(attestation.as_bytes());
    let signature = bytes_to_hex(&sig.to_bytes());

    Ok(LinkageProof {
        master_pubkey: master_hex,
        child_pubkey: child_hex,
        purpose: None,
        index: None,
        attestation,
        signature,
    })
}

/// Create a full linkage proof (purpose and index revealed).
///
/// Attestation format: `nsec-tree:link:{master_hex}:{child_hex}:{purpose}:{index}`
/// Signed with the master (root) secret key using BIP-340 Schnorr.
pub fn create_full_proof(
    root: &TreeRoot,
    child: &Identity,
) -> Result<LinkageProof, HeartwoodError> {
    let signing_key = SigningKey::from_bytes(root.secret())
        .map_err(|e| HeartwoodError::Derivation(format!("invalid root key: {e}")))?;

    let master_hex = bytes_to_hex(&signing_key.verifying_key().to_bytes());
    let child_hex = bytes_to_hex(&child.public_key);

    let attestation = format!(
        "nsec-tree:link:{master_hex}:{child_hex}:{}:{}",
        child.purpose, child.index
    );

    let sig: Signature = signing_key.sign(attestation.as_bytes());
    let signature = bytes_to_hex(&sig.to_bytes());

    Ok(LinkageProof {
        master_pubkey: master_hex.clone(),
        child_pubkey: child_hex.clone(),
        purpose: Some(child.purpose.clone()),
        index: Some(child.index),
        attestation,
        signature,
    })
}

/// Verify a linkage proof by checking the BIP-340 Schnorr signature.
///
/// Returns `Ok(true)` if the signature is valid, `Ok(false)` if invalid.
pub fn verify_proof(proof: &LinkageProof) -> Result<bool, HeartwoodError> {
    let master_bytes = hex::decode(&proof.master_pubkey)
        .map_err(|_| HeartwoodError::InvalidProof)?;

    let verifying_key = VerifyingKey::from_bytes(&master_bytes)
        .map_err(|_| HeartwoodError::InvalidProof)?;

    let sig_bytes = hex::decode(&proof.signature)
        .map_err(|_| HeartwoodError::InvalidProof)?;

    let signature = Signature::try_from(sig_bytes.as_slice())
        .map_err(|_| HeartwoodError::InvalidProof)?;

    match verifying_key.verify(proof.attestation.as_bytes(), &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}
