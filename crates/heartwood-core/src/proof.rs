// crates/heartwood-core/src/proof.rs
use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use signature::{Signer, Verifier};

use crate::encoding::bytes_to_hex;
use crate::types::{HeartwoodError, Identity, LinkageProof, TreeRoot};
use crate::validate::validate_proof_purpose;

/// True if `s` is exactly 64 ASCII lowercase hex characters.
fn is_lower_hex_64(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

/// True if `s` is exactly 128 ASCII lowercase hex characters (BIP-340 signature).
fn is_lower_hex_128(s: &str) -> bool {
    s.len() == 128 && s.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

/// Reconstruct the canonical attestation string from a LinkageProof's fields,
/// or return `None` if the fields are structurally invalid (bad hex, out-of-range
/// index, reserved characters in purpose, mismatched purpose/index optional pair).
///
/// Matches the TypeScript `canonicalAttestation` helper introduced in
/// nsec-tree 1.4.4 so that both implementations agree on which proofs are
/// structurally valid before checking the Schnorr signature.
fn canonical_attestation(proof: &LinkageProof) -> Option<String> {
    if !is_lower_hex_64(&proof.master_pubkey) || !is_lower_hex_64(&proof.child_pubkey) {
        return None;
    }
    match (&proof.purpose, proof.index) {
        (None, None) => {
            Some(format!("nsec-tree:own|{}|{}", proof.master_pubkey, proof.child_pubkey))
        }
        (Some(purpose), Some(index)) => {
            // `index` is u32 so it cannot exceed MAX_INDEX (= u32::MAX); the
            // explicit bounds check that appears in the TypeScript port is
            // redundant here and is elided.
            if validate_proof_purpose(purpose).is_err() {
                return None;
            }
            Some(format!(
                "nsec-tree:link|{}|{}|{}|{}",
                proof.master_pubkey, proof.child_pubkey, purpose, index
            ))
        }
        _ => None, // purpose and index must both be present or both absent
    }
}

/// Create a blind linkage proof (no purpose/index revealed).
///
/// Attestation format: `nsec-tree:own|{master_hex}|{child_hex}`
/// Signed with the master (root) secret key using BIP-340 Schnorr.
pub fn create_blind_proof(
    root: &TreeRoot,
    child: &Identity,
) -> Result<LinkageProof, HeartwoodError> {
    let signing_key = SigningKey::from_bytes(root.secret())
        .map_err(|e| HeartwoodError::Derivation(format!("invalid root key: {e}")))?;

    let master_hex = bytes_to_hex(&signing_key.verifying_key().to_bytes());
    let child_hex = bytes_to_hex(&child.public_key);

    let attestation = format!("nsec-tree:own|{master_hex}|{child_hex}");

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
/// Attestation format: `nsec-tree:link|{master_hex}|{child_hex}|{purpose}|{index}`
/// Signed with the master (root) secret key using BIP-340 Schnorr.
///
/// The child's purpose is validated against the stricter proof-layer rules
/// (`validate_proof_purpose`): no `|`, no control characters. A purpose that
/// the derivation layer accepted might still be rejected here if it contains
/// control characters — call `validate_proof_purpose` early in an
/// application if the proof needs to be created later.
pub fn create_full_proof(
    root: &TreeRoot,
    child: &Identity,
) -> Result<LinkageProof, HeartwoodError> {
    validate_proof_purpose(&child.purpose)?;

    let signing_key = SigningKey::from_bytes(root.secret())
        .map_err(|e| HeartwoodError::Derivation(format!("invalid root key: {e}")))?;

    let master_hex = bytes_to_hex(&signing_key.verifying_key().to_bytes());
    let child_hex = bytes_to_hex(&child.public_key);

    let attestation =
        format!("nsec-tree:link|{master_hex}|{child_hex}|{}|{}", child.purpose, child.index);

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
/// Returns `Ok(true)` if the proof is structurally well-formed, the
/// attestation matches the canonical reconstruction from its fields, and
/// the signature verifies against the master pubkey. Returns `Ok(false)`
/// for any failure of those checks. Returns `Err(HeartwoodError::InvalidProof)`
/// only for unparseable master-pubkey or signature hex (a structural error
/// at the field-level that canonical_attestation should catch, but kept as
/// error for backwards compatibility).
///
/// Matches the TypeScript `verifyProof` semantics in nsec-tree 1.4.4:
/// signature is verified over the locally reconstructed canonical
/// attestation, not over the caller-supplied `proof.attestation` string.
/// The two are proven equal via strict equality first; using the
/// reconstructed form makes the invariant explicit and resilient to future
/// refactors.
pub fn verify_proof(proof: &LinkageProof) -> Result<bool, HeartwoodError> {
    let expected = match canonical_attestation(proof) {
        Some(s) => s,
        None => return Ok(false),
    };
    if proof.attestation != expected {
        return Ok(false);
    }
    if !is_lower_hex_128(&proof.signature) {
        return Ok(false);
    }

    let master_bytes =
        hex::decode(&proof.master_pubkey).map_err(|_| HeartwoodError::InvalidProof)?;

    let verifying_key =
        VerifyingKey::from_bytes(&master_bytes).map_err(|_| HeartwoodError::InvalidProof)?;

    let sig_bytes = hex::decode(&proof.signature).map_err(|_| HeartwoodError::InvalidProof)?;

    let signature =
        Signature::try_from(sig_bytes.as_slice()).map_err(|_| HeartwoodError::InvalidProof)?;

    // Verify over the reconstructed canonical attestation, not proof.attestation.
    match verifying_key.verify(expected.as_bytes(), &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}
