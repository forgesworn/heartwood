use crate::types::HeartwoodError;

/// Maximum purpose string length in UTF-8 bytes.
const MAX_PURPOSE_BYTES: usize = 255;

/// True if the string contains any C0 control character or DEL (`\x00-\x1F`, `\x7F`).
pub(crate) fn contains_control_char(s: &str) -> bool {
    s.chars().any(|c| {
        let n = c as u32;
        n < 0x20 || n == 0x7F
    })
}

/// Validate a purpose string for derivation.
///
/// Rules (per PROTOCOL.md §3): non-empty, max 255 UTF-8 bytes, no null bytes,
/// not whitespace-only. This Rust implementation additionally rejects `|` at
/// the derivation layer for defence in depth — the TypeScript implementation
/// accepts `|` at derivation but rejects it at the proof layer
/// (`validateProofPurpose`). Both implementations agree on what purposes are
/// legal in a linkage proof; the Rust rule is a strict superset.
pub fn validate_purpose(purpose: &str) -> Result<(), HeartwoodError> {
    if purpose.is_empty() {
        return Err(HeartwoodError::InvalidPurpose("purpose must not be empty".into()));
    }
    if purpose.len() > MAX_PURPOSE_BYTES {
        return Err(HeartwoodError::InvalidPurpose("purpose exceeds 255 bytes".into()));
    }
    if purpose.contains('\0') {
        return Err(HeartwoodError::InvalidPurpose("purpose must not contain null bytes".into()));
    }
    if purpose.contains('|') {
        return Err(HeartwoodError::InvalidPurpose(
            "purpose must not contain '|' (attestation delimiter)".into(),
        ));
    }
    if purpose.trim().is_empty() {
        return Err(HeartwoodError::InvalidPurpose("purpose must not be whitespace-only".into()));
    }
    Ok(())
}

/// Validate a purpose string for embedding in a linkage-proof attestation.
///
/// Extends `validate_purpose` with rejection of C0 and DEL control characters
/// (`\x00-\x1F`, `\x7F`). Matches the TypeScript `validateProofPurpose` helper
/// introduced in nsec-tree 1.4.4 so that cross-implementation verifiers agree
/// on what purposes are legal in a proof.
pub fn validate_proof_purpose(purpose: &str) -> Result<(), HeartwoodError> {
    validate_purpose(purpose)?;
    if contains_control_char(purpose) {
        return Err(HeartwoodError::InvalidPurpose(
            "purpose used in a linkage proof must not contain control characters".into(),
        ));
    }
    Ok(())
}
