use crate::types::HeartwoodError;

/// Maximum purpose string length in UTF-8 bytes.
const MAX_PURPOSE_BYTES: usize = 255;

/// Validate a purpose string for derivation.
///
/// Rules: non-empty, max 255 UTF-8 bytes, no null bytes, not whitespace-only.
pub fn validate_purpose(purpose: &str) -> Result<(), HeartwoodError> {
    if purpose.is_empty() {
        return Err(HeartwoodError::InvalidPurpose(
            "purpose must not be empty".into(),
        ));
    }
    if purpose.as_bytes().len() > MAX_PURPOSE_BYTES {
        return Err(HeartwoodError::InvalidPurpose(
            "purpose exceeds 255 bytes".into(),
        ));
    }
    if purpose.contains('\0') {
        return Err(HeartwoodError::InvalidPurpose(
            "purpose must not contain null bytes".into(),
        ));
    }
    if purpose.trim().is_empty() {
        return Err(HeartwoodError::InvalidPurpose(
            "purpose must not be whitespace-only".into(),
        ));
    }
    Ok(())
}
