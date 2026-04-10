// crates/heartwood-core/src/persona.rs
use crate::derive::{derive, derive_from_identity};
use crate::types::{HeartwoodError, Identity, Persona, TreeRoot};
use crate::validate::contains_control_char;

/// Validate that a persona name is a sane string for interpolation into a
/// derivation purpose and for cross-implementation storage.
///
/// Rejects: empty, whitespace-only, `|` (the linkage-proof attestation
/// delimiter), and C0/DEL control characters. Matches the TypeScript
/// `validatePersonaName` helper tightened in nsec-tree 1.4.4.
fn validate_persona_name(name: &str) -> Result<(), HeartwoodError> {
    if name.is_empty() {
        return Err(HeartwoodError::InvalidPersonaName(
            "persona name must not be empty".into(),
        ));
    }
    if name.trim().is_empty() {
        return Err(HeartwoodError::InvalidPersonaName(
            "persona name must not be whitespace-only".into(),
        ));
    }
    if name.contains('|') {
        return Err(HeartwoodError::InvalidPersonaName(
            "persona name must not contain '|' (attestation delimiter)".into(),
        ));
    }
    if contains_control_char(name) {
        return Err(HeartwoodError::InvalidPersonaName(
            "persona name must not contain control characters".into(),
        ));
    }
    Ok(())
}

/// Derive a named persona from a tree root.
///
/// The purpose string is constructed as `nostr:persona:{name}`.
/// Index defaults to 0 if not specified.
pub fn derive_persona(
    root: &TreeRoot,
    name: &str,
    index: Option<u32>,
) -> Result<Persona, HeartwoodError> {
    validate_persona_name(name)?;
    let purpose = format!("nostr:persona:{name}");
    let idx = index.unwrap_or(0);
    let identity = derive(root, &purpose, idx)?;

    Ok(Persona { identity, name: name.to_string(), index: idx })
}

/// Derive a sub-identity from an existing persona.
///
/// Uses the persona's identity as a parent key and derives a child
/// from it, enabling two-level key hierarchies (root -> persona -> sub-identity).
pub fn derive_from_persona(
    persona: &Persona,
    purpose: &str,
    index: Option<u32>,
) -> Result<Identity, HeartwoodError> {
    let idx = index.unwrap_or(0);
    derive_from_identity(&persona.identity, purpose, idx)
}
