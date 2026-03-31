// crates/heartwood-core/src/persona.rs
use crate::derive::{derive, derive_from_identity};
use crate::types::{HeartwoodError, Identity, Persona, TreeRoot};

/// Derive a named persona from a tree root.
///
/// The purpose string is constructed as `nostr:persona:{name}`.
/// Index defaults to 0 if not specified.
pub fn derive_persona(
    root: &TreeRoot,
    name: &str,
    index: Option<u32>,
) -> Result<Persona, HeartwoodError> {
    let purpose = format!("nostr:persona:{name}");
    let idx = index.unwrap_or(0);
    let identity = derive(root, &purpose, idx)?;

    Ok(Persona {
        identity,
        name: name.to_string(),
        index: idx,
    })
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
