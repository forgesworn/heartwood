// crates/heartwood-core/src/derive.rs
use hmac::{Hmac, Mac};
use k256::schnorr::SigningKey;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::encoding::encode_npub;
use crate::root::create_tree_root;
use crate::types::{HeartwoodError, Identity, TreeRoot, DOMAIN_PREFIX, MAX_INDEX};
use crate::validate::validate_purpose;

type HmacSha256 = Hmac<Sha256>;

/// Build the HMAC context message for child key derivation.
///
/// Format: `b"nsec-tree\0" || purpose_utf8 || 0x00 || index_u32_big_endian`
fn build_context(purpose: &str, index: u32) -> Vec<u8> {
    let purpose_bytes = purpose.as_bytes();
    let mut msg = Vec::with_capacity(DOMAIN_PREFIX.len() + purpose_bytes.len() + 1 + 4);
    msg.extend_from_slice(DOMAIN_PREFIX);
    msg.extend_from_slice(purpose_bytes);
    msg.push(0x00);
    msg.extend_from_slice(&index.to_be_bytes());
    msg
}

/// Derive a child identity from a TreeRoot.
///
/// Uses HMAC-SHA256 with the root secret as key and a context message
/// containing the domain prefix, purpose, and index. Skips indices that
/// produce invalid secp256k1 scalars (exceeding curve order).
pub fn derive(root: &TreeRoot, purpose: &str, index: u32) -> Result<Identity, HeartwoodError> {
    validate_purpose(purpose)?;

    let secret = root.secret();
    let mut current_index = index;

    loop {
        let context = build_context(purpose, current_index);

        let mut mac = HmacSha256::new_from_slice(secret)
            .map_err(|e| HeartwoodError::Derivation(format!("HMAC init failed: {e}")))?;
        mac.update(&context);
        let result = mac.finalize();
        let mut derived: [u8; 32] = result.into_bytes().into();

        // Try to create a valid secp256k1 signing key
        match SigningKey::from_bytes(&derived) {
            Ok(signing_key) => {
                let verifying_key = signing_key.verifying_key();
                let public_key: [u8; 32] = verifying_key.to_bytes().into();

                return Ok(Identity {
                    npub: encode_npub(&public_key),
                    private_key: zeroize::Zeroizing::new(derived),
                    public_key,
                    purpose: purpose.to_string(),
                    index: current_index,
                });
            }
            Err(_) => {
                derived.zeroize(); // don't leak failed attempt
                // Invalid scalar (exceeds curve order), try next index
                if current_index == MAX_INDEX {
                    return Err(HeartwoodError::IndexOverflow);
                }
                current_index += 1;
            }
        }
    }
}

/// Derive a child identity from an existing identity.
///
/// Creates a transient TreeRoot from the identity's private key using
/// `create_tree_root` directly (no HMAC intermediate), then derives
/// a child from it. This enables arbitrary-depth key hierarchies.
pub fn derive_from_identity(
    identity: &Identity,
    purpose: &str,
    index: u32,
) -> Result<Identity, HeartwoodError> {
    let root = create_tree_root(&*identity.private_key)?;
    derive(&root, purpose, index)
}
