// crates/heartwood-core/src/root.rs
use hmac::{Hmac, Mac};
use k256::schnorr::SigningKey;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::encoding::{decode_nsec, encode_npub};
use crate::types::{HeartwoodError, TreeRoot, MNEMONIC_PATH, NSEC_ROOT_LABEL};

type HmacSha256 = Hmac<Sha256>;

/// Create a TreeRoot directly from a 32-byte secret (no HMAC intermediate).
///
/// Derives the BIP-340 x-only public key and encodes it as npub.
/// Takes the secret by reference to avoid copying it onto the stack.
pub(crate) fn create_tree_root(secret: &[u8; 32]) -> Result<TreeRoot, HeartwoodError> {
    let signing_key = SigningKey::from_bytes(secret)
        .map_err(|e| HeartwoodError::Derivation(format!("invalid secret key: {e}")))?;
    let verifying_key = signing_key.verifying_key();
    let pubkey_bytes: [u8; 32] = verifying_key.to_bytes().into();
    let master_pubkey = encode_npub(&pubkey_bytes);
    Ok(TreeRoot::new(zeroize::Zeroizing::new(*secret), master_pubkey))
}

/// Create a TreeRoot from raw nsec bytes using the HMAC intermediate.
///
/// 1. `tree_root_secret = HMAC-SHA256(key=nsec_bytes, msg="nsec-tree-root")`
/// 2. Derive BIP-340 x-only public key from tree_root_secret
/// 3. Encode as npub
pub fn from_nsec_bytes(nsec_bytes: &[u8; 32]) -> Result<TreeRoot, HeartwoodError> {
    let mut mac = HmacSha256::new_from_slice(nsec_bytes)
        .map_err(|e| HeartwoodError::Derivation(format!("HMAC init failed: {e}")))?;
    mac.update(NSEC_ROOT_LABEL);
    let result = mac.finalize();
    let mut tree_root_secret: [u8; 32] = result.into_bytes().into();
    let result = create_tree_root(&tree_root_secret);
    tree_root_secret.zeroize();
    result
}

/// Create a TreeRoot from a bech32-encoded nsec string.
pub fn from_nsec(nsec: &str) -> Result<TreeRoot, HeartwoodError> {
    let mut nsec_bytes = decode_nsec(nsec)?;
    let result = from_nsec_bytes(&nsec_bytes);
    nsec_bytes.zeroize();
    result
}

/// Create a TreeRoot from a BIP-39 mnemonic phrase.
///
/// 1. Validate the mnemonic
/// 2. Generate seed via PBKDF2 (with optional passphrase)
/// 3. Derive BIP-32 HDKey at path m/44'/1237'/727'/0'/0'
/// 4. Use the 32-byte private key directly as tree root secret (NO HMAC intermediate)
pub fn from_mnemonic(mnemonic: &str, passphrase: Option<&str>) -> Result<TreeRoot, HeartwoodError> {
    use bip39::Mnemonic;

    let parsed: Mnemonic = mnemonic.parse().map_err(|_| HeartwoodError::InvalidMnemonic)?;

    let seed = zeroize::Zeroizing::new(parsed.to_seed(passphrase.unwrap_or("")));

    let master = bip32::XPrv::new(*seed)
        .map_err(|e| HeartwoodError::Derivation(format!("BIP-32 master key failed: {e}")))?;

    // Parse derivation path and derive step by step
    let path: bip32::DerivationPath = MNEMONIC_PATH
        .parse()
        .map_err(|e| HeartwoodError::Derivation(format!("invalid derivation path: {e}")))?;

    let child = path
        .iter()
        .try_fold(master, |key, child_num| key.derive_child(child_num))
        .map_err(|e| HeartwoodError::Derivation(format!("BIP-32 derivation failed: {e}")))?;

    let mut private_key_bytes = zeroize::Zeroizing::new(child.to_bytes());

    let result = create_tree_root(&private_key_bytes);
    private_key_bytes.zeroize();
    result
}
