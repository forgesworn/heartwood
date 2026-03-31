// crates/heartwood-core/src/types.rs
use thiserror::Error;
use zeroize::Zeroize;

/// Maximum derivation index (u32::MAX).
pub const MAX_INDEX: u32 = 0xFFFF_FFFF;

/// Default number of indices to scan during recovery.
pub const DEFAULT_SCAN_RANGE: u32 = 20;

/// Maximum allowed scan range.
pub const MAX_SCAN_RANGE: u32 = 10_000;

/// HMAC domain prefix: "nsec-tree\0" as bytes.
pub const DOMAIN_PREFIX: &[u8] = b"nsec-tree\0";

/// Label for intermediate HMAC when creating root from nsec.
pub const NSEC_ROOT_LABEL: &[u8] = b"nsec-tree-root";

/// BIP-32 derivation path for mnemonic root.
pub const MNEMONIC_PATH: &str = "m/44'/1237'/727'/0'/0'";

#[derive(Debug, Error)]
pub enum HeartwoodError {
    #[error("index overflow: no valid key found in range")]
    IndexOverflow,
    #[error("invalid purpose: {0}")]
    InvalidPurpose(String),
    #[error("invalid mnemonic")]
    InvalidMnemonic,
    #[error("invalid nsec")]
    InvalidNsec,
    #[error("invalid npub")]
    InvalidNpub,
    #[error("invalid proof")]
    InvalidProof,
    #[error("scan range must be 1..={MAX_SCAN_RANGE}")]
    InvalidScanRange,
    #[error("invalid persona name: {0}")]
    InvalidPersonaName(String),
    #[error("key derivation failed: {0}")]
    Derivation(String),
}

/// Master tree root. Owns the secret; zeroes on drop.
pub struct TreeRoot {
    secret: zeroize::Zeroizing<[u8; 32]>,
    pub master_pubkey: String, // npub bech32
}

impl TreeRoot {
    pub(crate) fn new(secret: [u8; 32], master_pubkey: String) -> Self {
        Self { secret: zeroize::Zeroizing::new(secret), master_pubkey }
    }

    pub(crate) fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    /// Explicitly destroy the root, zeroising the secret.
    pub fn destroy(mut self) {
        self.secret.zeroize();
    }
}

/// A derived child identity.
pub struct Identity {
    pub npub: String,
    pub private_key: zeroize::Zeroizing<[u8; 32]>,
    pub public_key: [u8; 32],
    pub purpose: String,
    pub index: u32,
}

impl Identity {
    /// Compute the bech32-encoded nsec on demand (never stored in memory).
    pub fn nsec(&self) -> String {
        crate::encoding::encode_nsec(&self.private_key)
    }

    /// Zero the private key bytes.
    pub fn zeroize(&mut self) {
        self.private_key.zeroize();
    }
}

/// A named persona wrapping an identity.
pub struct Persona {
    pub identity: Identity,
    pub name: String,
    pub index: u32,
}

/// A linkage proof (blind or full).
pub struct LinkageProof {
    pub master_pubkey: String, // lowercase hex, 64 chars
    pub child_pubkey: String,  // lowercase hex, 64 chars
    pub purpose: Option<String>,
    pub index: Option<u32>,
    pub attestation: String,
    pub signature: String, // lowercase hex, 128 chars
}
