// crates/heartwood-nip46/src/methods.rs
//! NIP-46 request and response types, including Heartwood extensions.

use serde::{Deserialize, Serialize};

/// A NIP-46 request from a remote client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum Nip46Request {
    /// Return the signer's public key.
    GetPublicKey,

    /// Sign a Nostr event (params: [event_json]).
    SignEvent(Vec<serde_json::Value>),

    /// NIP-44 encrypt (params: [peer_pubkey, plaintext]).
    Nip44Encrypt(Vec<serde_json::Value>),

    /// NIP-44 decrypt (params: [peer_pubkey, ciphertext]).
    Nip44Decrypt(Vec<serde_json::Value>),

    /// NIP-04 encrypt (deprecated; params: [peer_pubkey, plaintext]).
    Nip04Encrypt(Vec<serde_json::Value>),

    /// NIP-04 decrypt (deprecated; params: [peer_pubkey, ciphertext]).
    Nip04Decrypt(Vec<serde_json::Value>),

    // ------------------------------------------------------------------
    // Heartwood extensions
    // ------------------------------------------------------------------
    /// Derive a child identity at the given path (params: [purpose, index]).
    HeartwoodDerive(Vec<serde_json::Value>),

    /// Derive a named persona (params: [name]).
    HeartwoodDerivePersona(Vec<serde_json::Value>),

    /// List all known identities for the current root (no params).
    HeartwoodListIdentities,

    /// Switch the active identity to the given npub (params: [npub]).
    HeartwoodSwitch(Vec<serde_json::Value>),

    /// Create a linkage proof between two identities (params: [child_npub]).
    HeartwoodCreateProof(Vec<serde_json::Value>),

    /// Verify a linkage proof (params: [proof_json]).
    HeartwoodVerifyProof(Vec<serde_json::Value>),

    /// Recover identities by scanning derived keys (params: [lookahead?]).
    HeartwoodRecover(Vec<serde_json::Value>),
}

/// A NIP-46 response sent back to the remote client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Nip46Response {
    /// The request `id` this response correlates to.
    pub id: String,

    /// Successful result payload (present when `error` is `None`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,

    /// Error message (present when the request could not be fulfilled).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Nip46Response {
    /// Construct a successful response.
    pub fn ok(id: impl Into<String>, result: serde_json::Value) -> Self {
        Self { id: id.into(), result: Some(result), error: None }
    }

    /// Construct an error response.
    pub fn err(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self { id: id.into(), result: None, error: Some(message.into()) }
    }
}
