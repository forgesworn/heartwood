// crates/heartwood-nip46/src/methods.rs
//! NIP-46 request and response types, including Heartwood extensions.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A NIP-46 request from a remote client.
///
/// Custom `Debug` to avoid leaking secret material (plaintext, keys) from params.
#[derive(Clone, Serialize, Deserialize)]
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

/// Custom `Debug` that redacts param contents to prevent secret leakage in logs.
impl fmt::Debug for Nip46Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GetPublicKey => write!(f, "GetPublicKey"),
            Self::SignEvent(p) => write!(f, "SignEvent([{} params])", p.len()),
            Self::Nip44Encrypt(p) => write!(f, "Nip44Encrypt([{} params])", p.len()),
            Self::Nip44Decrypt(p) => write!(f, "Nip44Decrypt([{} params])", p.len()),
            Self::Nip04Encrypt(p) => write!(f, "Nip04Encrypt([{} params])", p.len()),
            Self::Nip04Decrypt(p) => write!(f, "Nip04Decrypt([{} params])", p.len()),
            Self::HeartwoodDerive(p) => write!(f, "HeartwoodDerive([{} params])", p.len()),
            Self::HeartwoodDerivePersona(p) => write!(f, "HeartwoodDerivePersona([{} params])", p.len()),
            Self::HeartwoodListIdentities => write!(f, "HeartwoodListIdentities"),
            Self::HeartwoodSwitch(p) => write!(f, "HeartwoodSwitch([{} params])", p.len()),
            Self::HeartwoodCreateProof(p) => write!(f, "HeartwoodCreateProof([{} params])", p.len()),
            Self::HeartwoodVerifyProof(p) => write!(f, "HeartwoodVerifyProof([{} params])", p.len()),
            Self::HeartwoodRecover(p) => write!(f, "HeartwoodRecover([{} params])", p.len()),
        }
    }
}

/// A NIP-46 response sent back to the remote client.
///
/// Fields are private to enforce nsec filtering via the `ok()` constructor.
/// Use `ok()` and `err()` to create instances. Use accessors to read fields.
#[non_exhaustive]
#[derive(Clone, Serialize, Deserialize)]
pub struct Nip46Response {
    /// The request `id` this response correlates to.
    id: String,

    /// Successful result payload (present when `error` is `None`).
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,

    /// Error message (present when the request could not be fulfilled).
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Custom `Debug` that redacts result contents.
impl fmt::Debug for Nip46Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Nip46Response")
            .field("id", &self.id)
            .field("result", &self.result.as_ref().map(|_| "[redacted]"))
            .field("error", &self.error)
            .finish()
    }
}

/// Check whether a JSON value contains an nsec string anywhere in its tree.
fn contains_nsec(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(s) => s.starts_with("nsec1"),
        serde_json::Value::Array(arr) => arr.iter().any(contains_nsec),
        serde_json::Value::Object(map) => map.values().any(contains_nsec),
        _ => false,
    }
}

impl Nip46Response {
    /// Construct a successful response.
    ///
    /// Returns an error response if the result contains nsec material.
    pub fn ok(id: impl Into<String>, result: serde_json::Value) -> Self {
        let id = id.into();
        if contains_nsec(&result) {
            return Self { id, result: None, error: Some("response contained secret key material".into()) };
        }
        Self { id, result: Some(result), error: None }
    }

    /// Construct an error response.
    pub fn err(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self { id: id.into(), result: None, error: Some(message.into()) }
    }

    /// The request ID this response correlates to.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The successful result payload, if present.
    pub fn result(&self) -> Option<&serde_json::Value> {
        self.result.as_ref()
    }

    /// The error message, if present.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
}
