// crates/heartwood-nip46/src/session.rs
//! Client session management.

use std::collections::HashMap;
use std::time::Instant;

use crate::permissions::ClientPermissions;

/// A single authenticated client session.
pub struct ClientSession {
    /// The client's Nostr public key (hex).
    pub client_pubkey: String,

    /// Per-client permissions and rate-limit state.
    pub permissions: ClientPermissions,

    /// When this session was established.
    pub connected_at: Instant,
}

impl ClientSession {
    /// Create a new session for `client_pubkey` with default permissions.
    pub fn new(client_pubkey: impl Into<String>) -> Self {
        Self {
            client_pubkey: client_pubkey.into(),
            permissions: ClientPermissions::default(),
            connected_at: Instant::now(),
        }
    }
}

/// Manages all active client sessions keyed by client public key.
pub struct SessionManager {
    sessions: HashMap<String, ClientSession>,
}

impl SessionManager {
    /// Create an empty session manager.
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Register a new session, replacing any existing one for the same pubkey.
    pub fn add(&mut self, session: ClientSession) {
        self.sessions.insert(session.client_pubkey.clone(), session);
    }

    /// Look up a session by client public key.
    pub fn get(&self, client_pubkey: &str) -> Option<&ClientSession> {
        self.sessions.get(client_pubkey)
    }

    /// Look up a session mutably (needed for rate-limit tracking).
    pub fn get_mut(&mut self, client_pubkey: &str) -> Option<&mut ClientSession> {
        self.sessions.get_mut(client_pubkey)
    }

    /// Remove and return the session for `client_pubkey`, if present.
    pub fn remove(&mut self, client_pubkey: &str) -> Option<ClientSession> {
        self.sessions.remove(client_pubkey)
    }

    /// Return a list of all active client public keys.
    pub fn list(&self) -> Vec<&str> {
        self.sessions.keys().map(String::as_str).collect()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}
