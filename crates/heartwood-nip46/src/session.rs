// crates/heartwood-nip46/src/session.rs
//! Client session management with expiry and limits.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::permissions::ClientPermissions;

/// Maximum number of concurrent sessions.
const MAX_SESSIONS: usize = 32;

/// Session idle timeout (10 minutes).
const SESSION_TTL: Duration = Duration::from_secs(600);

/// Validate that a string is a 64-character lowercase hex public key.
fn is_valid_hex_pubkey(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// A single authenticated client session.
pub struct ClientSession {
    /// The client's Nostr public key (64-char lowercase hex).
    pub client_pubkey: String,

    /// Per-client permissions and rate-limit state.
    pub permissions: ClientPermissions,

    /// When this session was established.
    pub connected_at: Instant,

    /// When this session last processed a request.
    last_active: Instant,
}

impl ClientSession {
    /// Create a new session for `client_pubkey` with default permissions.
    ///
    /// Returns `None` if `client_pubkey` is not a valid 64-char lowercase hex string.
    pub fn new(client_pubkey: impl Into<String>) -> Option<Self> {
        let pubkey = client_pubkey.into();
        if !is_valid_hex_pubkey(&pubkey) {
            return None;
        }
        let now = Instant::now();
        Some(Self {
            client_pubkey: pubkey,
            permissions: ClientPermissions::default(),
            connected_at: now,
            last_active: now,
        })
    }

    /// Touch the session to update last-active timestamp.
    pub fn touch(&mut self) {
        self.last_active = Instant::now();
    }

    /// Whether this session has exceeded its idle timeout.
    pub fn is_expired(&self) -> bool {
        self.last_active.elapsed() >= SESSION_TTL
    }
}

/// Manages all active client sessions keyed by client public key.
pub struct SessionManager {
    sessions: HashMap<String, ClientSession>,
}

impl SessionManager {
    /// Create an empty session manager.
    pub fn new() -> Self {
        Self { sessions: HashMap::new() }
    }

    /// Purge expired sessions.
    fn purge_expired(&mut self) {
        self.sessions.retain(|_, s| !s.is_expired());
    }

    /// Register a new session, replacing any existing one for the same pubkey.
    ///
    /// Returns `false` if the session limit would be exceeded (after purging expired).
    pub fn add(&mut self, session: ClientSession) -> bool {
        self.purge_expired();
        // Allow replacement of existing session without counting against limit
        if !self.sessions.contains_key(&session.client_pubkey)
            && self.sessions.len() >= MAX_SESSIONS
        {
            return false;
        }
        self.sessions.insert(session.client_pubkey.clone(), session);
        true
    }

    /// Look up a session by client public key.
    pub fn get(&self, client_pubkey: &str) -> Option<&ClientSession> {
        self.sessions.get(client_pubkey).filter(|s| !s.is_expired())
    }

    /// Look up a session mutably (needed for rate-limit tracking).
    pub fn get_mut(&mut self, client_pubkey: &str) -> Option<&mut ClientSession> {
        self.sessions.get_mut(client_pubkey).filter(|s| !s.is_expired())
    }

    /// Remove and return the session for `client_pubkey`, if present.
    pub fn remove(&mut self, client_pubkey: &str) -> Option<ClientSession> {
        self.sessions.remove(client_pubkey)
    }

    /// Return a list of all active (non-expired) client public keys.
    pub fn list(&self) -> Vec<&str> {
        self.sessions.iter().filter(|(_, s)| !s.is_expired()).map(|(k, _)| k.as_str()).collect()
    }

    /// Return the number of active sessions.
    pub fn active_count(&self) -> usize {
        self.sessions.values().filter(|s| !s.is_expired()).count()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}
