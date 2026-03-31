// crates/heartwood-nip46/src/server.rs
//! Heartwood NIP-46 server state.

use std::sync::Mutex;

use heartwood_core::TreeRoot;

use crate::session::SessionManager;

/// The Heartwood NIP-46 server state.
pub struct HeartwoodServer {
    // Full request handling will be implemented when integrating
    // with Nostr relay WebSocket layer.
    #[allow(dead_code)]
    root: Option<TreeRoot>,

    #[allow(dead_code)]
    sessions: Mutex<SessionManager>,
}

impl HeartwoodServer {
    /// Create a new server instance with no loaded root key.
    pub fn new() -> Self {
        Self {
            root: None,
            sessions: Mutex::new(SessionManager::new()),
        }
    }

    /// Create a server instance pre-loaded with a root key.
    pub fn with_root(root: TreeRoot) -> Self {
        Self {
            root: Some(root),
            sessions: Mutex::new(SessionManager::new()),
        }
    }
}

impl Default for HeartwoodServer {
    fn default() -> Self {
        Self::new()
    }
}
