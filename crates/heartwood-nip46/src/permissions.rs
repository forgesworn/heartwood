// crates/heartwood-nip46/src/permissions.rs
//! Per-client permission model with kind allowlists, method restrictions, and rate limiting.

use std::collections::HashSet;
use std::time::{Duration, Instant};

/// Methods that require explicit opt-in (sensitive Heartwood extensions).
const PRIVILEGED_METHODS: &[&str] = &[
    "heartwood_derive",
    "heartwood_derive_persona",
    "heartwood_switch",
    "heartwood_create_proof",
    "heartwood_recover",
];

/// Permissions granted to a connected client.
pub struct ClientPermissions {
    /// If `Some`, only these event kinds may be signed. `None` means all kinds.
    pub allowed_kinds: Option<HashSet<u32>>,

    /// Methods this client is allowed to call. If `None`, standard NIP-46 methods
    /// only (no Heartwood extensions). Heartwood extension methods require explicit
    /// opt-in.
    pub allowed_methods: Option<HashSet<String>>,

    /// Maximum number of requests per 60-second window.
    pub rate_limit: u32,

    // --- internal rate-limiting state ---
    window_start: Instant,
    requests_in_window: u32,
}

impl Default for ClientPermissions {
    fn default() -> Self {
        Self {
            allowed_kinds: None,
            allowed_methods: None,
            rate_limit: 60,
            window_start: Instant::now(),
            requests_in_window: 0,
        }
    }
}

impl ClientPermissions {
    /// Create new permissions with all defaults (all kinds, standard methods only, 60 req/min).
    pub fn new() -> Self {
        Self::default()
    }

    /// Return `true` if this client is allowed to sign an event of `kind`.
    pub fn can_sign_kind(&self, kind: u32) -> bool {
        match &self.allowed_kinds {
            None => true,
            Some(set) => set.contains(&kind),
        }
    }

    /// Return `true` if this client is allowed to call the given method.
    ///
    /// Standard NIP-46 methods (get_public_key, sign_event, nip44_*, nip04_*,
    /// heartwood_list_identities, heartwood_verify_proof) are always allowed.
    /// Privileged Heartwood extension methods require explicit opt-in via
    /// `allowed_methods`.
    pub fn can_call_method(&self, method: &str) -> bool {
        if !PRIVILEGED_METHODS.contains(&method) {
            return true;
        }
        match &self.allowed_methods {
            None => false,
            Some(set) => set.contains(method),
        }
    }

    /// Return `true` if the client is within its rate limit.
    ///
    /// Advances the internal counter; resets the window when 60 seconds have
    /// elapsed since the last reset.
    pub fn check_rate_limit(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.window_start);

        if elapsed >= Duration::from_secs(60) {
            // New window -- reset counter.
            self.window_start = now;
            self.requests_in_window = 0;
        }

        if self.requests_in_window < self.rate_limit {
            self.requests_in_window += 1;
            true
        } else {
            false
        }
    }
}
