// crates/heartwood-device/src/audit.rs
//! Signing audit log with a bounded ring-buffer.

// Scaffold: `log` and `recent` will be called from the NIP-46 server and the
// web API once those layers are wired up in Phase 2.

use std::collections::VecDeque;

use serde::Serialize;

const MAX_ENTRIES: usize = 1000;

/// A single entry in the audit log.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    /// Unix timestamp (seconds since epoch).
    pub timestamp: u64,

    /// Hex-encoded public key of the requesting client.
    pub client_pubkey: String,

    /// The NIP-46 method name (e.g. `"sign_event"`).
    pub method: String,

    /// Nostr event kind, when applicable (e.g. `Some(1)` for a text note).
    pub event_kind: Option<u32>,

    /// The npub of the identity that produced the signature.
    pub identity_npub: String,
}

/// In-memory audit log backed by a `VecDeque` ring buffer (max 1 000 entries).
pub struct AuditLog {
    entries: VecDeque<AuditEntry>,
}

impl AuditLog {
    /// Create an empty audit log.
    pub fn new() -> Self {
        Self { entries: VecDeque::with_capacity(MAX_ENTRIES) }
    }

    /// Append an entry to the log, evicting the oldest if at capacity.
    pub fn log(&mut self, entry: AuditEntry) {
        if self.entries.len() >= MAX_ENTRIES {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
    }

    /// Return all log entries in chronological order.
    pub fn entries(&self) -> &VecDeque<AuditEntry> {
        &self.entries
    }

    /// Return the `count` most-recent entries, oldest-first.
    pub fn recent(&self, count: usize) -> Vec<&AuditEntry> {
        self.entries.iter().rev().take(count).collect::<Vec<_>>().into_iter().rev().collect()
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}
