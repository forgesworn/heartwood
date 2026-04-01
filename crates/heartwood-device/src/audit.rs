// crates/heartwood-device/src/audit.rs
//! Signing audit log with a bounded ring-buffer and optional disk persistence.

// Scaffold: `log` and `recent` will be called from the NIP-46 server and the
// web API once those layers are wired up in Phase 2.

use std::collections::VecDeque;
use std::path::PathBuf;

use serde::Serialize;

const MAX_ENTRIES: usize = 1000;
/// Maximum audit log file size before rotation (1 MiB).
#[allow(dead_code)]
const MAX_LOG_FILE_SIZE: u64 = 1_048_576;

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

/// In-memory audit log backed by a `VecDeque` ring buffer (max 1 000 entries)
/// with optional append-only disk persistence.
pub struct AuditLog {
    entries: VecDeque<AuditEntry>,
    /// Path to the on-disk audit log file, if disk persistence is enabled.
    #[allow(dead_code)]
    log_path: Option<PathBuf>,
}

impl AuditLog {
    /// Create an empty audit log without disk persistence.
    pub fn new() -> Self {
        Self { entries: VecDeque::with_capacity(MAX_ENTRIES), log_path: None }
    }

    /// Create an audit log that persists entries to an append-only file.
    ///
    /// The file is capped at 1 MiB; when exceeded, the current file is
    /// rotated to `.1` and a fresh file is started.
    pub fn with_persistence(path: PathBuf) -> Self {
        Self { entries: VecDeque::with_capacity(MAX_ENTRIES), log_path: Some(path) }
    }

    /// Append an entry to the log, evicting the oldest if at capacity.
    ///
    /// If disk persistence is configured, the entry is also appended to the
    /// log file. Write failures are logged but do not prevent in-memory logging.
    #[allow(dead_code)]
    pub fn log(&mut self, entry: AuditEntry) {
        if let Some(path) = &self.log_path {
            if let Err(e) = Self::append_to_file(path, &entry) {
                tracing::warn!("Failed to persist audit entry: {e}");
            }
        }
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
    #[allow(dead_code)]
    pub fn recent(&self, count: usize) -> Vec<&AuditEntry> {
        self.entries.iter().rev().take(count).collect::<Vec<_>>().into_iter().rev().collect()
    }

    /// Append a single entry as a JSON line to the audit log file.
    ///
    /// Rotates the file if it exceeds `MAX_LOG_FILE_SIZE`.
    fn append_to_file(path: &PathBuf, entry: &AuditEntry) -> std::io::Result<()> {
        // Rotate if needed
        if path.exists() {
            if let Ok(meta) = std::fs::metadata(path) {
                if meta.len() >= MAX_LOG_FILE_SIZE {
                    let rotated = path.with_extension("log.1");
                    std::fs::rename(path, rotated)?;
                }
            }
        }

        let line = serde_json::to_string(entry).map_err(std::io::Error::other)?;
        Self::append_line(path, &line)
    }

    #[cfg(unix)]
    fn append_line(path: &PathBuf, line: &str) -> std::io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file =
            std::fs::OpenOptions::new().create(true).append(true).mode(0o600).open(path)?;
        writeln!(file, "{}", line)
    }

    #[cfg(not(unix))]
    fn append_line(path: &PathBuf, line: &str) -> std::io::Result<()> {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
        writeln!(file, "{}", line)
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}
