// crates/heartwood-device/src/tor.rs
//! Tor daemon management and hidden-service address discovery.

// Scaffold: `with_dir` and `is_running` will be called from the main daemon
// and health-check endpoints in Phase 2.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use tracing::{info, warn};

/// Manages the Tor hidden service for the Heartwood web UI.
pub struct TorManager {
    onion_dir: PathBuf,
}

impl TorManager {
    /// Create a manager using the default onion directory
    /// (`/var/lib/tor/heartwood`).
    pub fn new() -> Self {
        Self { onion_dir: PathBuf::from("/var/lib/tor/heartwood") }
    }

    /// Create a manager with a custom onion directory path.
    pub fn with_dir(onion_dir: PathBuf) -> Self {
        Self { onion_dir }
    }

    /// Read the `.onion` hostname from Tor's `hostname` file, if present.
    pub fn onion_address(&self) -> Option<String> {
        let hostname_path = self.onion_dir.join("hostname");
        fs::read_to_string(&hostname_path)
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
    }

    /// Poll for the onion address until it appears or `timeout_secs` elapses.
    ///
    /// Returns `Some(address)` on success, `None` on timeout.
    pub async fn wait_for_onion(&self, timeout_secs: u64) -> Option<String> {
        let poll_interval = Duration::from_secs(1);
        let mut elapsed = 0u64;

        loop {
            if let Some(addr) = self.onion_address() {
                // .onion addresses are ASCII, but use get() to be panic-free.
                let truncated = addr.get(..8).unwrap_or(&addr);
                info!("Tor onion address ready: {}...", truncated);
                return Some(addr);
            }

            if elapsed >= timeout_secs {
                warn!("Tor onion address not ready after {}s", timeout_secs);
                return None;
            }

            tokio::time::sleep(poll_interval).await;
            elapsed += 1;
        }
    }

    /// Return `true` if the `tor` systemd unit is currently active.
    pub fn is_running(&self) -> bool {
        Command::new("systemctl")
            .args(["is-active", "--quiet", "tor"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

impl Default for TorManager {
    fn default() -> Self {
        Self::new()
    }
}
