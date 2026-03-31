// crates/heartwood-device/src/storage.rs
//! Encrypted secret storage on the device filesystem.

// Scaffold: `config_path`, `ensure_dir`, `save_master_secret`,
// `load_master_secret`, `save_config`, and `load_config` will be called from
// the setup and recovery flows in Phase 2.
#![allow(dead_code)]

use std::fs;
use std::io;
use std::path::PathBuf;

/// Filesystem-backed storage for secrets and configuration.
///
/// Secrets are stored as raw bytes; callers are responsible for
/// encryption/decryption (e.g. AES-GCM keyed from the device PIN).
pub struct Storage {
    base_dir: PathBuf,
}

impl Storage {
    /// Create a storage handle rooted at `base_dir`.
    ///
    /// Defaults to `/var/lib/heartwood` when `base_dir` is `None`.
    pub fn new(base_dir: Option<PathBuf>) -> Self {
        let base_dir = base_dir.unwrap_or_else(|| PathBuf::from("/var/lib/heartwood"));
        Self { base_dir }
    }

    fn secret_path(&self) -> PathBuf {
        self.base_dir.join("master.secret")
    }

    fn config_path(&self) -> PathBuf {
        self.base_dir.join("config.json")
    }

    fn ensure_dir(&self) -> io::Result<()> {
        fs::create_dir_all(&self.base_dir)
    }

    /// Return `true` if an encrypted master secret has been stored.
    pub fn has_master_secret(&self) -> bool {
        self.secret_path().exists()
    }

    /// Persist encrypted master secret bytes to disk.
    pub fn save_master_secret(&self, encrypted: &[u8]) -> io::Result<()> {
        self.ensure_dir()?;
        fs::write(self.secret_path(), encrypted)
    }

    /// Load and return the stored encrypted master secret bytes.
    pub fn load_master_secret(&self) -> io::Result<Vec<u8>> {
        fs::read(self.secret_path())
    }

    /// Persist a JSON config string to disk.
    pub fn save_config(&self, config: &str) -> io::Result<()> {
        self.ensure_dir()?;
        fs::write(self.config_path(), config)
    }

    /// Load the stored JSON config string.
    pub fn load_config(&self) -> io::Result<String> {
        fs::read_to_string(self.config_path())
    }
}
