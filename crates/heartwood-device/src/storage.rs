// crates/heartwood-device/src/storage.rs
//! Encrypted secret storage on the device filesystem.

// Scaffold: `config_path`, `ensure_dir`, `save_master_secret`,
// `load_master_secret`, `save_config`, and `load_config` will be called from
// the setup and recovery flows in Phase 2.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

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
        fs::create_dir_all(&self.base_dir)?;
        set_dir_permissions(&self.base_dir)?;
        Ok(())
    }

    /// Return `true` if an encrypted master secret has been stored.
    pub fn has_master_secret(&self) -> bool {
        self.secret_path().exists()
    }

    /// Persist encrypted master secret bytes to disk with restrictive permissions.
    pub fn save_master_secret(&self, encrypted: &[u8]) -> io::Result<()> {
        self.ensure_dir()?;
        write_secret_file(&self.secret_path(), encrypted)
    }

    /// Load and return the stored encrypted master secret bytes.
    pub fn load_master_secret(&self) -> io::Result<Vec<u8>> {
        fs::read(self.secret_path())
    }

    /// Delete the stored master secret, returning to setup mode.
    ///
    /// Overwrites the file contents with zeros before unlinking.
    /// Best-effort on flash storage — the overwrite may not reach the same
    /// physical cells, but it raises the bar meaningfully.
    pub fn delete_master_secret(&self) -> io::Result<()> {
        let path = self.secret_path();
        if path.exists() {
            // Overwrite with zeros before removing
            let len = fs::metadata(&path)?.len() as usize;
            let zeros = vec![0u8; len];
            let mut file = fs::OpenOptions::new().write(true).open(&path)?;
            io::Write::write_all(&mut file, &zeros)?;
            file.sync_all()?;
            drop(file);
            fs::remove_file(path)?;
        }
        Ok(())
    }

    /// Persist a JSON config string to disk with restrictive permissions.
    pub fn save_config(&self, config: &str) -> io::Result<()> {
        self.ensure_dir()?;
        write_secret_file(&self.config_path(), config.as_bytes())
    }

    /// Load the stored JSON config string.
    pub fn load_config(&self) -> io::Result<String> {
        fs::read_to_string(self.config_path())
    }
}

/// Set directory permissions to 0700 (owner only).
#[cfg(unix)]
fn set_dir_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

/// Set directory permissions (non-Unix fallback -- no-op).
#[cfg(not(unix))]
fn set_dir_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// Write secret material to a file with mode 0600 (owner read/write only).
#[cfg(unix)]
fn write_secret_file(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file =
        fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
    io::Write::write_all(&mut file, data)?;
    Ok(())
}

/// Write secret material to a file (non-Unix fallback).
#[cfg(not(unix))]
fn write_secret_file(path: &Path, data: &[u8]) -> io::Result<()> {
    fs::write(path, data)
}
