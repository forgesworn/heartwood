// crates/heartwood-device/src/storage.rs
//! Encrypted secret storage on the device filesystem.

// Scaffold: `config_path`, `ensure_dir`, `save_master_secret`,
// `load_master_secret`, `save_config`, and `load_config` will be called from
// the setup and recovery flows in Phase 2.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::Argon2;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

// --- Encryption at rest (AES-256-GCM + Argon2id) ---

const ENCRYPTION_V1: u8 = 0x01;
const ENCRYPTION_V2: u8 = 0x02;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
/// Minimum blob size: version (1) + salt (16) + nonce (12) + GCM tag (16) = 45
const MIN_ENCRYPTED_LEN: usize = 1 + SALT_LEN + NONCE_LEN + 16;

/// Encryption error — wrong PIN or corrupt/truncated blob.
#[derive(Debug)]
pub enum EncryptionError {
    InvalidFormat,
    DecryptionFailed,
}

impl std::fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFormat => write!(f, "invalid encrypted format"),
            Self::DecryptionFailed => write!(f, "decryption failed (wrong PIN?)"),
        }
    }
}

impl std::error::Error for EncryptionError {}

/// Derive a 256-bit key from a PIN/passphrase and salt using Argon2id.
///
/// V1: m=19456 KiB (19 MiB), t=2, p=1 — original library defaults.
/// V2: m=65536 KiB (64 MiB), t=3, p=1 — stronger params for Pi Zero 2 W.
fn derive_key(pin: &str, salt: &[u8], version: u8) -> Zeroizing<[u8; KEY_LEN]> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    let params = match version {
        ENCRYPTION_V1 => argon2::Params::new(19456, 2, 1, Some(KEY_LEN)),
        _ => argon2::Params::new(65536, 3, 1, Some(KEY_LEN)),
    }
    .expect("valid Argon2 params");
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    argon2
        .hash_password_into(pin.as_bytes(), salt, key.as_mut())
        .expect("Argon2id key derivation failed");
    key
}

/// Encrypt plaintext with AES-256-GCM keyed from a PIN via Argon2id.
///
/// Always writes the latest version (V2). On-disk format:
/// `[version 1B][salt 16B][nonce 12B][ciphertext + GCM tag]`
#[allow(deprecated)] // Nonce::from_slice — aes-gcm 0.10 uses generic-array 0.x
pub fn encrypt_with_pin(pin: &str, plaintext: &[u8]) -> Vec<u8> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let key = derive_key(pin, &salt, ENCRYPTION_V2);
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).expect("key length mismatch");
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).expect("AES-GCM encryption failed");

    let mut blob = Vec::with_capacity(1 + SALT_LEN + NONCE_LEN + ciphertext.len());
    blob.push(ENCRYPTION_V2);
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    blob
}

/// Decrypt a blob produced by [`encrypt_with_pin`].
///
/// Returns the plaintext and the version byte that was used. Callers can
/// check `needs_migration(version)` to decide whether to re-encrypt.
#[allow(deprecated)] // Nonce::from_slice — aes-gcm 0.10 uses generic-array 0.x
pub fn decrypt_with_pin(pin: &str, blob: &[u8]) -> Result<(Zeroizing<Vec<u8>>, u8), EncryptionError> {
    if blob.len() < MIN_ENCRYPTED_LEN {
        return Err(EncryptionError::InvalidFormat);
    }
    let version = blob[0];
    if version != ENCRYPTION_V1 && version != ENCRYPTION_V2 {
        return Err(EncryptionError::InvalidFormat);
    }

    let salt = &blob[1..1 + SALT_LEN];
    let nonce_bytes = &blob[1 + SALT_LEN..1 + SALT_LEN + NONCE_LEN];
    let ciphertext = &blob[1 + SALT_LEN + NONCE_LEN..];

    let key = derive_key(pin, salt, version);
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).expect("key length mismatch");
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map(|pt| (Zeroizing::new(pt), version))
        .map_err(|_| EncryptionError::DecryptionFailed)
}

/// Returns `true` if the blob was encrypted with an older KDF version.
pub fn needs_migration(version: u8) -> bool {
    version < ENCRYPTION_V2
}

/// Returns `true` if the data looks like an encrypted blob (starts with a known version byte).
///
/// Plaintext legacy files start with ASCII text (`bunker:`, `tree-mnemonic:`, `tree-nsec:`),
/// so checking the first byte against the version markers is sufficient.
pub fn is_encrypted(data: &[u8]) -> bool {
    matches!(data.first(), Some(&ENCRYPTION_V1) | Some(&ENCRYPTION_V2))
        && data.len() >= MIN_ENCRYPTED_LEN
}

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
pub(crate) fn write_secret_file(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file =
        fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
    io::Write::write_all(&mut file, data)?;
    Ok(())
}

/// Write secret material to a file (non-Unix fallback).
#[cfg(not(unix))]
pub(crate) fn write_secret_file(path: &Path, data: &[u8]) -> io::Result<()> {
    fs::write(path, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let pin = "1234";
        let plaintext = b"bunker:nsec1abc123";
        let blob = encrypt_with_pin(pin, plaintext);
        assert_eq!(blob[0], ENCRYPTION_V2, "new blobs must use V2");
        let (decrypted, version) = decrypt_with_pin(pin, &blob).expect("decryption failed");
        assert_eq!(&*decrypted, plaintext);
        assert_eq!(version, ENCRYPTION_V2);
        assert!(!needs_migration(version));
    }

    #[test]
    fn v1_blob_decrypts_and_flags_migration() {
        // Simulate a V1 blob by encrypting with V1 params directly.
        let pin = "1234";
        let plaintext = b"bunker:nsec1abc123";

        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);

        let key = derive_key(pin, &salt, ENCRYPTION_V1);
        let cipher = Aes256Gcm::new_from_slice(key.as_ref()).unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, &plaintext[..]).unwrap();

        let mut blob = Vec::with_capacity(1 + SALT_LEN + NONCE_LEN + ciphertext.len());
        blob.push(ENCRYPTION_V1);
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ciphertext);

        let (decrypted, version) = decrypt_with_pin(pin, &blob).expect("V1 decryption failed");
        assert_eq!(&*decrypted, plaintext);
        assert_eq!(version, ENCRYPTION_V1);
        assert!(needs_migration(version));
    }

    #[test]
    fn wrong_pin_fails() {
        let blob = encrypt_with_pin("1234", b"secret data");
        let result = decrypt_with_pin("9999", &blob);
        assert!(result.is_err());
    }

    #[test]
    fn truncated_blob_fails() {
        let result = decrypt_with_pin("1234", &[ENCRYPTION_V1, 0, 0]);
        assert!(matches!(result, Err(EncryptionError::InvalidFormat)));
    }

    #[test]
    fn wrong_version_byte_fails() {
        let mut blob = encrypt_with_pin("1234", b"data");
        blob[0] = 0xFF;
        let result = decrypt_with_pin("1234", &blob);
        assert!(matches!(result, Err(EncryptionError::InvalidFormat)));
    }

    #[test]
    fn is_encrypted_detects_encrypted_blob() {
        let blob = encrypt_with_pin("5678", b"tree-nsec:nsec1xyz");
        assert!(is_encrypted(&blob));
    }

    #[test]
    fn is_encrypted_detects_v1_blob() {
        // A blob starting with 0x01 and long enough is detected
        let mut blob = vec![ENCRYPTION_V1; MIN_ENCRYPTED_LEN];
        blob[0] = ENCRYPTION_V1;
        assert!(is_encrypted(&blob));
    }

    #[test]
    fn is_encrypted_rejects_plaintext() {
        assert!(!is_encrypted(b"bunker:nsec1abc123"));
        assert!(!is_encrypted(b"tree-mnemonic::abandon ability"));
        assert!(!is_encrypted(b"tree-nsec:nsec1xyz"));
    }

    #[test]
    fn is_encrypted_rejects_empty() {
        assert!(!is_encrypted(&[]));
    }

    #[test]
    fn different_encryptions_produce_different_blobs() {
        let pin = "4321";
        let plaintext = b"same data";
        let blob1 = encrypt_with_pin(pin, plaintext);
        let blob2 = encrypt_with_pin(pin, plaintext);
        // Different random salt and nonce each time
        assert_ne!(blob1, blob2);
        // But both decrypt to the same plaintext
        assert_eq!(&*decrypt_with_pin(pin, &blob1).unwrap().0, plaintext);
        assert_eq!(&*decrypt_with_pin(pin, &blob2).unwrap().0, plaintext);
    }

    #[test]
    fn storage_round_trip() {
        let dir = std::env::temp_dir().join(format!("heartwood-test-{}", std::process::id()));
        let storage = Storage::new(Some(dir.clone()));

        let pin = "5555";
        let payload = b"bunker:nsec1testkey";
        let encrypted = encrypt_with_pin(pin, payload);

        storage.save_master_secret(&encrypted).unwrap();
        assert!(storage.has_master_secret());

        let loaded = storage.load_master_secret().unwrap();
        assert!(is_encrypted(&loaded));

        let (decrypted, _) = decrypt_with_pin(pin, &loaded).unwrap();
        assert_eq!(&*decrypted, payload);

        storage.delete_master_secret().unwrap();
        assert!(!storage.has_master_secret());

        let _ = fs::remove_dir_all(dir);
    }
}
