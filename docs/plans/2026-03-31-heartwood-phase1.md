# Heartwood Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a working Heartwood prototype on Raspberry Pi -- Rust nsec-tree core, NIP-46 server, Tor hidden service, OLED display, web UI setup wizard.

**Architecture:** Single Rust binary running on Raspberry Pi OS Lite. The binary contains the nsec-tree crypto core, a NIP-46 server, and an HTTP server for the web UI. C Tor daemon runs as a system service. OLED driven via I2C from the Rust binary. Secrets stored in an encrypted directory (LUKS or age-encrypted file) unlocked by PIN at boot.

**Tech Stack:** Rust (stable, aarch64-unknown-linux-gnu), k256, hmac, sha2, zeroize, bip32, bip39, bech32, axum (HTTP), ssd1306 (OLED), C Tor, Raspberry Pi OS Lite.

**Dev environment:** Develop and test on macOS/Linux x86_64. Cross-compile for aarch64 or compile natively on the Pi 4. All tests run on the host.

---

## File Structure

```
heartwood/
  Cargo.toml                          # Workspace root
  crates/
    heartwood-core/
      Cargo.toml                      # nsec-tree Rust port (no I/O, pure crypto)
      src/
        lib.rs                        # Public API re-exports
        types.rs                      # TreeRoot, Identity, LinkageProof, Persona, errors, constants
        encoding.rs                   # NIP-19 bech32 encode/decode (nsec, npub, hex)
        validate.rs                   # Purpose string validation
        derive.rs                     # HMAC-SHA256 child key derivation
        root.rs                       # TreeRoot creation (fromNsec, fromMnemonic)
        proof.rs                      # Blind and full linkage proofs (BIP-340 Schnorr)
        persona.rs                    # Named persona derivation, two-level hierarchy
        recover.rs                    # Scan-based identity recovery
    heartwood-nip46/
      Cargo.toml                      # NIP-46 protocol server
      src/
        lib.rs
        server.rs                     # NIP-46 request handler (standard + extensions)
        methods.rs                    # Method dispatch and response building
        permissions.rs                # Per-client kind permissions + rate limiting
        session.rs                    # Client session management (paired clients)
    heartwood-device/
      Cargo.toml                      # Pi-specific: OLED, storage, Tor integration
      src/
        main.rs                       # Entry point, boot sequence, PIN unlock
        oled.rs                       # SSD1306 display driver (status, QR, mnemonic)
        storage.rs                    # Encrypted secret storage (age-encrypted file)
        tor.rs                        # Tor daemon management (start, wait, read .onion)
        web.rs                        # Axum HTTP server for web UI
        audit.rs                      # Signing audit log (ring buffer)
  web/
    index.html                        # Setup wizard + management SPA (single file, <100KB)
  pi/
    setup.sh                          # Pi OS image customisation script
    heartwood.service                 # systemd unit file
    torrc                             # Tor hidden service config template
  tests/
    vectors.rs                        # Frozen test vectors (must match TypeScript exactly)
```

---

## Task 1: Rust workspace and heartwood-core scaffold

**Files:**
- Create: `Cargo.toml` (workspace)
- Create: `crates/heartwood-core/Cargo.toml`
- Create: `crates/heartwood-core/src/lib.rs`
- Create: `crates/heartwood-core/src/types.rs`

- [ ] **Step 1: Create workspace Cargo.toml**

```toml
[workspace]
resolver = "2"
members = [
    "crates/heartwood-core",
]

[workspace.package]
edition = "2021"
license = "MIT"
repository = "https://github.com/forgesworn/heartwood"
```

- [ ] **Step 2: Create heartwood-core Cargo.toml**

```toml
[package]
name = "heartwood-core"
version = "0.1.0"
edition.workspace = true
license.workspace = true
repository.workspace = true
description = "nsec-tree deterministic identity derivation — Rust port"

[dependencies]
k256 = { version = "0.13", features = ["schnorr", "arithmetic"] }
hmac = "0.12"
sha2 = "0.10"
zeroize = { version = "1", features = ["derive"] }
bip32 = "0.5"
bip39 = "2"
bech32 = "0.11"
hex = "0.4"
thiserror = "2"

[dev-dependencies]
```

- [ ] **Step 3: Create types.rs with all type definitions and constants**

```rust
// crates/heartwood-core/src/types.rs
use zeroize::{Zeroize, ZeroizeOnDrop};
use thiserror::Error;

/// Maximum derivation index (u32::MAX).
pub const MAX_INDEX: u32 = 0xFFFF_FFFF;

/// Default number of indices to scan during recovery.
pub const DEFAULT_SCAN_RANGE: u32 = 20;

/// Maximum allowed scan range.
pub const MAX_SCAN_RANGE: u32 = 10_000;

/// HMAC domain prefix: "nsec-tree\0" as bytes.
pub const DOMAIN_PREFIX: &[u8] = b"nsec-tree\0";

/// Label for intermediate HMAC when creating root from nsec.
pub const NSEC_ROOT_LABEL: &[u8] = b"nsec-tree-root";

/// BIP-32 derivation path for mnemonic root.
pub const MNEMONIC_PATH: &str = "m/44'/1237'/727'/0'/0'";

#[derive(Debug, Error)]
pub enum HeartwoodError {
    #[error("index overflow: no valid key found in range")]
    IndexOverflow,
    #[error("invalid purpose: {0}")]
    InvalidPurpose(String),
    #[error("invalid mnemonic")]
    InvalidMnemonic,
    #[error("invalid nsec")]
    InvalidNsec,
    #[error("invalid npub")]
    InvalidNpub,
    #[error("invalid proof")]
    InvalidProof,
    #[error("scan range must be 1..={MAX_SCAN_RANGE}")]
    InvalidScanRange,
    #[error("key derivation failed: {0}")]
    Derivation(String),
}

/// Master tree root. Owns the secret; zeroises on drop.
pub struct TreeRoot {
    secret: zeroize::Zeroizing<[u8; 32]>,
    pub master_pubkey: String, // npub bech32
}

impl TreeRoot {
    pub(crate) fn new(secret: [u8; 32], master_pubkey: String) -> Self {
        Self {
            secret: zeroize::Zeroizing::new(secret),
            master_pubkey,
        }
    }

    pub(crate) fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    /// Explicitly destroy the root, zeroising the secret.
    pub fn destroy(mut self) {
        self.secret.zeroize();
    }
}

/// A derived child identity.
pub struct Identity {
    pub nsec: String,
    pub npub: String,
    pub private_key: zeroize::Zeroizing<[u8; 32]>,
    pub public_key: [u8; 32],
    pub purpose: String,
    pub index: u32,
}

impl Identity {
    /// Zero the private key bytes.
    pub fn zeroize(&mut self) {
        self.private_key.zeroize();
    }
}

/// A named persona wrapping an identity.
pub struct Persona {
    pub identity: Identity,
    pub name: String,
    pub index: u32,
}

/// A linkage proof (blind or full).
pub struct LinkageProof {
    pub master_pubkey: String, // lowercase hex, 64 chars
    pub child_pubkey: String,  // lowercase hex, 64 chars
    pub purpose: Option<String>,
    pub index: Option<u32>,
    pub attestation: String,
    pub signature: String, // lowercase hex, 128 chars
}
```

- [ ] **Step 4: Create lib.rs with module declarations**

```rust
// crates/heartwood-core/src/lib.rs
pub mod types;
pub mod encoding;
pub mod validate;
pub mod derive;
pub mod root;
pub mod proof;
pub mod persona;
pub mod recover;
```

- [ ] **Step 5: Verify it compiles**

Run: `cargo check -p heartwood-core`
Expected: compiles with no errors (some unused warnings are fine)

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml crates/
git commit -m "feat: scaffold heartwood-core Rust crate with types and constants"
```

---

## Task 2: NIP-19 bech32 encoding

**Files:**
- Create: `crates/heartwood-core/src/encoding.rs`
- Create: `tests/vectors.rs` (start of frozen vectors)

- [ ] **Step 1: Write failing tests for bech32 encoding**

Add to workspace Cargo.toml under heartwood-core dev-dependencies: nothing extra needed (hex is already a dep).

Create `crates/heartwood-core/tests/encoding_test.rs`:

```rust
use heartwood_core::encoding::{encode_nsec, decode_nsec, encode_npub, decode_npub};

#[test]
fn round_trip_nsec() {
    let key = [0x01u8; 32];
    let nsec = encode_nsec(&key);
    assert!(nsec.starts_with("nsec1"));
    let decoded = decode_nsec(&nsec).unwrap();
    assert_eq!(decoded, key);
}

#[test]
fn round_trip_npub() {
    let key = [0x02u8; 32];
    let npub = encode_npub(&key);
    assert!(npub.starts_with("npub1"));
    let decoded = decode_npub(&npub).unwrap();
    assert_eq!(decoded, key);
}

#[test]
fn decode_invalid_prefix_fails() {
    let key = [0x01u8; 32];
    let nsec = encode_nsec(&key);
    // Try decoding an nsec as npub -- should fail
    assert!(decode_npub(&nsec).is_err());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p heartwood-core --test encoding_test`
Expected: FAIL (module encoding not found or functions not defined)

- [ ] **Step 3: Implement encoding.rs**

```rust
// crates/heartwood-core/src/encoding.rs
use bech32::{Bech32, Hrp};
use crate::types::HeartwoodError;

const BECH32_LIMIT: usize = 1500;

fn encode_bech32(hrp_str: &str, bytes: &[u8; 32]) -> String {
    let hrp = Hrp::parse(hrp_str).expect("valid hrp");
    bech32::encode::<Bech32>(hrp, bytes).expect("valid encoding")
}

fn decode_bech32(expected_hrp: &str, encoded: &str) -> Result<[u8; 32], HeartwoodError> {
    let (hrp, data) = bech32::decode(encoded)
        .map_err(|_| HeartwoodError::InvalidNsec)?;
    if hrp.as_str() != expected_hrp {
        return Err(HeartwoodError::InvalidNsec);
    }
    let bytes: [u8; 32] = data
        .try_into()
        .map_err(|_| HeartwoodError::InvalidNsec)?;
    Ok(bytes)
}

pub fn encode_nsec(private_key: &[u8; 32]) -> String {
    encode_bech32("nsec", private_key)
}

pub fn decode_nsec(nsec: &str) -> Result<[u8; 32], HeartwoodError> {
    decode_bech32("nsec", nsec)
}

pub fn encode_npub(public_key: &[u8; 32]) -> String {
    encode_bech32("npub", public_key)
}

pub fn decode_npub(npub: &str) -> Result<[u8; 32], HeartwoodError> {
    decode_bech32("npub", npub)
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, HeartwoodError> {
    hex::decode(hex_str).map_err(|_| HeartwoodError::InvalidNsec)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p heartwood-core --test encoding_test`
Expected: 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add crates/heartwood-core/src/encoding.rs crates/heartwood-core/tests/
git commit -m "feat: NIP-19 bech32 encoding (nsec/npub) with round-trip tests"
```

---

## Task 3: Purpose string validation

**Files:**
- Create: `crates/heartwood-core/src/validate.rs`
- Create: `crates/heartwood-core/tests/validate_test.rs`

- [ ] **Step 1: Write failing tests**

```rust
// crates/heartwood-core/tests/validate_test.rs
use heartwood_core::validate::validate_purpose;

#[test]
fn valid_purposes() {
    assert!(validate_purpose("social").is_ok());
    assert!(validate_purpose("commerce").is_ok());
    assert!(validate_purpose("nostr:persona:personal").is_ok());
    assert!(validate_purpose("a").is_ok());
}

#[test]
fn empty_purpose_fails() {
    assert!(validate_purpose("").is_err());
}

#[test]
fn whitespace_only_fails() {
    assert!(validate_purpose("   ").is_err());
    assert!(validate_purpose("\t").is_err());
}

#[test]
fn null_byte_in_purpose_fails() {
    assert!(validate_purpose("social\0evil").is_err());
}

#[test]
fn too_long_purpose_fails() {
    let long = "a".repeat(256);
    assert!(validate_purpose(&long).is_err());
}

#[test]
fn max_length_purpose_passes() {
    let max = "a".repeat(255);
    assert!(validate_purpose(&max).is_ok());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p heartwood-core --test validate_test`
Expected: FAIL

- [ ] **Step 3: Implement validate.rs**

```rust
// crates/heartwood-core/src/validate.rs
use crate::types::HeartwoodError;

/// Maximum purpose string length in UTF-8 bytes.
const MAX_PURPOSE_BYTES: usize = 255;

/// Validate a purpose string for derivation.
///
/// Rules: non-empty, max 255 UTF-8 bytes, no null bytes, not whitespace-only.
pub fn validate_purpose(purpose: &str) -> Result<(), HeartwoodError> {
    if purpose.is_empty() {
        return Err(HeartwoodError::InvalidPurpose(
            "purpose must not be empty".into(),
        ));
    }
    if purpose.as_bytes().len() > MAX_PURPOSE_BYTES {
        return Err(HeartwoodError::InvalidPurpose(
            "purpose exceeds 255 bytes".into(),
        ));
    }
    if purpose.contains('\0') {
        return Err(HeartwoodError::InvalidPurpose(
            "purpose must not contain null bytes".into(),
        ));
    }
    if purpose.trim().is_empty() {
        return Err(HeartwoodError::InvalidPurpose(
            "purpose must not be whitespace-only".into(),
        ));
    }
    Ok(())
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p heartwood-core --test validate_test`
Expected: 6 tests PASS

- [ ] **Step 5: Commit**

```bash
git add crates/heartwood-core/src/validate.rs crates/heartwood-core/tests/validate_test.rs
git commit -m "feat: purpose string validation with boundary tests"
```

---

## Task 4: HMAC-SHA256 key derivation

**Files:**
- Create: `crates/heartwood-core/src/derive.rs`
- Create: `crates/heartwood-core/tests/derive_test.rs`

- [ ] **Step 1: Write failing tests using frozen vectors**

```rust
// crates/heartwood-core/tests/derive_test.rs
use heartwood_core::root::from_nsec_bytes;
use heartwood_core::derive::derive;

/// Vector 1: nsec root 0x01-fill, purpose=social, index=0
#[test]
fn vector1_nsec_root_social_0() {
    let input = [0x01u8; 32];
    let root = from_nsec_bytes(&input).unwrap();
    let child = derive(&root, "social", Some(0)).unwrap();
    assert_eq!(
        child.nsec,
        "nsec1nr5ck3mw4v7zhj6syrj2v7dyrd6wa0anpgregnzrv8ysv5qjvhnsafv7mx"
    );
    assert_eq!(
        child.npub,
        "npub1ehzv62sphgdc4lfjnxmxcwx3xpp6rxktdp7rxnc9yl8l4arykdeqyfhrxy"
    );
    assert_eq!(child.index, 0);
    assert_eq!(
        root.master_pubkey,
        "npub13sp7q3awvrqpa9p2svm7w8ghudghlnrraekwl7qh8w7j8747vjwskvzy2u"
    );
}

/// Vector 2: same root, purpose=commerce, index=0
#[test]
fn vector2_nsec_root_commerce_0() {
    let input = [0x01u8; 32];
    let root = from_nsec_bytes(&input).unwrap();
    let child = derive(&root, "commerce", Some(0)).unwrap();
    assert_eq!(
        child.nsec,
        "nsec1l3329mrljxtscjzln469xf5drf4qwfe7aq5u73xgw6zl0p6c7p8sd6vumk"
    );
}

/// Vector 3: same root, purpose=social, index=1
#[test]
fn vector3_nsec_root_social_1() {
    let input = [0x01u8; 32];
    let root = from_nsec_bytes(&input).unwrap();
    let child = derive(&root, "social", Some(1)).unwrap();
    assert_eq!(
        child.nsec,
        "nsec1sq4zl5cay4ghh54mndcedsmhumxz7vnj3wgkctp75uw2wqmk0yts3ny5vz"
    );
}

/// Different purposes must produce different keys.
#[test]
fn different_purposes_different_keys() {
    let input = [0x01u8; 32];
    let root = from_nsec_bytes(&input).unwrap();
    let social = derive(&root, "social", Some(0)).unwrap();
    let commerce = derive(&root, "commerce", Some(0)).unwrap();
    assert_ne!(social.nsec, commerce.nsec);
    assert_ne!(social.npub, commerce.npub);
}

/// Different indices must produce different keys.
#[test]
fn different_indices_different_keys() {
    let input = [0x01u8; 32];
    let root = from_nsec_bytes(&input).unwrap();
    let child0 = derive(&root, "social", Some(0)).unwrap();
    let child1 = derive(&root, "social", Some(1)).unwrap();
    assert_ne!(child0.nsec, child1.nsec);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p heartwood-core --test derive_test`
Expected: FAIL (derive and root modules not implemented)

- [ ] **Step 3: Implement root.rs (fromNsec path only for now)**

```rust
// crates/heartwood-core/src/root.rs
use hmac::{Hmac, Mac};
use sha2::Sha256;
use k256::schnorr::SigningKey;
use zeroize::Zeroize;

use crate::encoding::{encode_npub, decode_nsec};
use crate::types::{HeartwoodError, TreeRoot, NSEC_ROOT_LABEL};

type HmacSha256 = Hmac<Sha256>;

/// Create a TreeRoot from raw 32-byte nsec key material.
pub fn from_nsec_bytes(nsec_bytes: &[u8; 32]) -> Result<TreeRoot, HeartwoodError> {
    // Intermediate HMAC: tree_root = HMAC-SHA256(key=nsec_bytes, msg="nsec-tree-root")
    let mut mac = HmacSha256::new_from_slice(nsec_bytes)
        .map_err(|e| HeartwoodError::Derivation(e.to_string()))?;
    mac.update(NSEC_ROOT_LABEL);
    let result = mac.finalize().into_bytes();

    let mut secret = [0u8; 32];
    secret.copy_from_slice(&result);

    create_tree_root(secret)
}

/// Create a TreeRoot from a bech32-encoded nsec string.
pub fn from_nsec(nsec: &str) -> Result<TreeRoot, HeartwoodError> {
    let bytes = decode_nsec(nsec)?;
    from_nsec_bytes(&bytes)
}

/// Internal: create a TreeRoot from a 32-byte secret.
pub(crate) fn create_tree_root(mut secret: [u8; 32]) -> Result<TreeRoot, HeartwoodError> {
    let signing_key = SigningKey::from_bytes(&secret.into())
        .map_err(|e| HeartwoodError::Derivation(e.to_string()))?;
    let verifying_key = signing_key.verifying_key();
    let pubkey_bytes: [u8; 32] = verifying_key.to_bytes().into();
    let master_pubkey = encode_npub(&pubkey_bytes);

    Ok(TreeRoot::new(secret, master_pubkey))
}

/// Create a TreeRoot from a BIP-39 mnemonic.
pub fn from_mnemonic(mnemonic: &str, passphrase: Option<&str>) -> Result<TreeRoot, HeartwoodError> {
    use bip39::Mnemonic;
    use bip32::{Seed, XPrv};

    let mnemonic: Mnemonic = mnemonic.parse()
        .map_err(|_| HeartwoodError::InvalidMnemonic)?;
    let seed = mnemonic.to_seed(passphrase.unwrap_or(""));

    // Derive at m/44'/1237'/727'/0'/0'
    let xprv = XPrv::derive_from_path(
        &seed,
        &"m/44'/1237'/727'/0'/0'".parse().map_err(|_| HeartwoodError::Derivation("invalid path".into()))?,
    ).map_err(|e| HeartwoodError::Derivation(e.to_string()))?;

    let mut secret = [0u8; 32];
    secret.copy_from_slice(&xprv.to_bytes());

    create_tree_root(secret)
}
```

- [ ] **Step 4: Implement derive.rs**

```rust
// crates/heartwood-core/src/derive.rs
use hmac::{Hmac, Mac};
use sha2::Sha256;
use k256::schnorr::SigningKey;

use crate::encoding::{encode_nsec, encode_npub};
use crate::types::{HeartwoodError, TreeRoot, Identity, MAX_INDEX, DOMAIN_PREFIX};
use crate::validate::validate_purpose;

type HmacSha256 = Hmac<Sha256>;

/// Build the HMAC message: DOMAIN_PREFIX || purpose_bytes || 0x00 || index_u32_be
fn build_context(purpose: &str, index: u32) -> Vec<u8> {
    let purpose_bytes = purpose.as_bytes();
    let mut msg = Vec::with_capacity(DOMAIN_PREFIX.len() + purpose_bytes.len() + 1 + 4);
    msg.extend_from_slice(DOMAIN_PREFIX);
    msg.extend_from_slice(purpose_bytes);
    msg.push(0x00);
    msg.extend_from_slice(&index.to_be_bytes());
    msg
}

/// Derive a child identity from a tree root.
///
/// If `index` is None, defaults to 0.
/// If the derived key is not valid for secp256k1, increments index and retries.
pub fn derive(root: &TreeRoot, purpose: &str, index: Option<u32>) -> Result<Identity, HeartwoodError> {
    validate_purpose(purpose)?;

    let start_index = index.unwrap_or(0);
    let secret = root.secret();

    for current_index in start_index..=MAX_INDEX {
        let context = build_context(purpose, current_index);
        let mut mac = HmacSha256::new_from_slice(secret)
            .map_err(|e| HeartwoodError::Derivation(e.to_string()))?;
        mac.update(&context);
        let result = mac.finalize().into_bytes();

        let mut derived = [0u8; 32];
        derived.copy_from_slice(&result);

        // Try to create a valid signing key (checks curve order)
        match SigningKey::from_bytes(&derived.into()) {
            Ok(signing_key) => {
                let verifying_key = signing_key.verifying_key();
                let public_key: [u8; 32] = verifying_key.to_bytes().into();

                return Ok(Identity {
                    nsec: encode_nsec(&derived),
                    npub: encode_npub(&public_key),
                    private_key: zeroize::Zeroizing::new(derived),
                    public_key,
                    purpose: purpose.to_string(),
                    index: current_index,
                });
            }
            Err(_) => continue, // Invalid key, try next index
        }
    }

    Err(HeartwoodError::IndexOverflow)
}

/// Derive from an existing identity (arbitrary-depth hierarchies).
pub fn derive_from_identity(
    identity: &Identity,
    purpose: &str,
    index: Option<u32>,
) -> Result<Identity, HeartwoodError> {
    let intermediate_root = crate::root::create_tree_root(*identity.private_key)?;
    derive(&intermediate_root, purpose, index)
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p heartwood-core --test derive_test`
Expected: 5 tests PASS, all frozen vectors match

- [ ] **Step 6: Commit**

```bash
git add crates/heartwood-core/src/root.rs crates/heartwood-core/src/derive.rs crates/heartwood-core/tests/derive_test.rs
git commit -m "feat: HMAC-SHA256 key derivation with frozen test vectors"
```

---

## Task 5: Mnemonic root creation

**Files:**
- Modify: `crates/heartwood-core/src/root.rs` (already has from_mnemonic)
- Create: `crates/heartwood-core/tests/mnemonic_test.rs`

- [ ] **Step 1: Write failing tests using frozen vectors**

```rust
// crates/heartwood-core/tests/mnemonic_test.rs
use heartwood_core::root::{from_mnemonic, from_nsec_bytes};
use heartwood_core::derive::derive;

/// Vector 4: mnemonic root, purpose=social, index=0
#[test]
fn vector4_mnemonic_social_0() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let root = from_mnemonic(mnemonic, None).unwrap();
    assert_eq!(
        root.master_pubkey,
        "npub186c5ke7vjsk98z8qx4ctdrggsl2qlu627g6xvg6yumrj5c5c6etqcfaclx"
    );
    let child = derive(&root, "social", Some(0)).unwrap();
    assert_eq!(
        child.nsec,
        "nsec17rnusheefhuryyhpprnq5l3zvpzhg24xm9n7588amun6uedvdtyqnpcsm4"
    );
}

/// Vector 5: mnemonic root and nsec root must produce different master pubkeys
/// (different derivation paths: m/44'/1237'/727'/0'/0' vs HMAC separation)
#[test]
fn vector5_path_independence() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic_root = from_mnemonic(mnemonic, None).unwrap();

    // NIP-06 derived key at m/44'/1237'/0'/0/0 (different path)
    let nip06_key = hex::decode("5f29af3b9676180290e77a4efad265c4c2ff28a5302461f73597fda26bb25731").unwrap();
    let mut nip06_bytes = [0u8; 32];
    nip06_bytes.copy_from_slice(&nip06_key);
    let nsec_root = from_nsec_bytes(&nip06_bytes).unwrap();

    // These MUST be different
    assert_ne!(mnemonic_root.master_pubkey, nsec_root.master_pubkey);
    assert_eq!(
        nsec_root.master_pubkey,
        "npub1fezyufqcfk9nqwamc6n6fwtm3yr2hrj8tc5xf0t3qs75tqvkz2hq40tnpd"
    );
}

#[test]
fn invalid_mnemonic_fails() {
    assert!(from_mnemonic("not a valid mnemonic at all", None).is_err());
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test -p heartwood-core --test mnemonic_test`
Expected: 3 tests PASS (from_mnemonic was implemented in Task 4)

If any fail, debug the BIP-32 derivation path. The mnemonic "abandon...about" is the standard BIP-39 test vector.

- [ ] **Step 3: Commit**

```bash
git add crates/heartwood-core/tests/mnemonic_test.rs
git commit -m "test: mnemonic root creation with frozen vectors and path independence"
```

---

## Task 6: Linkage proofs (Schnorr BIP-340)

**Files:**
- Create: `crates/heartwood-core/src/proof.rs`
- Create: `crates/heartwood-core/tests/proof_test.rs`

- [ ] **Step 1: Write failing tests**

```rust
// crates/heartwood-core/tests/proof_test.rs
use heartwood_core::root::from_nsec_bytes;
use heartwood_core::derive::derive;
use heartwood_core::proof::{create_blind_proof, create_full_proof, verify_proof};

#[test]
fn blind_proof_round_trip() {
    let input = [0x01u8; 32];
    let root = from_nsec_bytes(&input).unwrap();
    let child = derive(&root, "social", Some(0)).unwrap();

    let proof = create_blind_proof(&root, &child).unwrap();

    // Blind proof has no purpose or index
    assert!(proof.purpose.is_none());
    assert!(proof.index.is_none());

    // Attestation format: "nsec-tree:own|{master_hex}|{child_hex}"
    assert!(proof.attestation.starts_with("nsec-tree:own|"));
    assert_eq!(proof.signature.len(), 128); // 64 bytes as hex

    // Verify
    assert!(verify_proof(&proof).unwrap());
}

#[test]
fn full_proof_round_trip() {
    let input = [0x01u8; 32];
    let root = from_nsec_bytes(&input).unwrap();
    let child = derive(&root, "social", Some(0)).unwrap();

    let proof = create_full_proof(&root, &child).unwrap();

    // Full proof has purpose and index
    assert_eq!(proof.purpose.as_deref(), Some("social"));
    assert_eq!(proof.index, Some(0));

    // Attestation format: "nsec-tree:link|{master_hex}|{child_hex}|social|0"
    assert!(proof.attestation.starts_with("nsec-tree:link|"));
    assert!(proof.attestation.ends_with("|social|0"));

    // Verify
    assert!(verify_proof(&proof).unwrap());
}

#[test]
fn tampered_attestation_fails_verification() {
    let input = [0x01u8; 32];
    let root = from_nsec_bytes(&input).unwrap();
    let child = derive(&root, "social", Some(0)).unwrap();

    let mut proof = create_blind_proof(&root, &child).unwrap();
    proof.attestation = "nsec-tree:own|0000|0000".to_string();

    assert!(!verify_proof(&proof).unwrap());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p heartwood-core --test proof_test`
Expected: FAIL

- [ ] **Step 3: Implement proof.rs**

```rust
// crates/heartwood-core/src/proof.rs
use k256::schnorr::{SigningKey, VerifyingKey, signature::Signer, signature::Verifier};
use crate::encoding::bytes_to_hex;
use crate::types::{HeartwoodError, TreeRoot, Identity, LinkageProof};

/// Create a blind linkage proof (no purpose/index revealed).
pub fn create_blind_proof(
    root: &TreeRoot,
    child: &Identity,
) -> Result<LinkageProof, HeartwoodError> {
    let master_hex = master_hex_from_root(root)?;
    let child_hex = bytes_to_hex(&child.public_key);

    let attestation = format!("nsec-tree:own|{}|{}", master_hex, child_hex);
    let signature = sign_attestation(root, &attestation)?;

    Ok(LinkageProof {
        master_pubkey: master_hex,
        child_pubkey: child_hex,
        purpose: None,
        index: None,
        attestation,
        signature,
    })
}

/// Create a full linkage proof (purpose and index revealed).
pub fn create_full_proof(
    root: &TreeRoot,
    child: &Identity,
) -> Result<LinkageProof, HeartwoodError> {
    let master_hex = master_hex_from_root(root)?;
    let child_hex = bytes_to_hex(&child.public_key);

    let attestation = format!(
        "nsec-tree:link|{}|{}|{}|{}",
        master_hex, child_hex, child.purpose, child.index
    );
    let signature = sign_attestation(root, &attestation)?;

    Ok(LinkageProof {
        master_pubkey: master_hex,
        child_pubkey: child_hex,
        purpose: Some(child.purpose.clone()),
        index: Some(child.index),
        attestation,
        signature,
    })
}

/// Verify a linkage proof signature against the master pubkey.
pub fn verify_proof(proof: &LinkageProof) -> Result<bool, HeartwoodError> {
    let pubkey_bytes = hex::decode(&proof.master_pubkey)
        .map_err(|_| HeartwoodError::InvalidProof)?;
    let sig_bytes = hex::decode(&proof.signature)
        .map_err(|_| HeartwoodError::InvalidProof)?;

    let pubkey_array: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| HeartwoodError::InvalidProof)?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| HeartwoodError::InvalidProof)?;

    let verifying_key = VerifyingKey::from_bytes(&pubkey_array.into())
        .map_err(|_| HeartwoodError::InvalidProof)?;
    let signature = k256::schnorr::Signature::try_from(sig_array.as_slice())
        .map_err(|_| HeartwoodError::InvalidProof)?;

    Ok(verifying_key.verify(proof.attestation.as_bytes(), &signature).is_ok())
}

fn master_hex_from_root(root: &TreeRoot) -> Result<String, HeartwoodError> {
    let signing_key = SigningKey::from_bytes(&(*root.secret()).into())
        .map_err(|e| HeartwoodError::Derivation(e.to_string()))?;
    let pubkey_bytes: [u8; 32] = signing_key.verifying_key().to_bytes().into();
    Ok(bytes_to_hex(&pubkey_bytes))
}

fn sign_attestation(root: &TreeRoot, attestation: &str) -> Result<String, HeartwoodError> {
    let signing_key = SigningKey::from_bytes(&(*root.secret()).into())
        .map_err(|e| HeartwoodError::Derivation(e.to_string()))?;
    let signature: k256::schnorr::Signature = signing_key.sign(attestation.as_bytes());
    Ok(bytes_to_hex(&signature.to_bytes()))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p heartwood-core --test proof_test`
Expected: 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add crates/heartwood-core/src/proof.rs crates/heartwood-core/tests/proof_test.rs
git commit -m "feat: BIP-340 Schnorr linkage proofs (blind + full) with verification"
```

---

## Task 7: Persona derivation

**Files:**
- Create: `crates/heartwood-core/src/persona.rs`
- Create: `crates/heartwood-core/tests/persona_test.rs`

- [ ] **Step 1: Write failing tests**

```rust
// crates/heartwood-core/tests/persona_test.rs
use heartwood_core::root::from_nsec_bytes;
use heartwood_core::persona::{derive_persona, derive_from_persona};

#[test]
fn persona_derives_with_prefixed_purpose() {
    let input = [0x01u8; 32];
    let root = from_nsec_bytes(&input).unwrap();
    let persona = derive_persona(&root, "personal", Some(0)).unwrap();
    assert_eq!(persona.name, "personal");
    assert_eq!(persona.identity.purpose, "nostr:persona:personal");
    assert_eq!(persona.index, persona.identity.index);
}

#[test]
fn different_persona_names_produce_different_keys() {
    let input = [0x01u8; 32];
    let root = from_nsec_bytes(&input).unwrap();
    let personal = derive_persona(&root, "personal", Some(0)).unwrap();
    let work = derive_persona(&root, "work", Some(0)).unwrap();
    assert_ne!(personal.identity.npub, work.identity.npub);
}

#[test]
fn derive_from_persona_creates_sub_identity() {
    let input = [0x01u8; 32];
    let root = from_nsec_bytes(&input).unwrap();
    let persona = derive_persona(&root, "personal", Some(0)).unwrap();
    let sub = derive_from_persona(&persona, "blog", Some(0)).unwrap();
    // Sub-identity must differ from persona identity
    assert_ne!(sub.npub, persona.identity.npub);
    assert_eq!(sub.purpose, "blog");
}

#[test]
fn persona_deterministic() {
    let input = [0x01u8; 32];
    let root1 = from_nsec_bytes(&input).unwrap();
    let root2 = from_nsec_bytes(&input).unwrap();
    let p1 = derive_persona(&root1, "social", Some(0)).unwrap();
    let p2 = derive_persona(&root2, "social", Some(0)).unwrap();
    assert_eq!(p1.identity.npub, p2.identity.npub);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p heartwood-core --test persona_test`
Expected: FAIL

- [ ] **Step 3: Implement persona.rs**

```rust
// crates/heartwood-core/src/persona.rs
use crate::derive::{derive, derive_from_identity};
use crate::types::{HeartwoodError, TreeRoot, Identity, Persona};

/// Derive a named persona from a tree root.
///
/// Purpose is constructed as "nostr:persona:{name}".
pub fn derive_persona(
    root: &TreeRoot,
    name: &str,
    index: Option<u32>,
) -> Result<Persona, HeartwoodError> {
    let purpose = format!("nostr:persona:{}", name);
    let identity = derive(root, &purpose, index)?;
    let actual_index = identity.index;
    Ok(Persona {
        identity,
        name: name.to_string(),
        index: actual_index,
    })
}

/// Derive a sub-identity from an existing persona.
pub fn derive_from_persona(
    persona: &Persona,
    purpose: &str,
    index: Option<u32>,
) -> Result<Identity, HeartwoodError> {
    derive_from_identity(&persona.identity, purpose, index)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p heartwood-core --test persona_test`
Expected: 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add crates/heartwood-core/src/persona.rs crates/heartwood-core/tests/persona_test.rs
git commit -m "feat: named persona derivation with two-level hierarchy"
```

---

## Task 8: Recovery scan

**Files:**
- Create: `crates/heartwood-core/src/recover.rs`
- Create: `crates/heartwood-core/tests/recover_test.rs`

- [ ] **Step 1: Write failing tests**

```rust
// crates/heartwood-core/tests/recover_test.rs
use heartwood_core::root::from_nsec_bytes;
use heartwood_core::derive::derive;
use heartwood_core::recover::recover;

#[test]
fn recover_finds_derived_identities() {
    let input = [0x01u8; 32];
    let root = from_nsec_bytes(&input).unwrap();

    // Derive some identities first (to know what to expect)
    let social0 = derive(&root, "social", Some(0)).unwrap();
    let commerce0 = derive(&root, "commerce", Some(0)).unwrap();

    // Recover should find them
    let purposes = vec!["social".to_string(), "commerce".to_string()];
    let found = recover(&root, &purposes, Some(5)).unwrap();

    assert!(found.contains_key("social"));
    assert!(found.contains_key("commerce"));
    assert_eq!(found["social"][0].npub, social0.npub);
    assert_eq!(found["commerce"][0].npub, commerce0.npub);
}

#[test]
fn recover_returns_empty_for_unknown_purpose() {
    let input = [0x01u8; 32];
    let root = from_nsec_bytes(&input).unwrap();

    let purposes = vec!["nonexistent".to_string()];
    let found = recover(&root, &purposes, Some(5)).unwrap();

    // Recovery always returns entries (deterministic derivation always produces keys)
    // It just scans and returns what it finds at each index
    assert!(found.contains_key("nonexistent"));
}

#[test]
fn invalid_scan_range_fails() {
    let input = [0x01u8; 32];
    let root = from_nsec_bytes(&input).unwrap();
    let purposes = vec!["social".to_string()];
    assert!(recover(&root, &purposes, Some(0)).is_err());
    assert!(recover(&root, &purposes, Some(10_001)).is_err());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p heartwood-core --test recover_test`
Expected: FAIL

- [ ] **Step 3: Implement recover.rs**

```rust
// crates/heartwood-core/src/recover.rs
use std::collections::HashMap;
use crate::derive::derive;
use crate::types::{HeartwoodError, TreeRoot, Identity, DEFAULT_SCAN_RANGE, MAX_SCAN_RANGE};

/// Scan and recover identities for the given purposes.
///
/// For each purpose, derives identities at indices 0..scan_range
/// and returns them in a map.
pub fn recover(
    root: &TreeRoot,
    purposes: &[String],
    scan_range: Option<u32>,
) -> Result<HashMap<String, Vec<Identity>>, HeartwoodError> {
    let range = scan_range.unwrap_or(DEFAULT_SCAN_RANGE);
    if range < 1 || range > MAX_SCAN_RANGE {
        return Err(HeartwoodError::InvalidScanRange);
    }

    let mut result: HashMap<String, Vec<Identity>> = HashMap::new();

    for purpose in purposes {
        let mut identities = Vec::new();
        for index in 0..range {
            match derive(root, purpose, Some(index)) {
                Ok(identity) => identities.push(identity),
                Err(HeartwoodError::IndexOverflow) => break,
                Err(e) => return Err(e),
            }
        }
        result.insert(purpose.clone(), identities);
    }

    Ok(result)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p heartwood-core --test recover_test`
Expected: 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add crates/heartwood-core/src/recover.rs crates/heartwood-core/tests/recover_test.rs
git commit -m "feat: scan-based identity recovery across purposes"
```

---

## Task 9: Public API and full test suite

**Files:**
- Modify: `crates/heartwood-core/src/lib.rs`
- Create: `crates/heartwood-core/tests/full_vectors_test.rs`

- [ ] **Step 1: Update lib.rs with public re-exports**

```rust
// crates/heartwood-core/src/lib.rs
pub mod types;
pub mod encoding;
pub mod validate;
pub mod derive;
pub mod root;
pub mod proof;
pub mod persona;
pub mod recover;

// Re-export primary API
pub use types::{TreeRoot, Identity, Persona, LinkageProof, HeartwoodError};
pub use root::{from_nsec, from_nsec_bytes, from_mnemonic};
pub use derive::{derive, derive_from_identity};
pub use proof::{create_blind_proof, create_full_proof, verify_proof};
pub use persona::{derive_persona, derive_from_persona};
pub use recover::recover;
pub use encoding::{encode_nsec, decode_nsec, encode_npub, decode_npub};
```

- [ ] **Step 2: Create full frozen vectors test**

```rust
// crates/heartwood-core/tests/full_vectors_test.rs
//! Frozen test vectors. These must NEVER be modified.
//! They validate byte-for-byte compatibility with the TypeScript nsec-tree.

use heartwood_core::*;

#[test]
fn vector1_nsec_root_01fill_social_0() {
    let root = from_nsec_bytes(&[0x01u8; 32]).unwrap();
    assert_eq!(root.master_pubkey, "npub13sp7q3awvrqpa9p2svm7w8ghudghlnrraekwl7qh8w7j8747vjwskvzy2u");
    let child = derive(&root, "social", Some(0)).unwrap();
    assert_eq!(child.nsec, "nsec1nr5ck3mw4v7zhj6syrj2v7dyrd6wa0anpgregnzrv8ysv5qjvhnsafv7mx");
    assert_eq!(child.npub, "npub1ehzv62sphgdc4lfjnxmxcwx3xpp6rxktdp7rxnc9yl8l4arykdeqyfhrxy");
    assert_eq!(child.index, 0);
}

#[test]
fn vector2_nsec_root_01fill_commerce_0() {
    let root = from_nsec_bytes(&[0x01u8; 32]).unwrap();
    let child = derive(&root, "commerce", Some(0)).unwrap();
    assert_eq!(child.nsec, "nsec1l3329mrljxtscjzln469xf5drf4qwfe7aq5u73xgw6zl0p6c7p8sd6vumk");
}

#[test]
fn vector3_nsec_root_01fill_social_1() {
    let root = from_nsec_bytes(&[0x01u8; 32]).unwrap();
    let child = derive(&root, "social", Some(1)).unwrap();
    assert_eq!(child.nsec, "nsec1sq4zl5cay4ghh54mndcedsmhumxz7vnj3wgkctp75uw2wqmk0yts3ny5vz");
}

#[test]
fn vector4_mnemonic_abandon_social_0() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let root = from_mnemonic(mnemonic, None).unwrap();
    assert_eq!(root.master_pubkey, "npub186c5ke7vjsk98z8qx4ctdrggsl2qlu627g6xvg6yumrj5c5c6etqcfaclx");
    let child = derive(&root, "social", Some(0)).unwrap();
    assert_eq!(child.nsec, "nsec17rnusheefhuryyhpprnq5l3zvpzhg24xm9n7588amun6uedvdtyqnpcsm4");
}

#[test]
fn vector5_path_independence() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic_root = from_mnemonic(mnemonic, None).unwrap();
    let nip06_key = hex::decode("5f29af3b9676180290e77a4efad265c4c2ff28a5302461f73597fda26bb25731").unwrap();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&nip06_key);
    let nsec_root = from_nsec_bytes(&bytes).unwrap();
    assert_ne!(mnemonic_root.master_pubkey, nsec_root.master_pubkey);
    assert_eq!(nsec_root.master_pubkey, "npub1fezyufqcfk9nqwamc6n6fwtm3yr2hrj8tc5xf0t3qs75tqvkz2hq40tnpd");
}
```

- [ ] **Step 3: Run full test suite**

Run: `cargo test -p heartwood-core`
Expected: ALL tests PASS

- [ ] **Step 4: Commit**

```bash
git add crates/heartwood-core/src/lib.rs crates/heartwood-core/tests/full_vectors_test.rs
git commit -m "feat: public API re-exports and frozen test vector suite"
```

---

## Task 10: NIP-46 server crate scaffold

**Files:**
- Create: `crates/heartwood-nip46/Cargo.toml`
- Create: `crates/heartwood-nip46/src/lib.rs`
- Create: `crates/heartwood-nip46/src/methods.rs`
- Create: `crates/heartwood-nip46/src/server.rs`
- Create: `crates/heartwood-nip46/src/permissions.rs`
- Create: `crates/heartwood-nip46/src/session.rs`
- Modify: `Cargo.toml` (add to workspace)

This task scaffolds the NIP-46 protocol layer. The full NIP-46 implementation involves Nostr relay communication (WebSocket), NIP-44 encryption, and event handling. This task creates the method dispatch and permission logic; relay connectivity is Task 11.

- [ ] **Step 1: Add to workspace**

Update root `Cargo.toml`:

```toml
[workspace]
resolver = "2"
members = [
    "crates/heartwood-core",
    "crates/heartwood-nip46",
]
```

- [ ] **Step 2: Create heartwood-nip46 Cargo.toml**

```toml
[package]
name = "heartwood-nip46"
version = "0.1.0"
edition.workspace = true
license.workspace = true
repository.workspace = true
description = "NIP-46 remote signing server with Heartwood extensions"

[dependencies]
heartwood-core = { path = "../heartwood-core" }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
tracing = "0.1"

[dev-dependencies]
```

- [ ] **Step 3: Create methods.rs with request/response types and dispatch**

```rust
// crates/heartwood-nip46/src/methods.rs
use serde::{Deserialize, Serialize};

/// NIP-46 request methods.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "method", content = "params")]
pub enum Nip46Request {
    // Standard NIP-46
    #[serde(rename = "get_public_key")]
    GetPublicKey,
    #[serde(rename = "sign_event")]
    SignEvent { event: serde_json::Value },
    #[serde(rename = "nip44_encrypt")]
    Nip44Encrypt { pubkey: String, plaintext: String },
    #[serde(rename = "nip44_decrypt")]
    Nip44Decrypt { pubkey: String, ciphertext: String },
    #[serde(rename = "nip04_encrypt")]
    Nip04Encrypt { pubkey: String, plaintext: String },
    #[serde(rename = "nip04_decrypt")]
    Nip04Decrypt { pubkey: String, ciphertext: String },

    // Heartwood extensions
    #[serde(rename = "heartwood_derive")]
    Derive { purpose: String, index: Option<u32> },
    #[serde(rename = "heartwood_derive_persona")]
    DerivePersona { name: String, index: Option<u32> },
    #[serde(rename = "heartwood_list_identities")]
    ListIdentities,
    #[serde(rename = "heartwood_switch")]
    Switch { npub: String },
    #[serde(rename = "heartwood_create_proof")]
    CreateProof { npub: String, full: bool },
    #[serde(rename = "heartwood_verify_proof")]
    VerifyProof { proof: serde_json::Value },
    #[serde(rename = "heartwood_recover")]
    Recover { purposes: Vec<String>, scan_range: Option<u32> },
}

/// NIP-46 response.
#[derive(Debug, Clone, Serialize)]
pub struct Nip46Response {
    pub id: String,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
}

impl Nip46Response {
    pub fn ok(id: String, result: serde_json::Value) -> Self {
        Self { id, result: Some(result), error: None }
    }

    pub fn err(id: String, error: String) -> Self {
        Self { id, result: None, error: Some(error) }
    }
}
```

- [ ] **Step 4: Create permissions.rs**

```rust
// crates/heartwood-nip46/src/permissions.rs
use std::collections::HashSet;
use std::time::Instant;

/// Per-client permission configuration.
pub struct ClientPermissions {
    /// Allowed event kinds this client can sign. None = all kinds allowed.
    pub allowed_kinds: Option<HashSet<u32>>,
    /// Maximum signing requests per minute.
    pub rate_limit: u32,
    /// Signing requests in the current window.
    requests_this_minute: u32,
    /// Start of the current rate limit window.
    window_start: Instant,
}

impl ClientPermissions {
    pub fn new(allowed_kinds: Option<HashSet<u32>>, rate_limit: u32) -> Self {
        Self {
            allowed_kinds,
            rate_limit,
            requests_this_minute: 0,
            window_start: Instant::now(),
        }
    }

    /// Check if this client is allowed to sign an event of the given kind.
    pub fn can_sign_kind(&self, kind: u32) -> bool {
        match &self.allowed_kinds {
            None => true,
            Some(kinds) => kinds.contains(&kind),
        }
    }

    /// Check and update rate limit. Returns true if request is allowed.
    pub fn check_rate_limit(&mut self) -> bool {
        if self.window_start.elapsed().as_secs() >= 60 {
            self.requests_this_minute = 0;
            self.window_start = Instant::now();
        }
        if self.requests_this_minute >= self.rate_limit {
            return false;
        }
        self.requests_this_minute += 1;
        true
    }
}

impl Default for ClientPermissions {
    fn default() -> Self {
        Self::new(None, 60) // All kinds, 60 requests/minute
    }
}
```

- [ ] **Step 5: Create session.rs**

```rust
// crates/heartwood-nip46/src/session.rs
use std::collections::HashMap;
use crate::permissions::ClientPermissions;

/// A paired client session.
pub struct ClientSession {
    pub client_pubkey: String,
    pub permissions: ClientPermissions,
    pub connected_at: std::time::Instant,
}

/// Manages all paired client sessions.
pub struct SessionManager {
    sessions: HashMap<String, ClientSession>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self { sessions: HashMap::new() }
    }

    pub fn add_session(&mut self, client_pubkey: String, permissions: ClientPermissions) {
        self.sessions.insert(client_pubkey.clone(), ClientSession {
            client_pubkey,
            permissions,
            connected_at: std::time::Instant::now(),
        });
    }

    pub fn get_session_mut(&mut self, client_pubkey: &str) -> Option<&mut ClientSession> {
        self.sessions.get_mut(client_pubkey)
    }

    pub fn remove_session(&mut self, client_pubkey: &str) {
        self.sessions.remove(client_pubkey);
    }

    pub fn list_sessions(&self) -> Vec<&str> {
        self.sessions.keys().map(|s| s.as_str()).collect()
    }
}
```

- [ ] **Step 6: Create lib.rs and server.rs stub**

```rust
// crates/heartwood-nip46/src/lib.rs
pub mod methods;
pub mod permissions;
pub mod server;
pub mod session;
```

```rust
// crates/heartwood-nip46/src/server.rs
use heartwood_core::{TreeRoot, Identity};
use crate::methods::{Nip46Request, Nip46Response};
use crate::session::SessionManager;
use std::collections::HashMap;
use std::sync::Mutex;

/// The Heartwood NIP-46 server state.
pub struct HeartwoodServer {
    root: TreeRoot,
    active_identity: Mutex<Identity>,
    derived_identities: Mutex<HashMap<String, Identity>>,
    sessions: Mutex<SessionManager>,
}

// Full request handling will be implemented when integrating with
// the Nostr relay WebSocket layer in the heartwood-device crate.
// This crate provides the protocol logic; the device crate provides I/O.
```

- [ ] **Step 7: Verify it compiles**

Run: `cargo check -p heartwood-nip46`
Expected: compiles

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml crates/heartwood-nip46/
git commit -m "feat: NIP-46 protocol crate with method dispatch, permissions, sessions"
```

---

## Task 11: Device crate -- OLED, storage, Tor, web server

**Files:**
- Create: `crates/heartwood-device/Cargo.toml`
- Create: `crates/heartwood-device/src/main.rs`
- Create: `crates/heartwood-device/src/oled.rs`
- Create: `crates/heartwood-device/src/storage.rs`
- Create: `crates/heartwood-device/src/tor.rs`
- Create: `crates/heartwood-device/src/web.rs`
- Create: `crates/heartwood-device/src/audit.rs`
- Modify: `Cargo.toml` (add to workspace)

This task creates the Pi-specific device binary with all I/O components. Each module is a thin wrapper that can be tested independently.

- [ ] **Step 1: Add to workspace and create Cargo.toml**

Update root `Cargo.toml`:

```toml
[workspace]
resolver = "2"
members = [
    "crates/heartwood-core",
    "crates/heartwood-nip46",
    "crates/heartwood-device",
]
```

```toml
# crates/heartwood-device/Cargo.toml
[package]
name = "heartwood-device"
version = "0.1.0"
edition.workspace = true
license.workspace = true
repository.workspace = true
description = "Heartwood device binary for Raspberry Pi"

[dependencies]
heartwood-core = { path = "../heartwood-core" }
heartwood-nip46 = { path = "../heartwood-nip46" }
axum = "0.8"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tracing = "0.1"
tracing-subscriber = "0.3"
qrcode = "0.14"
age = "0.10"
tower-http = { version = "0.6", features = ["fs", "cors"] }
```

- [ ] **Step 2: Create storage.rs -- encrypted secret storage**

```rust
// crates/heartwood-device/src/storage.rs
use std::path::{Path, PathBuf};
use std::fs;

const SECRETS_DIR: &str = "/var/lib/heartwood";
const MASTER_SECRET_FILE: &str = "master.age";
const CONFIG_FILE: &str = "config.json";

pub struct Storage {
    base_dir: PathBuf,
}

impl Storage {
    pub fn new(base_dir: Option<&str>) -> Self {
        Self {
            base_dir: PathBuf::from(base_dir.unwrap_or(SECRETS_DIR)),
        }
    }

    /// Check if a master secret exists.
    pub fn has_master_secret(&self) -> bool {
        self.base_dir.join(MASTER_SECRET_FILE).exists()
    }

    /// Save encrypted master secret (age-encrypted with PIN-derived key).
    pub fn save_master_secret(&self, encrypted: &[u8]) -> std::io::Result<()> {
        fs::create_dir_all(&self.base_dir)?;
        fs::write(self.base_dir.join(MASTER_SECRET_FILE), encrypted)
    }

    /// Load encrypted master secret.
    pub fn load_master_secret(&self) -> std::io::Result<Vec<u8>> {
        fs::read(self.base_dir.join(MASTER_SECRET_FILE))
    }

    /// Save device config (personas, client permissions, etc).
    pub fn save_config(&self, config: &str) -> std::io::Result<()> {
        fs::create_dir_all(&self.base_dir)?;
        fs::write(self.base_dir.join(CONFIG_FILE), config)
    }

    /// Load device config.
    pub fn load_config(&self) -> std::io::Result<String> {
        fs::read_to_string(self.base_dir.join(CONFIG_FILE))
    }
}
```

- [ ] **Step 3: Create tor.rs -- Tor daemon management**

```rust
// crates/heartwood-device/src/tor.rs
use std::path::PathBuf;
use std::fs;
use std::process::Command;

const ONION_DIR: &str = "/var/lib/tor/heartwood";
const HOSTNAME_FILE: &str = "hostname";

pub struct TorManager {
    onion_dir: PathBuf,
}

impl TorManager {
    pub fn new() -> Self {
        Self {
            onion_dir: PathBuf::from(ONION_DIR),
        }
    }

    /// Read the .onion address from Tor's hidden service directory.
    /// Returns None if Tor hasn't generated it yet.
    pub fn onion_address(&self) -> Option<String> {
        let path = self.onion_dir.join(HOSTNAME_FILE);
        fs::read_to_string(path).ok().map(|s| s.trim().to_string())
    }

    /// Wait for the .onion address to become available (Tor bootstrapping).
    /// Polls every second up to timeout_secs.
    pub async fn wait_for_onion(&self, timeout_secs: u64) -> Option<String> {
        for _ in 0..timeout_secs {
            if let Some(addr) = self.onion_address() {
                return Some(addr);
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        None
    }

    /// Check if the Tor service is running.
    pub fn is_running(&self) -> bool {
        Command::new("systemctl")
            .args(["is-active", "--quiet", "tor"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}
```

- [ ] **Step 4: Create oled.rs -- OLED display driver stub**

```rust
// crates/heartwood-device/src/oled.rs
use tracing::info;

/// OLED display driver.
/// On Pi, uses I2C via linux_embedded_hal + ssd1306 crate.
/// Falls back to terminal output on non-Pi (development).
pub struct Oled {
    is_hardware: bool,
}

impl Oled {
    pub fn new() -> Self {
        // Detect if we're on a Pi with I2C available
        let is_hardware = std::path::Path::new("/dev/i2c-1").exists();
        if is_hardware {
            info!("OLED: hardware I2C detected");
        } else {
            info!("OLED: no hardware, using terminal output");
        }
        Self { is_hardware }
    }

    /// Display a line of text.
    pub fn show_text(&self, text: &str) {
        if self.is_hardware {
            // TODO: implement I2C display via ssd1306 crate
            // For prototype, log to terminal
            info!("OLED: {}", text);
        } else {
            println!("[OLED] {}", text);
        }
    }

    /// Display a QR code (for .onion address + NIP-46 pairing).
    pub fn show_qr(&self, data: &str) {
        if self.is_hardware {
            info!("OLED QR: {}", data);
        } else {
            // Terminal QR via qrcode crate
            let qr = qrcode::QrCode::new(data.as_bytes()).unwrap();
            let string = qr.render::<char>()
                .quiet_zone(false)
                .module_dimensions(2, 1)
                .build();
            println!("{}", string);
        }
    }

    /// Display mnemonic words one at a time.
    pub fn show_mnemonic_word(&self, word_number: usize, word: &str) {
        let text = format!("Word {}/12: {}", word_number, word);
        self.show_text(&text);
    }

    /// Clear the display.
    pub fn clear(&self) {
        if self.is_hardware {
            info!("OLED: cleared");
        } else {
            println!("[OLED] ---");
        }
    }
}
```

- [ ] **Step 5: Create audit.rs -- signing audit log**

```rust
// crates/heartwood-device/src/audit.rs
use std::collections::VecDeque;
use serde::Serialize;

const MAX_LOG_ENTRIES: usize = 1000;

#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub timestamp: u64,
    pub client_pubkey: String,
    pub method: String,
    pub event_kind: Option<u32>,
    pub identity_npub: String,
}

/// Ring buffer audit log.
pub struct AuditLog {
    entries: VecDeque<AuditEntry>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            entries: VecDeque::with_capacity(MAX_LOG_ENTRIES),
        }
    }

    pub fn log(&mut self, entry: AuditEntry) {
        if self.entries.len() >= MAX_LOG_ENTRIES {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
    }

    pub fn entries(&self) -> &VecDeque<AuditEntry> {
        &self.entries
    }

    pub fn recent(&self, count: usize) -> Vec<&AuditEntry> {
        self.entries.iter().rev().take(count).collect()
    }
}
```

- [ ] **Step 6: Create web.rs -- Axum HTTP server**

```rust
// crates/heartwood-device/src/web.rs
use axum::{
    Router,
    routing::get,
    response::Html,
    extract::State,
    Json,
};
use std::sync::Arc;
use tokio::sync::Mutex;
use serde::Serialize;

use crate::audit::AuditLog;

pub struct AppState {
    pub audit_log: Mutex<AuditLog>,
    // TreeRoot and server state will be added as we integrate
}

#[derive(Serialize)]
struct StatusResponse {
    status: String,
    version: String,
}

async fn status() -> Json<StatusResponse> {
    Json(StatusResponse {
        status: "running".into(),
        version: env!("CARGO_PKG_VERSION").into(),
    })
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../../web/index.html"))
}

async fn audit_log(State(state): State<Arc<AppState>>) -> Json<Vec<crate::audit::AuditEntry>> {
    let log = state.audit_log.lock().await;
    let entries: Vec<_> = log.recent(100).into_iter().cloned().collect();
    Json(entries)
}

pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/status", get(status))
        .route("/api/audit", get(audit_log))
        .with_state(state)
}
```

- [ ] **Step 7: Create main.rs -- boot sequence**

```rust
// crates/heartwood-device/src/main.rs
mod oled;
mod storage;
mod tor;
mod web;
mod audit;

use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;
use tracing_subscriber;

#[tokio::main]
async fn main() {
    tracing_subscriber::init();
    info!("Heartwood starting...");

    // Initialise components
    let oled = oled::Oled::new();
    let storage = storage::Storage::new(None);
    let tor = tor::TorManager::new();
    let audit_log = audit::AuditLog::new();

    oled.show_text("HEARTWOOD");

    // Check if this is first boot (no master secret)
    if !storage.has_master_secret() {
        oled.show_text("SETUP MODE");
        info!("No master secret found. Entering setup mode.");
        // Setup will be handled via web UI
    } else {
        info!("Master secret found. Waiting for PIN...");
        oled.show_text("Enter PIN");
        // PIN entry via web UI
    }

    // Wait for Tor
    oled.show_text("Connecting to Tor...");
    if let Some(onion) = tor.wait_for_onion(120).await {
        info!("Tor hidden service: {}", onion);
        oled.show_qr(&onion);
    } else {
        info!("Tor not available, running on local network only");
        oled.show_text("heartwood.local");
    }

    // Start web server
    let state = Arc::new(web::AppState {
        audit_log: Mutex::new(audit_log),
    });
    let app = web::create_router(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    info!("Web UI listening on :8080");
    oled.show_text("READY");

    axum::serve(listener, app).await.unwrap();
}
```

- [ ] **Step 8: Create minimal web UI placeholder**

```html
<!-- web/index.html -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Heartwood</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: system-ui, sans-serif; background: #0a0a0a; color: #e0e0e0; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .container { max-width: 480px; padding: 2rem; text-align: center; }
        h1 { font-size: 2rem; margin-bottom: 1rem; }
        p { font-size: 1.1rem; line-height: 1.6; opacity: 0.8; }
        .status { margin-top: 2rem; padding: 1rem; background: #1a1a1a; border-radius: 8px; font-family: monospace; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Heartwood</h1>
        <p>Hardware signing appliance for Nostr</p>
        <div class="status" id="status">Loading...</div>
    </div>
    <script>
        fetch('/api/status')
            .then(r => r.json())
            .then(d => {
                document.getElementById('status').textContent =
                    `Status: ${d.status} | Version: ${d.version}`;
            })
            .catch(() => {
                document.getElementById('status').textContent = 'Connection failed';
            });
    </script>
</body>
</html>
```

- [ ] **Step 9: Verify it compiles**

Run: `cargo check -p heartwood-device`
Expected: compiles (some warnings about unused fields are fine)

- [ ] **Step 10: Commit**

```bash
git add Cargo.toml crates/heartwood-device/ web/
git commit -m "feat: device crate with OLED, storage, Tor, web server, audit log"
```

---

## Task 12: Pi deployment files

**Files:**
- Create: `pi/heartwood.service`
- Create: `pi/torrc`
- Create: `pi/setup.sh`

- [ ] **Step 1: Create systemd service file**

```ini
# pi/heartwood.service
[Unit]
Description=Heartwood signing appliance
After=network-online.target tor.service
Wants=network-online.target tor.service

[Service]
Type=simple
User=heartwood
Group=heartwood
ExecStart=/usr/local/bin/heartwood
Restart=always
RestartSec=5
Environment=RUST_LOG=info

# Security hardening
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/heartwood
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 2: Create Tor config template**

```
# pi/torrc
HiddenServiceDir /var/lib/tor/heartwood/
HiddenServicePort 80 127.0.0.1:8080
```

- [ ] **Step 3: Create Pi setup script**

```bash
#!/usr/bin/env bash
# pi/setup.sh -- Heartwood Pi setup script
# Run on a fresh Raspberry Pi OS Lite installation.
set -euo pipefail

echo "=== Heartwood Pi Setup ==="

# Install dependencies
sudo apt-get update
sudo apt-get install -y tor

# Create heartwood user
sudo useradd -r -s /usr/sbin/nologin heartwood || true
sudo mkdir -p /var/lib/heartwood
sudo chown heartwood:heartwood /var/lib/heartwood
sudo chmod 700 /var/lib/heartwood

# Configure Tor hidden service
sudo cp torrc /etc/tor/torrc.d/heartwood.conf
sudo systemctl restart tor

# Install heartwood binary (cross-compiled or built on Pi)
if [ -f "../target/release/heartwood-device" ]; then
    sudo cp ../target/release/heartwood-device /usr/local/bin/heartwood
    sudo chmod +x /usr/local/bin/heartwood
else
    echo "Binary not found. Build with: cargo build --release -p heartwood-device"
    echo "Or cross-compile with: cross build --release --target aarch64-unknown-linux-gnu -p heartwood-device"
fi

# Install and enable systemd service
sudo cp heartwood.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable heartwood
sudo systemctl start heartwood

echo "=== Heartwood installed ==="
echo "Check status: sudo systemctl status heartwood"
echo "View logs: sudo journalctl -u heartwood -f"
echo "Tor address will appear in: /var/lib/tor/heartwood/hostname"
```

- [ ] **Step 4: Commit**

```bash
git add pi/
git commit -m "feat: Pi deployment files (systemd, Tor config, setup script)"
```

---

## Task 13: README and project documentation

**Files:**
- Create: `README.md`

- [ ] **Step 1: Write README**

```markdown
# Heartwood

Hardware signing appliance for [nsec-tree](https://github.com/forgesworn/nsec-tree). Holds your Nostr master identity on a Raspberry Pi, derives unlimited unlinkable personas, signs events via NIP-46, reachable from anywhere via Tor. Private keys never leave the device.

## What it does

- **One mnemonic, all identities.** 12 words recover everything.
- **NIP-46 remote signing.** Works with every Nostr client that supports Nostr Connect.
- **Tor by default.** No clearnet exposure. No router configuration.
- **Per-client permissions.** Control which event kinds each paired app can sign.
- **Unlinkable personas.** Derive separate identities for work, personal, anon. Nobody can link them unless you choose to prove it.

## Hardware

| Item | Price |
|------|-------|
| Raspberry Pi Zero 2 W (or Pi 4 for dev) | ~GBP 15 |
| Micro SD card (8GB+) | ~GBP 4 |
| SSD1306 0.96" OLED (I2C) | ~GBP 5 |
| USB-C power supply | ~GBP 5 |
| **Total** | **~GBP 32** |

No soldering required.

## Quick start

1. Flash Raspberry Pi OS Lite to SD card
2. Boot Pi, SSH in
3. `git clone https://github.com/forgesworn/heartwood && cd heartwood/pi && bash setup.sh`
4. Wait for Tor (~60 seconds)
5. Scan QR code from OLED with your Nostr client

## Development

Develop on any machine (macOS, Linux). Tests run on the host.

```bash
cargo test                    # Run all tests
cargo test -p heartwood-core  # Core crypto tests only
cargo run -p heartwood-device # Run device binary (terminal mode)
```

## Architecture

```
heartwood-core     Pure crypto: nsec-tree derivation, signing, proofs
heartwood-nip46    NIP-46 protocol: method dispatch, permissions, sessions
heartwood-device   Pi binary: OLED, storage, Tor, web UI
```

## Licence

MIT
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add README with quick start and architecture overview"
```

---

## Task Summary

| Task | Component | What it delivers |
|------|-----------|-----------------|
| 1 | heartwood-core | Workspace, types, constants |
| 2 | heartwood-core | NIP-19 bech32 encoding |
| 3 | heartwood-core | Purpose validation |
| 4 | heartwood-core | HMAC-SHA256 derivation + frozen vectors |
| 5 | heartwood-core | Mnemonic root + path independence |
| 6 | heartwood-core | Schnorr linkage proofs |
| 7 | heartwood-core | Persona derivation |
| 8 | heartwood-core | Recovery scan |
| 9 | heartwood-core | Public API + full vector suite |
| 10 | heartwood-nip46 | NIP-46 protocol, permissions, sessions |
| 11 | heartwood-device | OLED, storage, Tor, web server, audit log |
| 12 | heartwood-device | Pi deployment (systemd, Tor, setup script) |
| 13 | docs | README |

After completing all 13 tasks: `cargo test` passes all frozen vectors, `cargo run -p heartwood-device` launches the web UI on port 8080 with terminal-mode OLED output, and the Pi deployment script installs everything with Tor.
