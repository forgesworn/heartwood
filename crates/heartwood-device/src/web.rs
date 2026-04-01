// crates/heartwood-device/src/web.rs
//! Axum HTTP server providing the Heartwood local web UI.

use std::sync::Arc;

use axum::{
    extract::{DefaultBodyLimit, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Mutex;
use tracing::info;

use argon2::Argon2;
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use rand_core::OsRng;

use crate::audit::AuditLog;
use crate::storage;
use crate::storage::Storage;

/// Shared application state for all HTTP handlers.
pub struct AppState {
    pub audit_log: Mutex<AuditLog>,
    pub storage: Mutex<Storage>,
    /// Decrypted master secret payload, held in memory while unlocked.
    /// `None` when locked or no secret exists.
    pub decrypted_payload: Mutex<Option<String>>,
}

/// Serve the bundled `index.html`.
async fn serve_index() -> impl IntoResponse {
    let html = include_str!("../../../web/index.html");
    (StatusCode::OK, [(header::CONTENT_TYPE, "text/html; charset=utf-8")], html)
}

/// Parse a decrypted payload string into (mode, npub).
fn parse_payload(payload: &str) -> (String, String) {
    if let Some(nsec) = payload.strip_prefix("bunker:") {
        let npub = heartwood_core::npub_from_nsec(nsec).unwrap_or_default();
        ("bunker".to_string(), npub)
    } else if let Some(rest) = payload.strip_prefix("tree-mnemonic:") {
        // Format: "tree-mnemonic:{passphrase}:{mnemonic}" or "tree-mnemonic::{mnemonic}"
        let (pass, mnemonic) = rest.split_once(':').unwrap_or(("", rest));
        let pass = if pass.is_empty() { None } else { Some(pass) };
        let npub = heartwood_core::from_mnemonic(mnemonic, pass)
            .map(|r| {
                let n = r.master_pubkey.clone();
                r.destroy();
                n
            })
            .unwrap_or_default();
        ("tree-mnemonic".to_string(), npub)
    } else if let Some(nsec) = payload.strip_prefix("tree-nsec:") {
        let npub = heartwood_core::from_nsec(nsec)
            .map(|r| {
                let n = r.master_pubkey.clone();
                r.destroy();
                n
            })
            .unwrap_or_default();
        ("tree-nsec".to_string(), npub)
    } else {
        ("unknown".to_string(), String::new())
    }
}

/// `GET /api/status` — return device status including setup and lock state.
///
/// When configured and unlocked, also returns the mode and npub.
async fn api_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let storage = state.storage.lock().await;
    let setup_required = !storage.has_master_secret();

    let relays = load_relays(&storage);

    let has_password = load_password(&storage).is_some();
    let tor_enabled =
        load_config(&storage).get("tor_enabled").and_then(|v| v.as_bool()).unwrap_or(false);

    if setup_required {
        return axum::Json(json!({
            "status": "running",
            "version": env!("CARGO_PKG_VERSION"),
            "setup_required": true,
            "has_password": has_password,
            "tor_enabled": tor_enabled,
            "relays": relays
        }));
    }

    // Check if the stored secret is encrypted or legacy plaintext
    let encryption_required = match storage.load_master_secret() {
        Ok(bytes) => !storage::is_encrypted(&bytes),
        Err(_) => false,
    };
    drop(storage);

    if encryption_required {
        return axum::Json(json!({
            "status": "running",
            "version": env!("CARGO_PKG_VERSION"),
            "setup_required": false,
            "encryption_required": true,
            "has_password": has_password,
            "tor_enabled": tor_enabled,
            "relays": relays
        }));
    }

    // Check lock state from cached decrypted payload
    let payload_guard = state.decrypted_payload.lock().await;
    let locked = payload_guard.is_none();

    if locked {
        return axum::Json(json!({
            "status": "running",
            "version": env!("CARGO_PKG_VERSION"),
            "setup_required": false,
            "locked": true,
            "has_password": has_password,
            "tor_enabled": tor_enabled,
            "relays": relays,
            "onion_address": read_onion_address()
        }));
    }

    let (mode, npub) = parse_payload(payload_guard.as_deref().unwrap_or(""));

    // Read bunker URI if available
    let bunker_uri = std::fs::read_to_string("/var/lib/heartwood/bunker-uri.txt")
        .ok()
        .map(|s| s.trim().to_string());

    axum::Json(json!({
        "status": "running",
        "version": env!("CARGO_PKG_VERSION"),
        "setup_required": false,
        "locked": false,
        "has_password": has_password,
        "tor_enabled": tor_enabled,
        "mode": mode,
        "npub": npub,
        "relays": relays,
        "bunker_uri": bunker_uri,
        "onion_address": read_onion_address()
    }))
}

#[derive(Deserialize)]
struct SetupRequest {
    /// "bunker", "tree-mnemonic", or "tree-nsec"
    mode: String,
    mnemonic: Option<String>,
    passphrase: Option<String>,
    nsec: Option<String>,
    /// 4–8 digit PIN used to encrypt the master secret at rest.
    pin: String,
}

/// `POST /api/setup` — initialise the device. Only works in setup mode.
///
/// Three modes:
/// - `bunker`: store nsec as-is for NIP-46 remote signing. Your existing npub is preserved.
/// - `tree-mnemonic`: derive an nsec-tree root from a BIP-39 mnemonic. New master identity.
/// - `tree-nsec`: derive an nsec-tree root from an existing nsec via HMAC. New master identity.
async fn api_setup(
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<SetupRequest>,
) -> impl IntoResponse {
    let storage = state.storage.lock().await;

    if storage.has_master_secret() {
        return (
            StatusCode::CONFLICT,
            axum::Json(json!({"error": "device already configured — reset first"})),
        );
    }

    // Validate PIN: 4–8 digits
    if req.pin.len() < 4 || req.pin.len() > 8 || !req.pin.chars().all(|c| c.is_ascii_digit()) {
        return (StatusCode::BAD_REQUEST, axum::Json(json!({"error": "PIN must be 4–8 digits"})));
    }

    let (npub, payload) = match req.mode.as_str() {
        "bunker" => {
            let nsec = match &req.nsec {
                Some(n) => n,
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        axum::Json(json!({"error": "bunker mode requires 'nsec'"})),
                    )
                }
            };
            match heartwood_core::npub_from_nsec(nsec) {
                Ok(npub) => (npub, format!("bunker:{nsec}")),
                Err(e) => {
                    return (StatusCode::BAD_REQUEST, axum::Json(json!({"error": format!("{e}")})))
                }
            }
        }
        "tree-mnemonic" => {
            let mnemonic = match &req.mnemonic {
                Some(m) => m,
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        axum::Json(json!({"error": "tree-mnemonic mode requires 'mnemonic'"})),
                    )
                }
            };
            match heartwood_core::from_mnemonic(mnemonic, req.passphrase.as_deref()) {
                Ok(root) => {
                    let npub = root.master_pubkey.clone();
                    root.destroy();
                    let payload = if let Some(pass) = &req.passphrase {
                        format!("tree-mnemonic:{pass}:{mnemonic}")
                    } else {
                        format!("tree-mnemonic::{mnemonic}")
                    };
                    (npub, payload)
                }
                Err(e) => {
                    return (StatusCode::BAD_REQUEST, axum::Json(json!({"error": format!("{e}")})))
                }
            }
        }
        "tree-nsec" => {
            let nsec = match &req.nsec {
                Some(n) => n,
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        axum::Json(json!({"error": "tree-nsec mode requires 'nsec'"})),
                    )
                }
            };
            match heartwood_core::from_nsec(nsec) {
                Ok(root) => {
                    let npub = root.master_pubkey.clone();
                    root.destroy();
                    (npub, format!("tree-nsec:{nsec}"))
                }
                Err(e) => {
                    return (StatusCode::BAD_REQUEST, axum::Json(json!({"error": format!("{e}")})))
                }
            }
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(
                    json!({"error": "mode must be 'bunker', 'tree-mnemonic', or 'tree-nsec'"}),
                ),
            )
        }
    };

    // Encrypt the payload with the PIN before writing to disk
    let encrypted = storage::encrypt_with_pin(&req.pin, payload.as_bytes());
    if let Err(e) = storage.save_master_secret(&encrypted) {
        tracing::error!("Failed to save master secret: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": "failed to save configuration"})),
        );
    }

    // Cache the decrypted payload so the device starts unlocked after setup
    drop(storage);
    write_runtime_payload(&payload);
    *state.decrypted_payload.lock().await = Some(payload);

    info!("Setup complete (mode={}). Pubkey: {npub}", req.mode);
    (StatusCode::OK, axum::Json(json!({"npub": npub, "mode": req.mode})))
}

#[derive(Deserialize)]
struct ResetRequest {
    password: String,
}

/// `POST /api/reset` — wipe stored secret and return to setup mode.
///
/// Requires the current device password in the POST body as a secondary
/// confirmation, since this operation destroys the master secret.
async fn api_reset(
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<ResetRequest>,
) -> impl IntoResponse {
    let storage = state.storage.lock().await;

    if !storage.has_master_secret() {
        return (StatusCode::OK, axum::Json(json!({"status": "already in setup mode"})));
    }

    // Verify password before allowing reset
    let stored = load_password(&storage);
    match stored {
        Some(stored) => {
            let valid = if is_hashed(&stored) {
                verify_password(&req.password, &stored)
            } else {
                req.password == stored
            };
            if !valid {
                return (StatusCode::FORBIDDEN, axum::Json(json!({"error": "incorrect password"})));
            }
        }
        None => {
            // No password set — should not happen in practice since auth_middleware
            // would allow unauthenticated access, but handle gracefully.
        }
    }

    match storage.delete_master_secret() {
        Ok(()) => {
            drop(storage);
            // Clear the cached decrypted payload and runtime file
            *state.decrypted_payload.lock().await = None;
            remove_runtime_payload();
            info!("Device reset. Returning to setup mode.");
            (StatusCode::OK, axum::Json(json!({"status": "reset complete"})))
        }
        Err(e) => {
            tracing::error!("Failed to reset device: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": "failed to reset device"})),
            )
        }
    }
}

// --- PIN / lock management ---

/// Runtime path for the decrypted payload (tmpfs on Linux, never hits disk).
/// The bunker sidecar reads from here after PIN unlock.
const RUNTIME_PAYLOAD_PATH: &str = "/run/heartwood/master.payload";

/// Write the decrypted payload to the runtime path so the bunker sidecar can read it.
fn write_runtime_payload(payload: &str) {
    let dir = std::path::Path::new(RUNTIME_PAYLOAD_PATH).parent().unwrap();
    if std::fs::create_dir_all(dir).is_err() {
        tracing::warn!("Could not create runtime directory {}", dir.display());
        return;
    }
    if let Err(e) =
        storage::write_secret_file(std::path::Path::new(RUNTIME_PAYLOAD_PATH), payload.as_bytes())
    {
        tracing::warn!("Could not write runtime payload: {e}");
    }
}

/// Remove the runtime payload file (on lock or reset).
fn remove_runtime_payload() {
    let _ = std::fs::remove_file(RUNTIME_PAYLOAD_PATH);
}

/// Validate a PIN: must be 4–8 ASCII digits.
fn validate_pin(pin: &str) -> bool {
    pin.len() >= 4 && pin.len() <= 8 && pin.chars().all(|c| c.is_ascii_digit())
}

#[derive(Deserialize)]
struct UnlockRequest {
    pin: String,
}

/// `POST /api/unlock` — decrypt the master secret and enter unlocked state.
///
/// The PIN is used to derive the AES-256-GCM key via Argon2id. If the PIN is
/// wrong, authenticated decryption fails and the endpoint returns 403.
async fn api_unlock(
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<UnlockRequest>,
) -> impl IntoResponse {
    let storage = state.storage.lock().await;

    if !storage.has_master_secret() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "no secret stored — run setup first"})),
        );
    }

    let bytes = match storage.load_master_secret() {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("Failed to read master secret: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": "failed to read secret"})),
            );
        }
    };
    drop(storage);

    if !storage::is_encrypted(&bytes) {
        return (
            StatusCode::CONFLICT,
            axum::Json(json!({"error": "secret is not encrypted — use /api/set-pin first"})),
        );
    }

    match storage::decrypt_with_pin(&req.pin, &bytes) {
        Ok(plaintext) => {
            let payload = String::from_utf8_lossy(&plaintext).to_string();
            write_runtime_payload(&payload);
            *state.decrypted_payload.lock().await = Some(payload);
            info!("Device unlocked");
            (StatusCode::OK, axum::Json(json!({"status": "unlocked"})))
        }
        Err(_) => (StatusCode::FORBIDDEN, axum::Json(json!({"error": "incorrect PIN"}))),
    }
}

/// `POST /api/lock` — clear the cached decrypted secret from memory.
async fn api_lock(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    *state.decrypted_payload.lock().await = None;
    remove_runtime_payload();
    info!("Device locked");
    axum::Json(json!({"status": "locked"}))
}

#[derive(Deserialize)]
struct SetPinRequest {
    pin: String,
    confirm: String,
}

/// `POST /api/set-pin` — encrypt a legacy plaintext secret with a new PIN.
///
/// Only works when the stored secret is unencrypted (legacy migration).
/// After encryption, the device is left in unlocked state.
async fn api_set_pin(
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<SetPinRequest>,
) -> impl IntoResponse {
    if req.pin != req.confirm {
        return (StatusCode::BAD_REQUEST, axum::Json(json!({"error": "PINs do not match"})));
    }
    if !validate_pin(&req.pin) {
        return (StatusCode::BAD_REQUEST, axum::Json(json!({"error": "PIN must be 4–8 digits"})));
    }

    let storage = state.storage.lock().await;

    let bytes = match storage.load_master_secret() {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("Failed to read master secret: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": "failed to read secret"})),
            );
        }
    };

    if storage::is_encrypted(&bytes) {
        return (StatusCode::CONFLICT, axum::Json(json!({"error": "secret is already encrypted"})));
    }

    // Encrypt the plaintext payload with the new PIN
    let encrypted = storage::encrypt_with_pin(&req.pin, &bytes);
    if let Err(e) = storage.save_master_secret(&encrypted) {
        tracing::error!("Failed to save encrypted secret: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": "failed to save encrypted secret"})),
        );
    }

    // Cache the decrypted payload — device is now unlocked
    let payload = String::from_utf8_lossy(&bytes).to_string();
    drop(storage);
    write_runtime_payload(&payload);
    *state.decrypted_payload.lock().await = Some(payload);

    info!("Legacy secret encrypted with PIN. Device unlocked.");
    (StatusCode::OK, axum::Json(json!({"status": "encrypted and unlocked"})))
}

/// Middleware that blocks most API endpoints when the device is locked.
///
/// Allows: `/`, `/api/status`, `/api/unlock`, `/api/set-pin`, `/api/setup`.
/// Everything else returns 423 Locked.
async fn lock_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> impl IntoResponse {
    let path = req.uri().path().to_string();

    // These endpoints work regardless of lock state
    let unlocked_paths = ["/", "/api/status", "/api/unlock", "/api/set-pin", "/api/setup"];
    if unlocked_paths.contains(&path.as_str()) {
        return next.run(req).await;
    }

    // Check if device is locked (has a secret but no cached decrypted payload)
    let storage = state.storage.lock().await;
    let has_secret = storage.has_master_secret();
    drop(storage);

    if has_secret {
        let payload = state.decrypted_payload.lock().await;
        if payload.is_none() {
            return (
                StatusCode::LOCKED,
                axum::Json(
                    json!({"error": "device is locked — POST to /api/unlock with your PIN"}),
                ),
            )
                .into_response();
        }
    }

    next.run(req).await
}

// --- Config helpers ---

/// Load the full config JSON, or return an empty object.
fn load_config(storage: &Storage) -> serde_json::Value {
    storage
        .load_config()
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| json!({}))
}

/// Merge a key into config and save.
fn save_config_key(storage: &Storage, key: &str, value: serde_json::Value) -> std::io::Result<()> {
    let mut config = load_config(storage);
    config[key] = value;
    storage.save_config(&config.to_string())
}

/// Load the stored password, if any.
fn load_password(storage: &Storage) -> Option<String> {
    let config = load_config(storage);
    config.get("password").and_then(|v| v.as_str()).map(|s| s.to_string())
}

// --- Auth middleware ---

/// Hash a password with Argon2id and a random salt.
fn hash_password(password: &str) -> Result<String, password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    Ok(argon2.hash_password(password.as_bytes(), &salt)?.to_string())
}

/// Verify a password against a stored hash. Returns `true` if valid.
fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
}

/// Returns `true` if the stored value is an argon2 PHC string (starts with `$argon2`).
fn is_hashed(stored: &str) -> bool {
    stored.starts_with("$argon2")
}

/// HTTP Basic Auth middleware. Skips auth if no password is set (first-time setup).
///
/// Transparently migrates plaintext passwords to argon2 hashes on first successful auth.
async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> impl IntoResponse {
    let storage = state.storage.lock().await;
    let password = load_password(&storage);

    // No password set — allow everything (first-time setup)
    let Some(stored) = password else {
        drop(storage);
        return next.run(req).await;
    };

    // Extract Basic auth credentials
    let provided = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|b64| {
            use base64::Engine;
            let decoded = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
            String::from_utf8(decoded).ok()
        })
        .map(|creds| {
            // Basic auth format is "user:password" — we only check the password part
            creds.split_once(':').map(|(_, p)| p.to_string()).unwrap_or(creds)
        });

    let Some(provided) = provided else {
        drop(storage);
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Basic realm=\"Heartwood\"")],
            "Unauthorised",
        )
            .into_response();
    };

    let authorised = if is_hashed(&stored) {
        verify_password(&provided, &stored)
    } else {
        // Legacy plaintext comparison — migrate to argon2 on success
        if provided == stored {
            if let Ok(hashed) = hash_password(&provided) {
                let _ = save_config_key(&storage, "password", json!(hashed));
                info!("Migrated plaintext password to argon2 hash");
            }
            true
        } else {
            false
        }
    };

    drop(storage); // release lock before calling next

    if authorised {
        next.run(req).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Basic realm=\"Heartwood\"")],
            "Unauthorised",
        )
            .into_response()
    }
}

/// Default relays for new installations.
const DEFAULT_RELAYS: &[&str] =
    &["wss://relay.damus.io", "wss://relay.nostr.band", "wss://nos.lol", "wss://relay.trotters.cc"];

/// Load relay list from config, or return defaults.
fn load_relays(storage: &Storage) -> Vec<String> {
    let config = load_config(storage);
    config
        .get("relays")
        .cloned()
        .and_then(|v| serde_json::from_value::<Vec<String>>(v).ok())
        .unwrap_or_else(|| DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect())
}

/// `GET /api/relays` — return the configured relay list.
async fn api_get_relays(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let storage = state.storage.lock().await;
    let relays = load_relays(&storage);
    axum::Json(json!({ "relays": relays }))
}

#[derive(Deserialize)]
struct RelayUpdate {
    relays: Vec<String>,
}

/// `POST /api/relays` — update the relay list.
///
/// Also recomputes the bunker URI file so the web UI reflects the new relays
/// immediately, without waiting for the bunker sidecar's file watcher.
async fn api_set_relays(
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<RelayUpdate>,
) -> impl IntoResponse {
    const MAX_RELAYS: usize = 20;
    const MAX_RELAY_URL_LEN: usize = 256;

    let relays: Vec<String> = req
        .relays
        .into_iter()
        .take(MAX_RELAYS)
        .map(|r| r.trim().to_string())
        .filter(|r| {
            (r.starts_with("wss://") || r.starts_with("ws://"))
                && r.len() <= MAX_RELAY_URL_LEN
                && r.is_ascii()
        })
        .collect();

    if relays.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "at least one valid relay URL required (wss:// or ws://)"})),
        );
    }

    let storage = state.storage.lock().await;
    match save_config_key(&storage, "relays", json!(relays)) {
        Ok(()) => {
            info!("Relay list updated: {} relays", relays.len());
            // Recompute the bunker URI so the web UI picks up the change immediately
            rewrite_bunker_uri(&relays);
            (StatusCode::OK, axum::Json(json!({ "relays": relays })))
        }
        Err(e) => {
            tracing::error!("Failed to save relay config: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": "failed to save configuration"})),
            )
        }
    }
}

/// Rewrite the bunker URI file with updated relays.
///
/// Reads the existing `bunker-uri.txt` to extract the bunker pubkey, then
/// rebuilds the URI with the new relay list. The bunker sidecar will also
/// recompute this when its config file watcher fires, but writing it here
/// ensures the web UI sees the update immediately.
fn rewrite_bunker_uri(relays: &[String]) {
    const BUNKER_URI_PATH: &str = "/var/lib/heartwood/bunker-uri.txt";

    // Parse the existing URI to extract the bunker public key
    let existing = match std::fs::read_to_string(BUNKER_URI_PATH) {
        Ok(s) => s.trim().to_string(),
        Err(_) => return, // bunker not running yet — nothing to rewrite
    };

    let bunker_pk = match parse_bunker_pubkey(&existing) {
        Some(pk) => pk,
        None => return,
    };

    let uri = build_bunker_uri(bunker_pk, relays);

    if let Err(e) =
        storage::write_secret_file(std::path::Path::new(BUNKER_URI_PATH), uri.as_bytes())
    {
        tracing::warn!("Could not rewrite bunker URI: {e}");
    }
}

/// Extract the bunker pubkey from a bunker URI string.
///
/// Returns `None` if the URI is malformed or the pubkey is not a valid 64-char hex string.
fn parse_bunker_pubkey(uri: &str) -> Option<&str> {
    let rest = uri.strip_prefix("bunker://")?;
    let pk = rest.split('?').next().unwrap_or("");
    if pk.len() == 64 && pk.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(pk)
    } else {
        None
    }
}

/// Build a bunker URI from a hex pubkey and relay list.
fn build_bunker_uri(pubkey: &str, relays: &[String]) -> String {
    let relay_params: String = relays
        .iter()
        .map(|r| {
            // Percent-encode the relay URL for use as a query parameter
            let encoded: String = r
                .bytes()
                .map(|b| match b {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                        String::from(b as char)
                    }
                    _ => format!("%{b:02X}"),
                })
                .collect();
            format!("relay={encoded}")
        })
        .collect::<Vec<_>>()
        .join("&");
    format!("bunker://{pubkey}?{relay_params}")
}

/// `GET /api/bunker` — return the bunker URI if the bunker sidecar has written one.
async fn api_bunker() -> impl IntoResponse {
    match std::fs::read_to_string("/var/lib/heartwood/bunker-uri.txt") {
        Ok(uri) => axum::Json(json!({"uri": uri.trim()})),
        Err(_) => axum::Json(json!({"uri": null, "message": "bunker not running"})),
    }
}

/// `GET /api/bunker/status` — return relay connection status from the bunker sidecar.
///
/// The bunker sidecar writes `bunker-status.json` every 15 seconds with per-relay
/// connection state. Returns an empty relays object if the file is missing.
async fn api_bunker_status() -> impl IntoResponse {
    match std::fs::read_to_string("/var/lib/heartwood/bunker-status.json") {
        Ok(s) => match serde_json::from_str::<serde_json::Value>(&s) {
            Ok(val) => axum::Json(val),
            Err(_) => axum::Json(json!({"relays": {}})),
        },
        Err(_) => axum::Json(json!({"relays": {}})),
    }
}

#[derive(Deserialize)]
struct PasswordRequest {
    password: String,
}

/// `POST /api/password` — set or change the device password.
///
/// The password is hashed with Argon2id before storage — the plaintext is never persisted.
async fn api_set_password(
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<PasswordRequest>,
) -> impl IntoResponse {
    if req.password.is_empty() {
        return (StatusCode::BAD_REQUEST, axum::Json(json!({"error": "password cannot be empty"})));
    }

    let hashed = match hash_password(&req.password) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("Failed to hash password: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": "failed to hash password"})),
            );
        }
    };

    let storage = state.storage.lock().await;
    match save_config_key(&storage, "password", json!(hashed)) {
        Ok(()) => {
            info!("Device password set");
            (StatusCode::OK, axum::Json(json!({"status": "password set"})))
        }
        Err(e) => {
            tracing::error!("Failed to save password: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": "failed to save configuration"})),
            )
        }
    }
}

#[derive(Deserialize)]
struct TorToggle {
    enabled: bool,
}

/// `POST /api/tor` — enable or disable Tor hidden service.
async fn api_set_tor(
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<TorToggle>,
) -> impl IntoResponse {
    let storage = state.storage.lock().await;
    match save_config_key(&storage, "tor_enabled", json!(req.enabled)) {
        Ok(()) => {
            info!("Tor {}", if req.enabled { "enabled" } else { "disabled" });
            (StatusCode::OK, axum::Json(json!({"tor_enabled": req.enabled})))
        }
        Err(e) => {
            tracing::error!("Failed to save tor config: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": "failed to save configuration"})),
            )
        }
    }
}

/// Read the Tor .onion address from the hidden service directory.
fn read_onion_address() -> Option<String> {
    std::fs::read_to_string("/var/lib/tor/heartwood/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// `GET /api/tor` — return Tor status and .onion address.
async fn api_get_tor(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let storage = state.storage.lock().await;
    let tor_enabled =
        load_config(&storage).get("tor_enabled").and_then(|v| v.as_bool()).unwrap_or(false);
    let onion_address = read_onion_address();
    axum::Json(json!({
        "tor_enabled": tor_enabled,
        "onion_address": onion_address,
    }))
}

/// `POST /api/restart` — restart the heartwood-device service via systemd.
///
/// Only works on systems with systemctl. Returns immediately; the process
/// will be replaced by systemd after it exits.
async fn api_restart() -> impl IntoResponse {
    info!("Restart requested via web UI");
    // Spawn the restart in a background task so we can return the response first
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        std::process::exit(0); // systemd RestartSec will restart us
    });
    axum::Json(json!({"status": "restarting"}))
}

/// `GET /api/audit` — return all recent audit log entries as JSON.
async fn api_audit(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let log = state.audit_log.lock().await;
    let entries: Vec<_> = log.entries().iter().collect();
    match serde_json::to_value(&entries) {
        Ok(val) => (StatusCode::OK, axum::Json(val)),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": "serialisation failed"})),
        ),
    }
}

// --- Client management (bunker allowlist) ---

/// `GET /api/clients` — return approved and pending clients.
async fn api_get_clients() -> impl IntoResponse {
    let approved = load_clients_file("/var/lib/heartwood/clients.json");
    let pending = load_clients_file("/var/lib/heartwood/pending-clients.json");
    axum::Json(json!({ "approved": approved, "pending": pending }))
}

#[derive(Deserialize)]
struct ApproveClient {
    pubkey: String,
    #[serde(default)]
    allowed_kinds: Option<Vec<u64>>,
    #[serde(default)]
    label: Option<String>,
}

/// `POST /api/clients/approve` — approve a pending client pubkey.
async fn api_approve_client(axum::Json(req): axum::Json<ApproveClient>) -> impl IntoResponse {
    // Validate hex pubkey format
    if req.pubkey.len() != 64 || !req.pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "invalid pubkey — expected 64 hex characters"})),
        );
    }

    let mut approved = load_clients_file("/var/lib/heartwood/clients.json");
    let approved_obj = approved.as_object_mut().unwrap();
    let mut entry = json!({ "approvedAt": chrono_now_iso() });
    if let Some(kinds) = &req.allowed_kinds {
        entry["allowedKinds"] = json!(kinds);
    }
    if let Some(label) = &req.label {
        if !label.is_empty() {
            entry["label"] = json!(label);
        }
    }
    approved_obj.insert(req.pubkey.clone(), entry);

    if let Err(e) = write_clients_file("/var/lib/heartwood/clients.json", &approved) {
        tracing::error!("Failed to save clients.json: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": "failed to save client list"})),
        );
    }

    // Remove from pending
    let mut pending = load_clients_file("/var/lib/heartwood/pending-clients.json");
    if let Some(obj) = pending.as_object_mut() {
        obj.remove(&req.pubkey);
        let _ = write_clients_file("/var/lib/heartwood/pending-clients.json", &pending);
    }

    info!("Approved client: {}...", &req.pubkey[..12]);
    (StatusCode::OK, axum::Json(json!({"status": "approved", "pubkey": req.pubkey})))
}

#[derive(Deserialize)]
struct RevokeClient {
    pubkey: String,
}

/// `POST /api/clients/revoke` — remove a client from the approved list.
async fn api_revoke_client(axum::Json(req): axum::Json<RevokeClient>) -> impl IntoResponse {
    let mut approved = load_clients_file("/var/lib/heartwood/clients.json");
    if let Some(obj) = approved.as_object_mut() {
        obj.remove(&req.pubkey);
        if let Err(e) = write_clients_file("/var/lib/heartwood/clients.json", &approved) {
            tracing::error!("Failed to save clients.json: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": "failed to save client list"})),
            );
        }
    }
    info!("Revoked client: {}...", &req.pubkey[..std::cmp::min(12, req.pubkey.len())]);
    (StatusCode::OK, axum::Json(json!({"status": "revoked", "pubkey": req.pubkey})))
}

/// Load a JSON file from the filesystem, returning an empty object if missing or malformed.
fn load_clients_file(path: &str) -> serde_json::Value {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| json!({}))
}

/// Write a JSON value to a file with restrictive permissions.
#[cfg(unix)]
fn write_clients_file(path: &str, data: &serde_json::Value) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let content = serde_json::to_string_pretty(data).map_err(std::io::Error::other)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    std::io::Write::write_all(&mut file, content.as_bytes())
}

#[cfg(not(unix))]
fn write_clients_file(path: &str, data: &serde_json::Value) -> std::io::Result<()> {
    let content = serde_json::to_string_pretty(data).map_err(std::io::Error::other)?;
    std::fs::write(path, content)
}

/// Return the current time as an ISO 8601 string (no external chrono dependency).
fn chrono_now_iso() -> String {
    let dur =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    // Simple ISO format: just the unix timestamp as a string.
    // For a proper ISO date we'd need chrono, but the bunker only needs a
    // human-readable timestamp, so we format it manually.
    let secs = dur.as_secs();
    format!("{secs}")
}

/// Build and return the application router.
///
/// No CORS layer is applied — the web UI uses same-origin requests.
/// Cross-origin access is denied by default for security.
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(serve_index))
        .route("/api/status", get(api_status))
        .route("/api/setup", post(api_setup))
        .route("/api/unlock", post(api_unlock))
        .route("/api/lock", post(api_lock))
        .route("/api/set-pin", post(api_set_pin))
        .route("/api/reset", post(api_reset))
        .route("/api/relays", get(api_get_relays).post(api_set_relays))
        .route("/api/bunker", get(api_bunker))
        .route("/api/bunker/status", get(api_bunker_status))
        .route("/api/password", post(api_set_password))
        .route("/api/tor", get(api_get_tor).post(api_set_tor))
        .route("/api/restart", post(api_restart))
        .route("/api/audit", get(api_audit))
        .route("/api/clients", get(api_get_clients))
        .route("/api/clients/approve", post(api_approve_client))
        .route("/api/clients/revoke", post(api_revoke_client))
        .layer(middleware::from_fn_with_state(state.clone(), lock_middleware))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .layer(DefaultBodyLimit::max(65536))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAKE_PK: &str = "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12";

    #[test]
    fn parse_bunker_pubkey_extracts_valid_key() {
        let uri = format!("bunker://{FAKE_PK}?relay=wss%3A%2F%2Frelay.damus.io");
        assert_eq!(parse_bunker_pubkey(&uri), Some(FAKE_PK));
    }

    #[test]
    fn parse_bunker_pubkey_no_query_string() {
        let uri = format!("bunker://{FAKE_PK}");
        assert_eq!(parse_bunker_pubkey(&uri), Some(FAKE_PK));
    }

    #[test]
    fn parse_bunker_pubkey_rejects_bad_prefix() {
        assert_eq!(parse_bunker_pubkey("nostr://abc"), None);
    }

    #[test]
    fn parse_bunker_pubkey_rejects_short_key() {
        assert_eq!(parse_bunker_pubkey("bunker://abc123?relay=wss://x"), None);
    }

    #[test]
    fn parse_bunker_pubkey_rejects_non_hex() {
        let bad = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        let uri = format!("bunker://{bad}?relay=wss://x");
        assert_eq!(parse_bunker_pubkey(&uri), None);
    }

    #[test]
    fn build_bunker_uri_single_relay() {
        let relays = vec!["wss://relay.damus.io".to_string()];
        let uri = build_bunker_uri(FAKE_PK, &relays);
        assert_eq!(uri, format!("bunker://{FAKE_PK}?relay=wss%3A%2F%2Frelay.damus.io"));
    }

    #[test]
    fn build_bunker_uri_multiple_relays() {
        let relays = vec!["wss://relay.damus.io".to_string(), "wss://nos.lol".to_string()];
        let uri = build_bunker_uri(FAKE_PK, &relays);
        assert!(uri.starts_with(&format!("bunker://{FAKE_PK}?")));
        assert!(uri.contains("relay=wss%3A%2F%2Frelay.damus.io"));
        assert!(uri.contains("relay=wss%3A%2F%2Fnos.lol"));
        // Relays joined by &
        assert!(uri.contains("&relay="));
    }

    #[test]
    fn build_bunker_uri_preserves_relay_order() {
        let relays = vec!["wss://first.relay".to_string(), "wss://second.relay".to_string()];
        let uri = build_bunker_uri(FAKE_PK, &relays);
        let first_pos = uri.find("first").unwrap();
        let second_pos = uri.find("second").unwrap();
        assert!(first_pos < second_pos, "relay order must be preserved");
    }

    #[test]
    fn build_bunker_uri_round_trips_through_parse() {
        let relays = vec!["wss://relay.damus.io".to_string()];
        let uri = build_bunker_uri(FAKE_PK, &relays);
        // The pubkey should be extractable from the built URI
        assert_eq!(parse_bunker_pubkey(&uri), Some(FAKE_PK));
    }
}
