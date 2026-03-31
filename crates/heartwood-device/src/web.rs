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
use crate::storage::Storage;

/// Shared application state for all HTTP handlers.
pub struct AppState {
    pub audit_log: Mutex<AuditLog>,
    pub storage: Mutex<Storage>,
}

/// Serve the bundled `index.html`.
async fn serve_index() -> impl IntoResponse {
    let html = include_str!("../../../web/index.html");
    (StatusCode::OK, [(header::CONTENT_TYPE, "text/html; charset=utf-8")], html)
}

/// `GET /api/status` — return device status including setup state.
///
/// When configured, also returns the mode and npub so the UI can display them.
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

    // Parse stored payload to extract mode and derive npub for display.
    let (mode, npub) = match storage.load_master_secret() {
        Ok(bytes) => {
            let payload = String::from_utf8_lossy(&bytes);
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
        Err(_) => ("unknown".to_string(), String::new()),
    };

    // Read bunker URI if available
    let bunker_uri = std::fs::read_to_string("/var/lib/heartwood/bunker-uri.txt")
        .ok()
        .map(|s| s.trim().to_string());

    axum::Json(json!({
        "status": "running",
        "version": env!("CARGO_PKG_VERSION"),
        "setup_required": false,
        "has_password": has_password,
        "tor_enabled": tor_enabled,
        "mode": mode,
        "npub": npub,
        "relays": relays,
        "bunker_uri": bunker_uri
    }))
}

#[derive(Deserialize)]
struct SetupRequest {
    /// "bunker", "tree-mnemonic", or "tree-nsec"
    mode: String,
    mnemonic: Option<String>,
    passphrase: Option<String>,
    nsec: Option<String>,
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

    if let Err(e) = storage.save_master_secret(payload.as_bytes()) {
        tracing::error!("Failed to save master secret: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": "failed to save configuration"})),
        );
    }

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
                return (
                    StatusCode::FORBIDDEN,
                    axum::Json(json!({"error": "incorrect password"})),
                );
            }
        }
        None => {
            // No password set — should not happen in practice since auth_middleware
            // would allow unauthenticated access, but handle gracefully.
        }
    }

    match storage.delete_master_secret() {
        Ok(()) => {
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

/// `GET /api/bunker` — return the bunker URI if the bunker sidecar has written one.
async fn api_bunker() -> impl IntoResponse {
    match std::fs::read_to_string("/var/lib/heartwood/bunker-uri.txt") {
        Ok(uri) => axum::Json(json!({"uri": uri.trim()})),
        Err(_) => axum::Json(json!({"uri": null, "message": "bunker not running"})),
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

/// Build and return the application router.
///
/// No CORS layer is applied — the web UI uses same-origin requests.
/// Cross-origin access is denied by default for security.
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(serve_index))
        .route("/api/status", get(api_status))
        .route("/api/setup", post(api_setup))
        .route("/api/reset", post(api_reset))
        .route("/api/relays", get(api_get_relays).post(api_set_relays))
        .route("/api/bunker", get(api_bunker))
        .route("/api/password", post(api_set_password))
        .route("/api/tor", post(api_set_tor))
        .route("/api/audit", get(api_audit))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .layer(DefaultBodyLimit::max(65536))
        .with_state(state)
}
