mod audit;
#[allow(dead_code)]
mod oled;
mod storage;
mod web;

use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    info!("Heartwood starting...");

    let data_dir =
        std::env::var("HEARTWOOD_DATA_DIR").unwrap_or_else(|_| "/var/lib/heartwood".to_string());
    let data_path = std::path::PathBuf::from(&data_dir);
    info!("Data directory: {}", data_dir);

    let oled = oled::Oled::new();
    let storage = storage::Storage::new(Some(data_path.clone()));
    let audit_log = audit::AuditLog::with_persistence(data_path.join("audit.log"));

    oled.show_text("HEARTWOOD");

    // Check for existing runtime payload (survives service restarts).
    // If present, resume unlocked state without requiring PIN.
    let cached_payload = {
        let payload_path = data_path.join("master.payload");
        match std::fs::read_to_string(&payload_path) {
            Ok(p) if !p.trim().is_empty() => {
                info!("Resuming unlocked state from cached payload");
                oled.show_text("UNLOCKED");
                Some(zeroize::Zeroizing::new(p.trim().to_string()))
            }
            _ => None,
        }
    };

    if cached_payload.is_none() {
        if !storage.has_master_secret() {
            oled.show_text("SETUP MODE");
            info!("No master secret found. Entering setup mode.");
        } else {
            info!("Master secret stored. Device locked until PIN is entered.");
            oled.show_text("LOCKED");
        }
    }

    let state = Arc::new(web::AppState {
        audit_log: Mutex::new(audit_log),
        storage: Mutex::new(storage),
        decrypted_payload: Mutex::new(cached_payload),
        unlock_throttle: Mutex::new(web::UnlockThrottle::new()),
        data_dir: data_path,
    });
    let app = web::create_router(state);

    let bind_addr = std::env::var("HEARTWOOD_BIND").unwrap_or_else(|_| "0.0.0.0:3000".to_string());
    let listener = match tokio::net::TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind {bind_addr}: {e}");
            std::process::exit(1);
        }
    };
    info!("Web UI listening on {bind_addr}");
    oled.show_text("READY");

    if let Err(e) = axum::serve(listener, app).await {
        error!("Server error: {e}");
        std::process::exit(1);
    }
}
