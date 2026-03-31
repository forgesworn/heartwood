// Scaffold modules -- many methods are wired up in later phases
#[allow(dead_code)]
mod audit;
#[allow(dead_code)]
mod oled;
#[allow(dead_code)]
mod storage;
#[allow(dead_code)]
mod tor;
mod web;

use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    info!("Heartwood starting...");

    let oled = oled::Oled::new();
    let storage = storage::Storage::new(None);
    let tor = tor::TorManager::new();
    let audit_log = audit::AuditLog::new();

    oled.show_text("HEARTWOOD");

    if !storage.has_master_secret() {
        oled.show_text("SETUP MODE");
        info!("No master secret found. Entering setup mode.");
    } else {
        info!("Master secret found. Waiting for PIN...");
        oled.show_text("Enter PIN");
    }

    oled.show_text("Connecting to Tor...");
    if let Some(onion) = tor.wait_for_onion(120).await {
        // Log only a truncated form to avoid leaking the full .onion address.
        // .onion addresses are ASCII, but use get() to be panic-free.
        let truncated = onion.get(..8).unwrap_or(&onion);
        info!("Tor hidden service ready: {}...", truncated);
        oled.show_qr(&onion);
    } else {
        info!("Tor not available, running on local network only");
        oled.show_text("heartwood.local");
    }

    let state = Arc::new(web::AppState { audit_log: Mutex::new(audit_log) });
    let app = web::create_router(state);

    let listener = match tokio::net::TcpListener::bind("127.0.0.1:8080").await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind 127.0.0.1:8080: {e}");
            std::process::exit(1);
        }
    };
    info!("Web UI listening on 127.0.0.1:8080");
    oled.show_text("READY");

    if let Err(e) = axum::serve(listener, app).await {
        error!("Server error: {e}");
        std::process::exit(1);
    }
}
