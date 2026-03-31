mod audit;
mod oled;
mod storage;
mod tor;
mod web;

use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

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
        info!("Tor hidden service: {}", onion);
        oled.show_qr(&onion);
    } else {
        info!("Tor not available, running on local network only");
        oled.show_text("heartwood.local");
    }

    let state = Arc::new(web::AppState { audit_log: Mutex::new(audit_log) });
    let app = web::create_router(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    info!("Web UI listening on :8080");
    oled.show_text("READY");

    axum::serve(listener, app).await.unwrap();
}
