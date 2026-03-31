// crates/heartwood-device/src/web.rs
//! Axum HTTP server providing the Heartwood local web UI.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use serde_json::json;
use tokio::sync::Mutex;

use crate::audit::AuditLog;

/// Shared application state for all HTTP handlers.
pub struct AppState {
    pub audit_log: Mutex<AuditLog>,
}

/// Serve the bundled `index.html`.
async fn serve_index() -> impl IntoResponse {
    let html = include_str!("../../../web/index.html");
    (StatusCode::OK, [(header::CONTENT_TYPE, "text/html; charset=utf-8")], html)
}

/// `GET /api/status` — return basic device status as JSON.
async fn api_status() -> impl IntoResponse {
    axum::Json(json!({
        "status": "running",
        "version": "0.1.0"
    }))
}

/// `GET /api/audit` — return all recent audit log entries as JSON.
async fn api_audit(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let log = state.audit_log.lock().await;
    let entries: Vec<_> = log.entries().iter().collect();
    axum::Json(serde_json::to_value(&entries).unwrap_or(json!([])))
}

/// Build and return the application router.
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(serve_index))
        .route("/api/status", get(api_status))
        .route("/api/audit", get(api_audit))
        .with_state(state)
}
