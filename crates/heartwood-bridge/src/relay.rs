//! Per-relay websocket task.
//!
//! Subscribes for NIP-46 requests addressed to our masters, forwards each
//! (de-duplicated) request to the serial worker, and publishes the device's
//! signed response events back to the relay. Reconnects with capped backoff.
//!
//! NIP-42 AUTH is intentionally unsupported: the bridge holds no key, so it
//! cannot sign an auth challenge. Relays that demand AUTH for kind-24133 are
//! out of scope (the device-direct wifi-standalone tier is the answer there).

use std::time::Duration;

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{broadcast, mpsc};
use tokio_tungstenite::tungstenite::Message;

use crate::dedup::Seen;
use crate::event::{Nip46Request, NIP46_KIND};

/// A unit of work for the serial worker.
#[derive(Debug, Clone)]
pub struct RequestJob {
    pub request: Nip46Request,
}

const SUBSCRIPTION_ID: &str = "heartwood-bridge";
const MIN_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Run one relay connection forever, reconnecting with capped backoff.
pub async fn run_relay(
    url: String,
    masters: Vec<String>,
    seen: Seen,
    job_tx: mpsc::Sender<RequestJob>,
    resp_tx: broadcast::Sender<String>,
) {
    let mut backoff = MIN_BACKOFF;
    loop {
        match connect_and_serve(&url, &masters, &seen, &job_tx, &resp_tx).await {
            Ok(()) => {
                tracing::info!(relay = %url, "connection closed; reconnecting");
                backoff = MIN_BACKOFF;
            }
            Err(e) => {
                tracing::warn!(relay = %url, "relay error: {e:#}; retry in {}s", backoff.as_secs());
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

async fn connect_and_serve(
    url: &str,
    masters: &[String],
    seen: &Seen,
    job_tx: &mpsc::Sender<RequestJob>,
    resp_tx: &broadcast::Sender<String>,
) -> Result<()> {
    let (ws, _) = tokio_tungstenite::connect_async(url)
        .await
        .with_context(|| format!("connecting to {url}"))?;
    tracing::info!(relay = %url, "connected");
    let (mut write, mut read) = ws.split();

    // Subscribe to live NIP-46 requests addressed to any of our masters.
    let since = crate::now_unix();
    let req = json!(["REQ", SUBSCRIPTION_ID, {
        "kinds": [NIP46_KIND],
        "#p": masters,
        "since": since,
    }]);
    write.send(Message::Text(req.to_string())).await.context("sending REQ")?;

    let mut resp_rx = resp_tx.subscribe();

    loop {
        tokio::select! {
            // Inbound from the relay.
            incoming = read.next() => {
                let msg = match incoming {
                    Some(m) => m.context("relay read failed")?,
                    None => return Ok(()), // stream ended
                };
                match msg {
                    Message::Text(text) => handle_relay_message(&text, url, masters, seen, job_tx).await,
                    Message::Ping(payload) => { let _ = write.send(Message::Pong(payload)).await; }
                    Message::Close(_) => return Ok(()),
                    _ => {}
                }
            }
            // Outbound: a freshly-signed response to publish everywhere.
            broadcasted = resp_rx.recv() => {
                match broadcasted {
                    Ok(event_json) => {
                        let publish = format!("[\"EVENT\",{event_json}]");
                        write.send(Message::Text(publish)).await.context("publishing event")?;
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(relay = %url, "publish lagged; dropped {n} response(s)");
                    }
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                }
            }
        }
    }
}

async fn handle_relay_message(
    text: &str,
    url: &str,
    masters: &[String],
    seen: &Seen,
    job_tx: &mpsc::Sender<RequestJob>,
) {
    let parsed: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return,
    };
    let arr = match parsed.as_array() {
        Some(a) if !a.is_empty() => a,
        _ => return,
    };

    match arr[0].as_str() {
        // ["EVENT", sub_id, event]
        Some("EVENT") => {
            let Some(event) = arr.get(2) else { return };
            match Nip46Request::from_event(event, masters) {
                Ok(Some(request)) => {
                    if seen.insert(&request.id) {
                        tracing::info!(
                            relay = %url,
                            client = %short(&request.client_pubkey_hex),
                            "request received"
                        );
                        if let Err(e) = job_tx.send(RequestJob { request }).await {
                            tracing::error!("serial worker is gone: {e}");
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => tracing::debug!(relay = %url, "ignoring malformed event: {e}"),
            }
        }
        // ["OK", id, accepted, message]
        Some("OK") => {
            let accepted = arr.get(2).and_then(Value::as_bool).unwrap_or(false);
            if !accepted {
                let msg = arr.get(3).and_then(Value::as_str).unwrap_or("");
                tracing::warn!(relay = %url, "relay rejected publish: {msg}");
            }
        }
        // ["CLOSED", sub_id, message]
        Some("CLOSED") => {
            let msg = arr.get(2).and_then(Value::as_str).unwrap_or("");
            tracing::warn!(relay = %url, "subscription closed by relay: {msg}");
        }
        // ["NOTICE", message]
        Some("NOTICE") => {
            let msg = arr.get(1).and_then(Value::as_str).unwrap_or("");
            tracing::debug!(relay = %url, "notice: {msg}");
        }
        _ => {} // EOSE and anything else: ignore
    }
}

/// First 12 hex chars, for compact logging.
fn short(hex: &str) -> &str {
    &hex[..hex.len().min(12)]
}
