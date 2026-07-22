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
/// Client-originated WebSocket ping cadence. NIP-46 traffic is bursty; an
/// idle flow gets silently evicted by stateful NATs and reverse proxies
/// (consumer conntrack commonly times out established TCP at 3600s — field
/// signature: the bridge goes deaf after "about an hour"). Pings keep the
/// flow warm and give the idle detector traffic to observe.
const PING_INTERVAL: Duration = Duration::from_secs(30);
/// No inbound traffic (pong, EVENT, anything) for this long means the socket
/// is half-open: packets are being black-holed and `read.next()` would wait
/// forever. Bail so the reconnect loop re-dials and re-subscribes. Three
/// missed pings — generous against a slow relay, decisive against a dead one.
const IDLE_LIMIT: Duration = Duration::from_secs(90);
/// Bound on any outbound send. A half-open socket can also park a write once
/// the kernel buffer fills; never let that disable the idle detector.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// What the caller must do after a handled relay message.
#[derive(Debug, PartialEq, Eq)]
enum Flow {
    Continue,
    /// The relay closed our subscription — only a fresh REQ (via reconnect)
    /// restores request delivery, so the session must be recycled.
    Resubscribe,
}

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

    let mut ping =
        tokio::time::interval_at(tokio::time::Instant::now() + PING_INTERVAL, PING_INTERVAL);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_inbound = tokio::time::Instant::now();

    loop {
        tokio::select! {
            // Inbound from the relay.
            incoming = read.next() => {
                let msg = match incoming {
                    Some(m) => m.context("relay read failed")?,
                    None => return Ok(()), // stream ended
                };
                last_inbound = tokio::time::Instant::now();
                match msg {
                    Message::Text(text) => {
                        if handle_relay_message(&text, url, masters, seen, job_tx).await == Flow::Resubscribe {
                            anyhow::bail!("subscription closed by relay");
                        }
                    }
                    Message::Ping(payload) => { let _ = write.send(Message::Pong(payload)).await; }
                    Message::Close(_) => return Ok(()),
                    _ => {} // Pong and binary: traffic is all we needed to see
                }
            }
            // Keepalive + half-open detection. The check runs before the
            // send, so a black-holed flow is declared dead by silence alone.
            _ = ping.tick() => {
                let idle = last_inbound.elapsed();
                if idle >= IDLE_LIMIT {
                    anyhow::bail!("no relay traffic for {}s; connection presumed dead", idle.as_secs());
                }
                tokio::time::timeout(SEND_TIMEOUT, write.send(Message::Ping(Vec::new())))
                    .await
                    .context("keepalive ping send timed out")?
                    .context("sending keepalive ping")?;
            }
            // Outbound: a freshly-signed response to publish everywhere.
            broadcasted = resp_rx.recv() => {
                match broadcasted {
                    Ok(event_json) => {
                        let publish = format!("[\"EVENT\",{event_json}]");
                        tokio::time::timeout(SEND_TIMEOUT, write.send(Message::Text(publish)))
                            .await
                            .context("publish send timed out")?
                            .context("publishing event")?;
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
) -> Flow {
    let parsed: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return Flow::Continue,
    };
    let arr = match parsed.as_array() {
        Some(a) if !a.is_empty() => a,
        _ => return Flow::Continue,
    };

    match arr[0].as_str() {
        // ["EVENT", sub_id, event]
        Some("EVENT") => {
            let Some(event) = arr.get(2) else { return Flow::Continue };
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
            let sub = arr.get(1).and_then(Value::as_str).unwrap_or("");
            let msg = arr.get(2).and_then(Value::as_str).unwrap_or("");
            tracing::warn!(relay = %url, "subscription closed by relay: {msg}");
            if sub == SUBSCRIPTION_ID {
                // Without the REQ no request ever reaches the device again;
                // logging alone left the bridge connected but deaf.
                return Flow::Resubscribe;
            }
        }
        // ["NOTICE", message]
        Some("NOTICE") => {
            let msg = arr.get(1).and_then(Value::as_str).unwrap_or("");
            tracing::debug!(relay = %url, "notice: {msg}");
        }
        _ => {} // EOSE and anything else: ignore
    }
    Flow::Continue
}

/// First 12 hex chars, for compact logging.
fn short(hex: &str) -> &str {
    &hex[..hex.len().min(12)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::sync::mpsc;

    const MASTER: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    const OTHER_MASTER: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const CLIENT: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    /// `["EVENT", sub, {…}]` addressed (`p` tag) to `master`.
    fn event_msg(kind: u64, master: &str, id: impl AsRef<str>) -> String {
        json!(["EVENT", "sub", {
            "id": id.as_ref(),
            "pubkey": CLIENT,
            "created_at": 1_700_000_000u64,
            "kind": kind,
            "tags": [["p", master]],
            "content": "AgCipherTextBase64==",
            "sig": "ff".repeat(64),
        }])
        .to_string()
    }

    /// masters = [MASTER]; a fresh dedup set; a job channel to observe dispatch.
    fn harness() -> (Vec<String>, Seen, mpsc::Sender<RequestJob>, mpsc::Receiver<RequestJob>) {
        let (tx, rx) = mpsc::channel(8);
        (vec![MASTER.to_string()], Seen::new(64), tx, rx)
    }

    #[tokio::test]
    async fn valid_request_for_our_master_queues_exactly_one_job() {
        let (masters, seen, tx, mut rx) = harness();
        let msg = event_msg(NIP46_KIND, MASTER, "a".repeat(64));
        handle_relay_message(&msg, "ws://t", &masters, &seen, &tx).await;

        let job = rx.try_recv().expect("a job should be queued");
        assert_eq!(job.request.master_pubkey_hex, MASTER);
        assert_eq!(job.request.client_pubkey_hex, CLIENT);
        assert_eq!(job.request.content, "AgCipherTextBase64==");
        assert!(rx.try_recv().is_err(), "exactly one job");
    }

    #[tokio::test]
    async fn duplicate_id_from_a_second_relay_is_not_requeued() {
        // The same request usually arrives from several relays at once; the
        // device must sign it once. Same id, two relays -> one job.
        let (masters, seen, tx, mut rx) = harness();
        let msg = event_msg(NIP46_KIND, MASTER, "b".repeat(64));
        handle_relay_message(&msg, "ws://relay-a", &masters, &seen, &tx).await;
        handle_relay_message(&msg, "ws://relay-b", &masters, &seen, &tx).await;

        assert!(rx.try_recv().is_ok(), "first sighting queues a job");
        assert!(rx.try_recv().is_err(), "the duplicate must be dropped");
    }

    #[tokio::test]
    async fn event_for_a_master_we_do_not_hold_is_ignored() {
        let (masters, seen, tx, mut rx) = harness();
        let msg = event_msg(NIP46_KIND, OTHER_MASTER, "c".repeat(64));
        handle_relay_message(&msg, "ws://t", &masters, &seen, &tx).await;
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn non_nip46_kind_is_ignored() {
        let (masters, seen, tx, mut rx) = harness();
        let msg = event_msg(1, MASTER, "d".repeat(64));
        handle_relay_message(&msg, "ws://t", &masters, &seen, &tx).await;
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn an_id_less_request_is_let_through_not_swallowed() {
        // dedup can't key an id-less event, so the handler must forward it
        // rather than silently drop it.
        let (masters, seen, tx, mut rx) = harness();
        let msg = json!(["EVENT", "sub", {
            "pubkey": CLIENT,
            "created_at": 1_700_000_000u64,
            "kind": NIP46_KIND,
            "tags": [["p", MASTER]],
            "content": "AgCipherTextBase64==",
            "sig": "ff".repeat(64),
        }])
        .to_string();
        handle_relay_message(&msg, "ws://t", &masters, &seen, &tx).await;
        assert!(rx.try_recv().is_ok(), "an id-less request is still dispatched");
    }

    #[tokio::test]
    async fn closed_for_our_subscription_forces_a_resubscribe() {
        let (masters, seen, tx, mut rx) = harness();
        let msg = format!(r#"["CLOSED","{SUBSCRIPTION_ID}","rate-limited"]"#);
        let flow = handle_relay_message(&msg, "ws://t", &masters, &seen, &tx).await;
        assert_eq!(flow, Flow::Resubscribe);
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn closed_for_a_foreign_subscription_changes_nothing() {
        let (masters, seen, tx, mut rx) = harness();
        let msg = r#"["CLOSED","someone-else","bye"]"#;
        let flow = handle_relay_message(msg, "ws://t", &masters, &seen, &tx).await;
        assert_eq!(flow, Flow::Continue);
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn protocol_noise_and_garbage_queue_nothing() {
        let (masters, seen, tx, mut rx) = harness();
        for msg in [
            r#"["EOSE","sub"]"#,
            r#"["OK","id",false,"blocked: pow"]"#,
            r#"["OK","id",true]"#,
            r#"["NOTICE","hello"]"#,
            r#"["CLOSED","sub","bye"]"#,
            r#"["EVENT","sub"]"#, // EVENT verb but no event element
            r#"not json at all"#,
            r#"{"not":"an array"}"#,
            r#"[]"#,
            r#"["EVENT","sub",{"kind":24133,"tags":[["p","short"]],"pubkey":"x"}]"#, // for nobody
        ] {
            handle_relay_message(msg, "ws://t", &masters, &seen, &tx).await;
        }
        assert!(rx.try_recv().is_err(), "no job from any non-request message");
    }
}
