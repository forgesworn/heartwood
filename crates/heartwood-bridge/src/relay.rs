//! Per-relay websocket task.
//!
//! Subscribes for NIP-46 requests addressed to our masters, forwards each
//! (de-duplicated) request to the serial worker, and publishes the device's
//! signed response events back to the relay. Reconnects with capped backoff.
//!
//! NIP-42 AUTH: the bridge holds no key, so the device signs. A relay's
//! `["AUTH", challenge]` is only remembered; the bridge signs in only when the
//! relay refuses our subscription with `auth-required:` (or `restricted:`
//! after sending a challenge), so relays that offer
//! AUTH without needing it never learn which keys sit behind this connection.
//! It then signs in once per master on that one connection and challenge
//! (NIP-42 lets a connection hold several authenticated keys, and the
//! subscription's `#p` names all of them), waits for every `OK`, and re-sends
//! the same REQ. A refused or unsignable AUTH ends the connection and backs off
//! for [`AUTH_FAILURE_BACKOFF`] rather than hammering the relay or the device.

use std::collections::HashSet;
use std::time::Duration;

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;

use crate::dedup::Seen;
use crate::event::{check_challenge, check_signed_relay_auth, Nip46Request, NIP46_KIND};

/// A unit of work for the (single, sequential) device worker.
#[derive(Debug)]
pub enum DeviceJob {
    /// A NIP-46 request; the signed response is broadcast to every relay.
    Request(Nip46Request),
    /// A NIP-42 relay AUTH signature, answered to the one asking connection.
    RelayAuth(RelayAuthJob),
}

/// Ask the device to sign a kind 22242 AUTH event as one master.
#[derive(Debug)]
pub struct RelayAuthJob {
    pub master_pubkey_hex: String,
    /// The configured relay URL, used verbatim as the `relay` tag.
    pub relay_url: String,
    pub challenge: String,
    /// The signed event JSON, or `None` if the device would not sign.
    pub reply: oneshot::Sender<Option<String>>,
}

const SUBSCRIPTION_ID: &str = "heartwood-bridge";
const MIN_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// Back-off after an AUTH failure (device cannot sign, relay refuses the key,
/// or refuses the subscription after AUTH). None of these heal in seconds, and
/// each retry costs a device signature per master.
const AUTH_FAILURE_BACKOFF: Duration = Duration::from_secs(300);
/// How long the relay has to answer our AUTH events with `OK`.
const AUTH_OK_TIMEOUT: Duration = Duration::from_secs(30);
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

/// NIP-42 sign-in failed in a way a quick retry will not fix.
#[derive(Debug)]
struct AuthFailure(String);

impl std::fmt::Display for AuthFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "relay AUTH failed: {}", self.0)
    }
}

impl std::error::Error for AuthFailure {}

/// What the caller must do after a handled relay message.
#[derive(Debug, PartialEq, Eq)]
enum Flow {
    Continue,
    /// The relay closed our subscription with this message.
    SubscriptionClosed(String),
    /// `["AUTH", challenge]`.
    AuthChallenge(String),
    /// `["OK", id, accepted, message]`, for a publish or one of our AUTHs.
    Ok {
        id: String,
        accepted: bool,
        message: String,
    },
}

/// Per-connection NIP-42 state.
#[derive(Default)]
struct AuthState {
    /// The first challenge the relay sent on this connection.
    challenge: Option<String>,
    /// The relay refused our REQ with `auth-required:`.
    wanted: bool,
    /// When the relay first asked; bounds the wait for its challenge.
    wanted_at: Option<tokio::time::Instant>,
    /// Signatures have been requested from the device.
    started: bool,
    /// Ids of our AUTH events the relay has not yet answered.
    awaiting_ok: HashSet<String>,
    sent_at: Option<tokio::time::Instant>,
    /// Every master's AUTH was accepted.
    authenticated: bool,
}

/// The signed AUTH events for every master as `(id, json)`, or why not.
type AuthResult = std::result::Result<Vec<(String, String)>, String>;

/// Run one relay connection forever, reconnecting with capped backoff.
pub async fn run_relay(
    url: String,
    masters: Vec<String>,
    seen: Seen,
    job_tx: mpsc::Sender<DeviceJob>,
    resp_tx: broadcast::Sender<String>,
) {
    let mut backoff = MIN_BACKOFF;
    loop {
        let mut wait = backoff;
        match connect_and_serve(&url, &masters, &seen, &job_tx, &resp_tx).await {
            Ok(()) => {
                tracing::info!(relay = %url, "connection closed; reconnecting");
                backoff = MIN_BACKOFF;
                wait = backoff;
            }
            Err(e) if e.downcast_ref::<AuthFailure>().is_some() => {
                wait = AUTH_FAILURE_BACKOFF;
                tracing::warn!(relay = %url, "{e:#}; retry in {}s", wait.as_secs());
            }
            Err(e) => {
                tracing::warn!(relay = %url, "relay error: {e:#}; retry in {}s", backoff.as_secs());
            }
        }
        tokio::time::sleep(wait).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

async fn connect_and_serve(
    url: &str,
    masters: &[String],
    seen: &Seen,
    job_tx: &mpsc::Sender<DeviceJob>,
    resp_tx: &broadcast::Sender<String>,
) -> Result<()> {
    let (ws, _) = tokio_tungstenite::connect_async(url)
        .await
        .with_context(|| format!("connecting to {url}"))?;
    tracing::info!(relay = %url, "connected");
    let (mut write, mut read) = ws.split();

    // Subscribe to live NIP-46 requests addressed to any of our masters. The
    // same REQ (same `since`) is re-sent after a NIP-42 sign-in.
    let since = crate::now_unix();
    let req = json!(["REQ", SUBSCRIPTION_ID, {
        "kinds": [NIP46_KIND],
        "#p": masters,
        "since": since,
    }])
    .to_string();
    write.send(Message::Text(req.clone().into())).await.context("sending REQ")?;
    let mut subscribed = true;

    let mut resp_rx = resp_tx.subscribe();
    let mut auth = AuthState::default();
    let mut auth_rx: Option<oneshot::Receiver<AuthResult>> = None;

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
                let text = match msg {
                    Message::Text(text) => text,
                    Message::Ping(payload) => { let _ = write.send(Message::Pong(payload)).await; continue; }
                    Message::Close(_) => return Ok(()),
                    _ => continue, // Pong and binary: traffic is all we needed to see
                };
                match handle_relay_message(&text, url, masters, seen, job_tx).await {
                    Flow::Continue => {}
                    Flow::SubscriptionClosed(msg) => {
                        subscribed = false;
                        let auth_required = msg.starts_with("auth-required:");
                        let restricted = msg.starts_with("restricted:");
                        if auth.authenticated && (auth_required || restricted) {
                            return Err(AuthFailure(format!(
                                "relay refused the subscription after AUTH: {msg}"
                            ))
                            .into());
                        }
                        // `restricted:` from a relay that has already sent a
                        // challenge is a sign-in prompt too: some gates word
                        // every refusal that way.
                        if !(auth_required || (restricted && auth.challenge.is_some())) {
                            // Without the REQ no request ever reaches the
                            // device again; logging alone left the bridge
                            // connected but deaf.
                            anyhow::bail!("subscription closed by relay: {msg}");
                        }
                        tracing::info!(relay = %url, "relay requires AUTH before serving requests");
                        if !auth.wanted {
                            auth.wanted = true;
                            auth.wanted_at = Some(tokio::time::Instant::now());
                        }
                    }
                    Flow::AuthChallenge(challenge) => {
                        if auth.challenge.is_some() {
                            tracing::debug!(relay = %url, "ignoring a repeat AUTH challenge");
                        } else if let Err(e) = check_challenge(&challenge) {
                            tracing::warn!(relay = %url, "ignoring unusable AUTH challenge: {e:#}");
                        } else {
                            auth.challenge = Some(challenge);
                        }
                    }
                    Flow::Ok { id, accepted, message } => {
                        if auth.awaiting_ok.remove(&id) {
                            if !accepted {
                                return Err(AuthFailure(format!("relay refused AUTH: {message}")).into());
                            }
                            if auth.awaiting_ok.is_empty() {
                                auth.authenticated = true;
                                tracing::info!(relay = %url, "signed in as {} key(s)", masters.len());
                                if !subscribed {
                                    send_text(&mut write, req.clone()).await.context("re-sending REQ")?;
                                    subscribed = true;
                                }
                            }
                        } else if !accepted {
                            tracing::warn!(relay = %url, "relay rejected publish: {message}");
                        }
                    }
                }
                // Sign in once the relay has both asked (auth-required) and
                // given us a challenge, in whichever order they arrived.
                if auth.wanted && !auth.started {
                    if let Some(challenge) = auth.challenge.clone() {
                        auth.started = true;
                        auth_rx = Some(request_auth_signatures(
                            job_tx.clone(),
                            masters.to_vec(),
                            url.to_string(),
                            challenge,
                        ));
                    }
                }
            }
            // The device's AUTH signatures for every master.
            signed = async { auth_rx.as_mut().expect("guarded by is_some").await }, if auth_rx.is_some() => {
                auth_rx = None;
                let events = match signed {
                    Ok(Ok(events)) => events,
                    Ok(Err(why)) => return Err(AuthFailure(why).into()),
                    Err(_) => return Err(AuthFailure("the AUTH signer went away".into()).into()),
                };
                for (id, event_json) in events {
                    auth.awaiting_ok.insert(id);
                    send_text(&mut write, format!("[\"AUTH\",{event_json}]")).await.context("sending AUTH")?;
                }
                auth.sent_at = Some(tokio::time::Instant::now());
            }
            // Keepalive + half-open detection. The check runs before the
            // send, so a black-holed flow is declared dead by silence alone.
            _ = ping.tick() => {
                let idle = last_inbound.elapsed();
                if idle >= IDLE_LIMIT {
                    anyhow::bail!("no relay traffic for {}s; connection presumed dead", idle.as_secs());
                }
                // Asked to sign in but never given a usable challenge: the
                // subscription is closed, so re-dial rather than sit deaf.
                if let Some(wanted_at) = auth.wanted_at {
                    if !auth.started && wanted_at.elapsed() >= AUTH_OK_TIMEOUT {
                        anyhow::bail!("relay required AUTH but sent no usable challenge");
                    }
                }
                if let Some(sent_at) = auth.sent_at {
                    if !auth.awaiting_ok.is_empty() && sent_at.elapsed() >= AUTH_OK_TIMEOUT {
                        return Err(AuthFailure("relay never answered our AUTH".into()).into());
                    }
                }
                tokio::time::timeout(SEND_TIMEOUT, write.send(Message::Ping(Vec::new().into())))
                    .await
                    .context("keepalive ping send timed out")?
                    .context("sending keepalive ping")?;
            }
            // Outbound: a freshly-signed response to publish everywhere.
            broadcasted = resp_rx.recv() => {
                match broadcasted {
                    Ok(event_json) => {
                        send_text(&mut write, format!("[\"EVENT\",{event_json}]"))
                            .await
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

/// Send one text frame, bounded by [`SEND_TIMEOUT`].
async fn send_text<S>(write: &mut S, text: String) -> Result<()>
where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    tokio::time::timeout(SEND_TIMEOUT, write.send(Message::Text(text.into())))
        .await
        .context("send timed out")?
        .context("send failed")
}

/// Ask the device, one master at a time, for a signed AUTH on `challenge`.
/// All or nothing: the relay serves `#p` only for keys that signed in, so a
/// partial sign-in would still leave the subscription refused.
fn request_auth_signatures(
    job_tx: mpsc::Sender<DeviceJob>,
    masters: Vec<String>,
    url: String,
    challenge: String,
) -> oneshot::Receiver<AuthResult> {
    let (done_tx, done_rx) = oneshot::channel();
    tokio::spawn(async move {
        let mut signed = Vec::with_capacity(masters.len());
        for master in masters {
            let (reply, reply_rx) = oneshot::channel();
            let job = DeviceJob::RelayAuth(RelayAuthJob {
                master_pubkey_hex: master.clone(),
                relay_url: url.clone(),
                challenge: challenge.clone(),
                reply,
            });
            if job_tx.send(job).await.is_err() {
                let _ = done_tx.send(Err("the device worker is gone".into()));
                return;
            }
            let outcome = match reply_rx.await {
                Ok(Some(json)) => check_signed_relay_auth(&json, &master, &url, &challenge)
                    .map(|id| (id, json))
                    .map_err(|e| format!("device returned an unusable AUTH event: {e:#}")),
                Ok(None) => Err(format!(
                    "device would not sign AUTH as {} (firmware without RELAY_AUTH, locked, \
                     or unknown key)",
                    short(&master)
                )),
                Err(_) => Err("the device worker dropped the AUTH request".into()),
            };
            match outcome {
                Ok(pair) => signed.push(pair),
                Err(why) => {
                    let _ = done_tx.send(Err(why));
                    return;
                }
            }
        }
        let _ = done_tx.send(Ok(signed));
    });
    done_rx
}

async fn handle_relay_message(
    text: &str,
    url: &str,
    masters: &[String],
    seen: &Seen,
    job_tx: &mpsc::Sender<DeviceJob>,
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
                        if let Err(e) = job_tx.send(DeviceJob::Request(request)).await {
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
            return Flow::Ok {
                id: arr.get(1).and_then(Value::as_str).unwrap_or("").to_string(),
                accepted: arr.get(2).and_then(Value::as_bool).unwrap_or(false),
                message: arr.get(3).and_then(Value::as_str).unwrap_or("").to_string(),
            };
        }
        // ["CLOSED", sub_id, message]
        Some("CLOSED") => {
            let sub = arr.get(1).and_then(Value::as_str).unwrap_or("");
            let msg = arr.get(2).and_then(Value::as_str).unwrap_or("");
            tracing::warn!(relay = %url, "subscription closed by relay: {msg}");
            if sub == SUBSCRIPTION_ID {
                return Flow::SubscriptionClosed(msg.to_string());
            }
        }
        // ["AUTH", challenge]
        Some("AUTH") => {
            if let Some(challenge) = arr.get(1).and_then(Value::as_str) {
                return Flow::AuthChallenge(challenge.to_string());
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
    fn harness() -> (Vec<String>, Seen, mpsc::Sender<DeviceJob>, mpsc::Receiver<DeviceJob>) {
        let (tx, rx) = mpsc::channel(8);
        (vec![MASTER.to_string()], Seen::new(64), tx, rx)
    }

    #[tokio::test]
    async fn valid_request_for_our_master_queues_exactly_one_job() {
        let (masters, seen, tx, mut rx) = harness();
        let msg = event_msg(NIP46_KIND, MASTER, "a".repeat(64));
        handle_relay_message(&msg, "ws://t", &masters, &seen, &tx).await;

        let Ok(DeviceJob::Request(request)) = rx.try_recv() else {
            panic!("a request job should be queued")
        };
        assert_eq!(request.master_pubkey_hex, MASTER);
        assert_eq!(request.client_pubkey_hex, CLIENT);
        assert_eq!(request.content, "AgCipherTextBase64==");
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
    async fn closed_for_our_subscription_is_reported_with_its_reason() {
        let (masters, seen, tx, mut rx) = harness();
        let msg = format!(r#"["CLOSED","{SUBSCRIPTION_ID}","rate-limited"]"#);
        let flow = handle_relay_message(&msg, "ws://t", &masters, &seen, &tx).await;
        assert_eq!(flow, Flow::SubscriptionClosed("rate-limited".into()));
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

    // --- NIP-42: a fake gated relay and a fake device signer --------------

    use std::collections::HashSet;
    use tokio::net::TcpListener;

    const CHALLENGE: &str = "challenge-7f3a";
    const REQUIRED: &str = "auth-required: sign in first";

    #[derive(Clone, Copy)]
    struct Gate {
        /// Send `["AUTH", challenge]` as soon as the client connects; else only
        /// after the first refused REQ.
        challenge_on_connect: bool,
        /// Refuse REQs whose `#p` names a key that has not signed in.
        gated: bool,
        /// Answer valid AUTH events with `OK true`.
        accept_auth: bool,
        /// The CLOSED message for a refused REQ.
        refusal: &'static str,
    }

    /// One-connection relay modelled on a NIP-42 gate: a connection may sign
    /// in as several keys, and a REQ is served only when every `#p` key has
    /// signed in. Every client message is reported on `log`.
    async fn gated_relay(listener: TcpListener, gate: Gate, log: mpsc::UnboundedSender<Value>) {
        let (stream, _) = listener.accept().await.unwrap();
        let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let (mut write, mut read) = ws.split();
        let auth_msg = json!(["AUTH", CHALLENGE]).to_string();
        let mut challenge_sent = gate.challenge_on_connect;
        if challenge_sent {
            write.send(Message::Text(auth_msg.clone().into())).await.unwrap();
        }
        let mut signed_in: HashSet<String> = HashSet::new();
        while let Some(Ok(msg)) = read.next().await {
            let Message::Text(text) = msg else { continue };
            let v: Value = serde_json::from_str(&text).unwrap();
            let _ = log.send(v.clone());
            match v[0].as_str() {
                Some("REQ") => {
                    let sub = v[1].as_str().unwrap().to_string();
                    let ps: Vec<&str> =
                        v[2]["#p"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
                    if !gate.gated || ps.iter().all(|p| signed_in.contains(*p)) {
                        write
                            .send(Message::Text(json!(["EOSE", sub]).to_string().into()))
                            .await
                            .unwrap();
                        let event = event_msg(NIP46_KIND, MASTER, "e".repeat(64));
                        write.send(Message::Text(event.into())).await.unwrap();
                    } else {
                        let closed = json!(["CLOSED", sub, gate.refusal]);
                        write.send(Message::Text(closed.to_string().into())).await.unwrap();
                        if !challenge_sent {
                            write.send(Message::Text(auth_msg.clone().into())).await.unwrap();
                            challenge_sent = true;
                        }
                    }
                }
                Some("AUTH") => {
                    let ev = &v[1];
                    let challenge_ok = ev["tags"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|t| t[0] == "challenge" && t[1] == CHALLENGE);
                    let ok = gate.accept_auth && challenge_ok;
                    if ok {
                        signed_in.insert(ev["pubkey"].as_str().unwrap().to_string());
                    }
                    let reply = json!(["OK", ev["id"], ok, if ok { "" } else { "restricted: no" }]);
                    write.send(Message::Text(reply.to_string().into())).await.unwrap();
                }
                _ => {}
            }
        }
    }

    /// What the fake device was asked to do.
    #[derive(Debug, PartialEq)]
    enum Saw {
        Auth { master: String, relay_url: String, challenge: String },
        Request(String),
    }

    /// Fake device worker: signs AUTH jobs with a canned (unsigned-but-shaped)
    /// 22242 when `willing`, else declines, and reports every job on `saw`.
    fn fake_signer(
        mut jobs: mpsc::Receiver<DeviceJob>,
        willing: bool,
    ) -> mpsc::UnboundedReceiver<Saw> {
        let (saw_tx, saw_rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(job) = jobs.recv().await {
                match job {
                    DeviceJob::Request(r) => {
                        let _ = saw_tx.send(Saw::Request(r.id));
                    }
                    DeviceJob::RelayAuth(a) => {
                        let signed = willing.then(|| {
                            json!({
                                "id": a.master_pubkey_hex, // unique per master, 64 hex
                                "pubkey": a.master_pubkey_hex,
                                "created_at": 1_700_000_000u64,
                                "kind": 22242,
                                "tags": [["relay", a.relay_url], ["challenge", a.challenge]],
                                "content": "",
                                "sig": "ab".repeat(64),
                            })
                            .to_string()
                        });
                        let _ = a.reply.send(signed);
                        let _ = saw_tx.send(Saw::Auth {
                            master: a.master_pubkey_hex,
                            relay_url: a.relay_url,
                            challenge: a.challenge,
                        });
                    }
                }
            }
        });
        saw_rx
    }

    /// Start a gated relay and a bridge connection to it with two masters.
    async fn start(
        gate: Gate,
        willing: bool,
    ) -> (
        String,
        mpsc::UnboundedReceiver<Value>,
        mpsc::UnboundedReceiver<Saw>,
        tokio::task::JoinHandle<Result<()>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let (log_tx, log_rx) = mpsc::unbounded_channel();
        tokio::spawn(gated_relay(listener, gate, log_tx));
        let (job_tx, job_rx) = mpsc::channel(8);
        let saw = fake_signer(job_rx, willing);
        let (resp_tx, _) = broadcast::channel(8);
        let masters = vec![MASTER.to_string(), OTHER_MASTER.to_string()];
        let task_url = url.clone();
        let conn = tokio::spawn(async move {
            connect_and_serve(&task_url, &masters, &Seen::new(64), &job_tx, &resp_tx).await
        });
        (url, log_rx, saw, conn)
    }

    async fn next<T>(rx: &mut mpsc::UnboundedReceiver<T>) -> T {
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timed out")
            .expect("channel closed")
    }

    /// Drive a gate that demands AUTH through to a served subscription and
    /// check every message the bridge sent on the way.
    async fn assert_signs_in_and_resubscribes(gate: Gate) {
        let (url, mut log, mut saw, conn) = start(gate, true).await;

        let first = next(&mut log).await;
        assert_eq!(first[0], "REQ", "subscribes first, unchanged");

        let mut authed = Vec::new();
        for _ in 0..2 {
            let msg = next(&mut log).await;
            assert_eq!(msg[0], "AUTH", "one AUTH per master before the REQ: {msg}");
            let ev = &msg[1];
            assert_eq!(ev["kind"], 22242);
            assert_eq!(ev["content"], "");
            assert_eq!(ev["tags"], json!([["relay", url], ["challenge", CHALLENGE]]));
            authed.push(ev["pubkey"].as_str().unwrap().to_string());
        }
        assert_eq!(authed, vec![MASTER.to_string(), OTHER_MASTER.to_string()]);

        let again = next(&mut log).await;
        assert_eq!(again[0], "REQ", "re-subscribes after every OK: {again}");
        assert_eq!(again, first, "the very same REQ (same filter and since)");

        // The device was asked for exactly those two signatures, for the
        // configured URL, then the served subscription delivered a request.
        for master in [MASTER, OTHER_MASTER] {
            assert_eq!(
                next(&mut saw).await,
                Saw::Auth {
                    master: master.into(),
                    relay_url: url.clone(),
                    challenge: CHALLENGE.into()
                }
            );
        }
        assert_eq!(next(&mut saw).await, Saw::Request("e".repeat(64)));
        assert!(!conn.is_finished(), "the connection stays up");
        conn.abort();
    }

    #[tokio::test]
    async fn signs_in_as_every_master_when_the_relay_requires_auth() {
        let gate =
            Gate { challenge_on_connect: true, gated: true, accept_auth: true, refusal: REQUIRED };
        assert_signs_in_and_resubscribes(gate).await;
    }

    #[tokio::test]
    async fn signs_in_when_auth_required_arrives_before_the_challenge() {
        let gate =
            Gate { challenge_on_connect: false, gated: true, accept_auth: true, refusal: REQUIRED };
        assert_signs_in_and_resubscribes(gate).await;
    }

    #[tokio::test]
    async fn a_restricted_refusal_after_a_challenge_also_prompts_sign_in() {
        let gate = Gate {
            challenge_on_connect: true,
            gated: true,
            accept_auth: true,
            refusal: "restricted: not allowlisted",
        };
        assert_signs_in_and_resubscribes(gate).await;
    }

    #[tokio::test]
    async fn a_restricted_refusal_without_a_challenge_is_a_plain_close() {
        let gate = Gate {
            challenge_on_connect: false,
            gated: true,
            accept_auth: true,
            refusal: "restricted: not allowlisted",
        };
        let (_url, _log, _saw, conn) = start(gate, true).await;
        let result = tokio::time::timeout(Duration::from_secs(5), conn).await.unwrap().unwrap();
        let err = result.expect_err("closed subscription");
        assert!(err.downcast_ref::<AuthFailure>().is_none(), "normal back-off: {err:#}");
    }

    #[tokio::test]
    async fn a_challenge_from_a_relay_that_does_not_require_auth_is_never_signed() {
        // Offered AUTH, not needed: nothing is signed, so the relay never
        // learns which keys sit behind this connection.
        let gate =
            Gate { challenge_on_connect: true, gated: false, accept_auth: true, refusal: REQUIRED };
        let (_url, mut log, mut saw, conn) = start(gate, true).await;
        assert_eq!(next(&mut log).await[0], "REQ");
        assert_eq!(next(&mut saw).await, Saw::Request("e".repeat(64)));
        assert!(log.try_recv().is_err(), "no AUTH sent");
        conn.abort();
    }

    async fn finished_with_auth_failure(conn: tokio::task::JoinHandle<Result<()>>) -> String {
        let result = tokio::time::timeout(Duration::from_secs(5), conn)
            .await
            .expect("connection should end, not hang")
            .expect("task should not panic");
        let err = result.expect_err("an AUTH failure is an error");
        assert!(err.downcast_ref::<AuthFailure>().is_some(), "long back-off class: {err:#}");
        format!("{err:#}")
    }

    #[tokio::test]
    async fn a_device_that_cannot_sign_ends_the_connection_without_sending_auth() {
        let gate =
            Gate { challenge_on_connect: true, gated: true, accept_auth: true, refusal: REQUIRED };
        let (_url, mut log, _saw, conn) = start(gate, false).await;
        let err = finished_with_auth_failure(conn).await;
        assert!(err.contains("would not sign"), "{err}");
        assert_eq!(next(&mut log).await[0], "REQ");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(log.try_recv().is_err(), "nothing after the REQ: no AUTH, no re-REQ");
    }

    #[tokio::test]
    async fn a_refused_auth_ends_the_connection_without_resubscribing() {
        let gate =
            Gate { challenge_on_connect: true, gated: true, accept_auth: false, refusal: REQUIRED };
        let (_url, mut log, _saw, conn) = start(gate, true).await;
        let err = finished_with_auth_failure(conn).await;
        assert!(err.contains("refused AUTH"), "{err}");
        let mut sent = Vec::new();
        while let Ok(Some(v)) = tokio::time::timeout(Duration::from_millis(200), log.recv()).await {
            sent.push(v[0].as_str().unwrap().to_string());
        }
        assert_eq!(sent.iter().filter(|s| *s == "REQ").count(), 1, "no re-REQ: {sent:?}");
        assert!(sent.contains(&"AUTH".to_string()), "{sent:?}");
    }

    #[tokio::test]
    async fn auth_and_ok_messages_are_parsed() {
        let (masters, seen, tx, _rx) = harness();
        let flow = handle_relay_message(r#"["AUTH","abc"]"#, "ws://t", &masters, &seen, &tx).await;
        assert_eq!(flow, Flow::AuthChallenge("abc".into()));
        let flow = handle_relay_message(
            r#"["OK","id1",false,"restricted: x"]"#,
            "ws://t",
            &masters,
            &seen,
            &tx,
        )
        .await;
        assert_eq!(
            flow,
            Flow::Ok { id: "id1".into(), accepted: false, message: "restricted: x".into() }
        );
        let flow = handle_relay_message(r#"["AUTH"]"#, "ws://t", &masters, &seen, &tx).await;
        assert_eq!(flow, Flow::Continue, "an AUTH without a challenge is ignored");
    }
}
