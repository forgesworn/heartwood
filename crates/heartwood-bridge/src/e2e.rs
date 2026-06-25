//! End-to-end test of the whole pump, without hardware.
//!
//! A NIP-46 request injected at a real (local) websocket relay flows through
//! the **real** relay client, over a **real** socket-pair "serial" link to a
//! simulated device, and the device's signed response is published back to the
//! relay. This exercises the actual frame codec, `SerialSession`, relay
//! subscribe/parse/publish, channel wiring and de-duplication together —
//! everything except a physical ESP32 and a public relay.

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;

use crate::dedup::Seen;
use crate::frame::{
    self, FRAME_TYPE_ENCRYPTED_REQUEST, FRAME_TYPE_NACK, FRAME_TYPE_PROVISION_LIST,
    FRAME_TYPE_PROVISION_LIST_RESPONSE, FRAME_TYPE_SESSION_ACK, FRAME_TYPE_SESSION_AUTH,
    FRAME_TYPE_SIGN_ENVELOPE_RESPONSE,
};
use crate::relay::{run_relay, RequestJob};
use crate::serial::SerialSession;

// NIP-19 vector: this npub decodes to MASTER_HEX.
const MASTER_NPUB: &str = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";
const MASTER_HEX: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
const CLIENT_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const CIPHERTEXT: &str = "AgRequestCipherTextBase64==";
const STAMP: u64 = 1_700_000_500;
const BRIDGE_SECRET: [u8; 32] = [0x42; 32];

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
    }
    out
}

/// The kind:24133 request the relay pushes to the bridge.
fn request_event() -> Value {
    json!({
        "id": "ab".repeat(32),
        "pubkey": CLIENT_HEX,
        "created_at": 1_700_000_400u64,
        "kind": 24133,
        "tags": [["p", MASTER_HEX]],
        "content": CIPHERTEXT,
        "sig": "ee".repeat(64),
    })
}

/// The signed kind:24133 response the simulated device returns (the signature
/// is opaque to the bridge, which republishes the event verbatim).
fn canned_signed_event() -> Value {
    json!({
        "id": "cc".repeat(32),
        "pubkey": MASTER_HEX,
        "created_at": STAMP,
        "kind": 24133,
        "tags": [["p", CLIENT_HEX]],
        "content": "AgResponseCipherTextBase64==",
        "sig": "dd".repeat(64),
    })
}

/// Simulated device: speaks the real frame protocol over the socket pair.
/// Answers SESSION_AUTH and PROVISION_LIST, then verifies one ENCRYPTED_REQUEST
/// and returns the signed envelope.
fn run_device_sim(mut io: UnixStream) {
    loop {
        let (ty, payload) = match frame::read_frame(&mut io, Duration::from_secs(15)) {
            Ok(frame) => frame,
            Err(_) => return, // host closed or timed out: we're done
        };
        match ty {
            FRAME_TYPE_SESSION_AUTH => {
                let status = if payload == BRIDGE_SECRET { 0x00 } else { 0x01 };
                let _ = io.write_all(&frame::build_frame(FRAME_TYPE_SESSION_ACK, &[status]));
            }
            FRAME_TYPE_PROVISION_LIST => {
                let infos = json!([{ "slot": 0, "label": "test", "mode": 1, "npub": MASTER_NPUB }]);
                let _ = io.write_all(&frame::build_frame(
                    FRAME_TYPE_PROVISION_LIST_RESPONSE,
                    infos.to_string().as_bytes(),
                ));
            }
            FRAME_TYPE_ENCRYPTED_REQUEST => {
                // Verify the 0x10 payload the bridge built for us.
                assert!(payload.len() >= 72, "0x10 payload too short");
                assert_eq!(&payload[0..32], &hex32(MASTER_HEX), "master pubkey");
                assert_eq!(&payload[32..64], &hex32(CLIENT_HEX), "client pubkey");
                assert_eq!(
                    u64::from_be_bytes(payload[64..72].try_into().unwrap()),
                    STAMP,
                    "created_at supplied by the host"
                );
                assert_eq!(&payload[72..], CIPHERTEXT.as_bytes(), "ciphertext verbatim");
                let event = canned_signed_event().to_string();
                let _ = io.write_all(&frame::build_frame(
                    FRAME_TYPE_SIGN_ENVELOPE_RESPONSE,
                    event.as_bytes(),
                ));
                return; // one request handled
            }
            _ => {
                let _ = io.write_all(&frame::build_frame(FRAME_TYPE_NACK, &[]));
            }
        }
    }
}

/// Minimal one-shot relay: accept a connection, expect the REQ, inject the
/// request event, then report the event the bridge publishes back.
async fn run_mock_relay(listener: TcpListener, published_tx: oneshot::Sender<Value>) {
    let (stream, _) = listener.accept().await.expect("accept");
    let ws = tokio_tungstenite::accept_async(stream).await.expect("ws handshake");
    let (mut write, mut read) = ws.split();

    // Wait for the subscription, then push the request.
    while let Some(Ok(msg)) = read.next().await {
        if let Message::Text(text) = msg {
            let v: Value = serde_json::from_str(&text).unwrap();
            if v[0] == "REQ" {
                assert_eq!(v[2]["kinds"][0], 24133, "subscribes for kind 24133");
                assert_eq!(v[2]["#p"][0], MASTER_HEX, "filters on our master");
                let event = json!(["EVENT", "heartwood-bridge", request_event()]);
                write.send(Message::Text(event.to_string())).await.unwrap();
                break;
            }
        }
    }

    // Report the published signed event (client publish is ["EVENT", event]).
    while let Some(Ok(msg)) = read.next().await {
        if let Message::Text(text) = msg {
            let v: Value = serde_json::from_str(&text).unwrap();
            if v[0] == "EVENT" && v.as_array().map(Vec::len) == Some(2) {
                let _ = published_tx.send(v[1].clone());
                return;
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_to_serial_to_device_e2e() {
    // 1) Socket-pair stands in for the USB serial link.
    let (host_io, device_io) = UnixStream::pair().expect("socketpair");
    host_io.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
    device_io.set_read_timeout(Some(Duration::from_millis(300))).unwrap();

    // 2) Device simulator on its own (blocking) thread.
    let device = std::thread::spawn(move || run_device_sim(device_io));

    // 3) Real session: authenticate and discover masters over the real codec.
    let mut session = SerialSession::from_io(Box::new(host_io));
    session.authenticate(&BRIDGE_SECRET).expect("authenticate");
    let masters = session.list_master_pubkeys().expect("provision-list");
    assert_eq!(masters, vec![MASTER_HEX.to_string()]);

    // 4) Real local relay on an ephemeral port.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let (published_tx, published_rx) = oneshot::channel();
    tokio::spawn(run_mock_relay(listener, published_tx));

    // 5) Wire the pump: a serial worker thread + the real relay client.
    let (job_tx, mut job_rx) = mpsc::channel::<RequestJob>(8);
    let (resp_tx, _) = broadcast::channel::<String>(8);
    let resp_for_worker = resp_tx.clone();
    let worker = std::thread::spawn(move || {
        if let Some(job) = job_rx.blocking_recv() {
            let payload = job.request.encrypted_request_payload(STAMP).unwrap();
            let signed = session.sign(&payload).expect("sign").expect("not NACKed");
            let _ = resp_for_worker.send(signed);
        }
    });
    tokio::spawn(run_relay(url, masters, Seen::new(64), job_tx, resp_tx));

    // 6) Assert the device's signed event was published back, verbatim.
    let published = tokio::time::timeout(Duration::from_secs(10), published_rx)
        .await
        .expect("timed out waiting for the published event")
        .expect("relay task dropped the sender");
    assert_eq!(published, canned_signed_event());

    let _ = device.join();
    let _ = worker.join();
}
