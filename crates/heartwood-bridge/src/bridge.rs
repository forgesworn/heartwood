//! The device worker.
//!
//! Owns the single device connection (serial port or Ledger APDU stream) on a
//! dedicated OS thread (the I/O is blocking), processes signing jobs strictly
//! sequentially — the device handles one request at a time — and broadcasts
//! each signed response to the relay tasks. On connection failure it reopens
//! and re-authenticates, retrying forever; the bridge is useless without the
//! device, so it simply waits.

use std::time::Duration;

use anyhow::Result;
use tokio::sync::{broadcast, mpsc, oneshot};

use crate::config::{Config, Transport};
use crate::ledger::LedgerSession;
use crate::relay::RequestJob;
use crate::serial::SerialSession;

/// The two device back-ends behind one seam: same 0x10 body in, same signed
/// envelope out.
enum Session {
    Serial(SerialSession),
    Ledger(LedgerSession),
}

impl Session {
    fn list_master_pubkeys(&mut self) -> Result<Vec<String>> {
        match self {
            Session::Serial(s) => s.list_master_pubkeys(),
            Session::Ledger(s) => s.list_master_pubkeys(),
        }
    }

    fn sign(&mut self, payload: &[u8]) -> Result<Option<String>> {
        match self {
            Session::Serial(s) => s.sign(payload),
            Session::Ledger(s) => s.sign(payload),
        }
    }
}

const REOPEN_BACKOFF: Duration = Duration::from_secs(3);

/// Spawn the serial worker. It authenticates, reports the discovered master
/// pubkeys through `masters_tx` (so the relay tasks can build their filters),
/// then loops over jobs from `job_rx`, broadcasting responses on `resp_tx`.
pub fn spawn_serial_worker(
    config: Config,
    mut job_rx: mpsc::Receiver<RequestJob>,
    resp_tx: broadcast::Sender<String>,
    masters_tx: oneshot::Sender<Vec<String>>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("serial-worker".into())
        .spawn(move || {
            let mut session = connect_blocking(&config);

            // Discover masters (retrying the whole session on failure).
            let masters = loop {
                match session.list_master_pubkeys() {
                    Ok(masters) => break masters,
                    Err(e) => {
                        tracing::error!("provision-list failed: {e:#}; reopening");
                        std::thread::sleep(REOPEN_BACKOFF);
                        session = connect_blocking(&config);
                    }
                }
            };
            tracing::info!("device masters: {}", join_short(&masters));
            if masters_tx.send(masters).is_err() {
                tracing::error!("main task gone before masters delivered; aborting worker");
                return;
            }

            // Process signing jobs sequentially.
            while let Some(job) = job_rx.blocking_recv() {
                let created_at = crate::now_unix();
                let payload = match job.request.encrypted_request_payload(created_at) {
                    Ok(payload) => payload,
                    Err(e) => {
                        tracing::warn!("dropping malformed request payload: {e:#}");
                        continue;
                    }
                };
                let client = short(&job.request.client_pubkey_hex);
                match session.sign(&payload) {
                    Ok(Some(event_json)) => {
                        tracing::info!(client = %client, "signed response ({} bytes)", event_json.len());
                        let _ = resp_tx.send(event_json);
                    }
                    Ok(None) => {
                        tracing::warn!(client = %client, "device NACKed (unknown master / decrypt / policy)");
                    }
                    Err(e) => {
                        tracing::error!("serial sign failed: {e:#}; reopening port");
                        session = connect_blocking(&config);
                    }
                }
            }

            tracing::info!("serial worker stopping (job channel closed)");
        })
        .expect("spawn serial worker thread")
}

/// Open + authenticate, retrying forever with backoff.
fn connect_blocking(config: &Config) -> Session {
    loop {
        match try_connect(config) {
            Ok(session) => return session,
            Err(e) => {
                tracing::error!(
                    "device connect failed: {e:#}; retry in {}s",
                    REOPEN_BACKOFF.as_secs()
                );
                std::thread::sleep(REOPEN_BACKOFF);
            }
        }
    }
}

fn try_connect(config: &Config) -> Result<Session> {
    match config.transport {
        Transport::Serial => {
            let mut session = SerialSession::open(&config.serial_port)?;
            match session.firmware_info() {
                Ok(info) => tracing::info!("device firmware: {info}"),
                Err(e) => tracing::debug!("firmware-info unavailable: {e:#}"),
            }
            let secret =
                config.bridge_secret.as_ref().expect("serial transport always has a secret");
            session.authenticate(secret)?;
            tracing::info!("bridge session authenticated");
            Ok(Session::Serial(session))
        }
        Transport::LedgerTcp => {
            // No session secret: the Ledger authenticates its user (PIN) and
            // gates signing on-device (TOFU approval in the app).
            let mut session = LedgerSession::open_tcp(&config.serial_port)?;
            match session.firmware_info() {
                Ok(info) => tracing::info!("device firmware: {info}"),
                Err(e) => tracing::debug!("firmware-info unavailable: {e:#}"),
            }
            Ok(Session::Ledger(session))
        }
    }
}

fn short(hex: &str) -> &str {
    &hex[..hex.len().min(12)]
}

fn join_short(masters: &[String]) -> String {
    masters.iter().map(|m| short(m)).collect::<Vec<_>>().join(", ")
}
