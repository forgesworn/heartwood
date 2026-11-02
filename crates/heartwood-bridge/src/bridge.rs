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
use crate::relay::{DeviceJob, RelayAuthJob};
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

    /// Sign a NIP-42 relay AUTH event. The Ledger app has no such command, so
    /// it always declines.
    fn sign_relay_auth(&mut self, payload: &[u8]) -> Result<Option<String>> {
        match self {
            Session::Serial(s) => s.sign_relay_auth(payload),
            Session::Ledger(_) => {
                tracing::debug!("the Ledger transport cannot sign relay AUTH");
                Ok(None)
            }
        }
    }
}

const REOPEN_BACKOFF: Duration = Duration::from_secs(3);

/// Spawn the serial worker. It authenticates, reports the discovered master
/// pubkeys through `masters_tx` (so the relay tasks can build their filters),
/// then loops over jobs from `job_rx`, broadcasting responses on `resp_tx`.
pub fn spawn_serial_worker(
    config: Config,
    mut job_rx: mpsc::Receiver<DeviceJob>,
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
                let request = match job {
                    DeviceJob::Request(request) => request,
                    DeviceJob::RelayAuth(auth) => {
                        if let Err(e) = sign_relay_auth(&mut session, &config.relays, auth) {
                            tracing::error!("relay AUTH sign failed: {e:#}; reopening port");
                            session = connect_blocking(&config);
                        }
                        continue;
                    }
                };
                let created_at = crate::now_unix();
                let payload = match request.encrypted_request_payload(created_at) {
                    Ok(payload) => payload,
                    Err(e) => {
                        tracing::warn!("dropping malformed request payload: {e:#}");
                        continue;
                    }
                };
                let client = short(&request.client_pubkey_hex);
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

/// Handle one relay AUTH job, always answering the waiting relay task. Only
/// a transport failure is an `Err` (the caller reopens the device).
fn sign_relay_auth(
    session: &mut Session,
    configured_relays: &[String],
    job: RelayAuthJob,
) -> Result<()> {
    let RelayAuthJob { master_pubkey_hex, relay_url, challenge, reply } = job;
    // Never sign a challenge for a relay the operator did not configure: an
    // AUTH signature is a credential for that relay alone.
    if !configured_relays.iter().any(|r| r == &relay_url) {
        tracing::warn!(relay = %relay_url, "refusing relay AUTH for an unconfigured relay");
        let _ = reply.send(None);
        return Ok(());
    }
    let payload = match crate::event::relay_auth_payload(
        &master_pubkey_hex,
        &relay_url,
        &challenge,
        crate::now_unix(),
    ) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(relay = %relay_url, "not signing relay AUTH: {e:#}");
            let _ = reply.send(None);
            return Ok(());
        }
    };
    match session.sign_relay_auth(&payload) {
        Ok(signed) => {
            let _ = reply.send(signed);
            Ok(())
        }
        Err(e) => {
            let _ = reply.send(None);
            Err(e)
        }
    }
}

/// Connect once and return the device's master pubkeys (`--bunker-uri`).
pub fn query_masters(config: &Config) -> Result<Vec<String>> {
    let mut session = try_connect(config)?;
    session.list_master_pubkeys()
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
        Transport::LedgerTcp | Transport::LedgerHid => {
            // No session secret: the Ledger authenticates its user (PIN) and
            // gates signing on-device (TOFU approval in the app).
            let mut session = match config.transport {
                Transport::LedgerTcp => LedgerSession::open_tcp(&config.serial_port)?,
                _ => LedgerSession::open_hid(&config.serial_port)?,
            };
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::net::UnixStream;

    const MASTER: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";

    fn job(relay_url: &str) -> (RelayAuthJob, oneshot::Receiver<Option<String>>) {
        let (reply, rx) = oneshot::channel();
        let job = RelayAuthJob {
            master_pubkey_hex: MASTER.into(),
            relay_url: relay_url.into(),
            challenge: "c1".into(),
            reply,
        };
        (job, rx)
    }

    #[test]
    fn relay_auth_for_an_unconfigured_relay_never_reaches_the_device() {
        let (host, mut device) = UnixStream::pair().unwrap();
        device.set_nonblocking(true).unwrap();
        let mut session = Session::Serial(crate::serial::SerialSession::from_io(Box::new(host)));
        let configured = vec!["wss://relay.example.com".to_string()];

        let (j, mut rx) = job("wss://elsewhere.example.net");
        sign_relay_auth(&mut session, &configured, j).expect("a refusal is not a device error");
        assert_eq!(rx.try_recv().unwrap(), None, "declined");

        let mut buf = [0u8; 16];
        let read = device.read(&mut buf);
        assert!(
            matches!(&read, Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "no frame was written to the device: {read:?}"
        );
    }
}
