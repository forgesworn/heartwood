//! heartwood-bridge — relay-to-serial signing bridge.
//!
//! A sidecar daemon for HSM-mode Heartwood instances. It connects the Nostr
//! relays to a USB-tethered signing device (ESP32/ESP8266) so a device with no
//! network of its own can still answer NIP-46 requests: the bridge is its
//! relay connection, and nothing more. All cryptography — NIP-44 decryption,
//! request handling, response signing — happens on the device, inline, via the
//! firmware's `ENCRYPTED_REQUEST` (0x10) → `SIGN_ENVELOPE_RESPONSE` (0x35)
//! path. The bridge never holds key material and never sees plaintext.
//!
//! See `docs/2026-06-25-relay-serial-bridge.md`.

mod bridge;
mod config;
mod dedup;
mod event;
mod frame;
mod npub;
mod relay;
mod serial;

#[cfg(all(test, unix))]
mod e2e;

use anyhow::{Context, Result};
use tokio::sync::{broadcast, mpsc, oneshot};

/// Request event ids remembered for cross-relay de-duplication.
const SEEN_CAPACITY: usize = 4096;
/// Pending signing jobs queued for the (single, sequential) device.
const JOB_QUEUE: usize = 64;
/// Buffered signed responses awaiting publication to each relay.
const RESP_QUEUE: usize = 256;

/// Current unix time in seconds. The device has no reliable clock, so the
/// bridge stamps the `created_at` the firmware writes into response envelopes.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    tracing::info!("heartwood-bridge starting");

    let config = config::Config::load()?;
    tracing::info!(
        "data dir {}, serial {}, relays [{}]",
        config.data_dir.display(),
        config.serial_port,
        config.relays.join(", ")
    );
    let relays = config.relays.clone();

    let (job_tx, job_rx) = mpsc::channel::<relay::RequestJob>(JOB_QUEUE);
    let (resp_tx, _) = broadcast::channel::<String>(RESP_QUEUE);
    let (masters_tx, masters_rx) = oneshot::channel::<Vec<String>>();

    // The serial worker owns the port on its own (blocking) thread.
    let _worker = bridge::spawn_serial_worker(config, job_rx, resp_tx.clone(), masters_tx);

    // Wait for the device's master pubkeys before subscribing to anything —
    // but stay responsive to shutdown if the device never shows up.
    let masters = tokio::select! {
        result = masters_rx => result.context("serial worker exited before reporting device masters")?,
        _ = shutdown_signal() => {
            tracing::info!("shutdown before the device was ready; exiting");
            return Ok(());
        }
    };

    let seen = dedup::Seen::new(SEEN_CAPACITY);
    for url in relays {
        tokio::spawn(relay::run_relay(
            url,
            masters.clone(),
            seen.clone(),
            job_tx.clone(),
            resp_tx.clone(),
        ));
    }
    // Drop our spare job sender so the count reflects only the relay tasks.
    drop(job_tx);

    tracing::info!("bridge running for {} master(s); awaiting requests", masters.len());

    shutdown_signal().await;
    tracing::info!("shutdown signal received; exiting");
    Ok(())
}

/// Resolve on SIGTERM (systemd stop) or Ctrl-C.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("cannot install SIGTERM handler: {e}; using Ctrl-C only");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
