//! Blocking serial session to the device.
//!
//! Opens the port, authenticates the bridge session, discovers the master
//! identities, and runs signing requests through the firmware's inline
//! `ENCRYPTED_REQUEST` (`0x10`) → `SIGN_ENVELOPE_RESPONSE` (`0x35`) path. All
//! cryptography happens on the device; this is a transport.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::frame::{
    self, FRAME_TYPE_ENCRYPTED_REQUEST, FRAME_TYPE_FIRMWARE_INFO,
    FRAME_TYPE_FIRMWARE_INFO_RESPONSE, FRAME_TYPE_NACK, FRAME_TYPE_PROVISION_LIST,
    FRAME_TYPE_PROVISION_LIST_RESPONSE, FRAME_TYPE_SESSION_ACK, FRAME_TYPE_SESSION_AUTH,
    FRAME_TYPE_SIGN_ENVELOPE_RESPONSE,
};
use crate::npub;

const BAUD: u32 = 115_200;
/// Per-`read` byte timeout used while assembling a frame.
const READ_TIMEOUT: Duration = Duration::from_millis(500);
/// Control frames (auth, provision-list, firmware-info) answer immediately.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
/// Signing may block on a physical button press (TOFU "ask" policy), so allow
/// the device plenty of time before giving up on a response.
const SIGN_TIMEOUT: Duration = Duration::from_secs(45);

/// Anything the session can speak over: a real serial port, or — in tests — an
/// in-process socket pair. Blanket-implemented for every suitable byte stream.
pub trait ReadWrite: std::io::Read + std::io::Write + Send {}
impl<T: std::io::Read + std::io::Write + Send + ?Sized> ReadWrite for T {}

/// Adapter letting a boxed `serialport` port (which cannot be coerced directly
/// to `Box<dyn ReadWrite>`) back a session.
struct SerialPortIo(Box<dyn serialport::SerialPort>);

impl std::io::Read for SerialPortIo {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}
impl std::io::Write for SerialPortIo {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

pub struct SerialSession {
    io: Box<dyn ReadWrite>,
}

impl SerialSession {
    /// Open the serial port. Does not authenticate.
    pub fn open(port_path: &str) -> Result<Self> {
        let port = serialport::new(port_path, BAUD)
            .timeout(READ_TIMEOUT)
            .open()
            .with_context(|| format!("opening serial port {port_path}"))?;
        Ok(Self { io: Box::new(SerialPortIo(port)) })
    }

    /// Build a session over an arbitrary byte stream — tests drive it over a
    /// `UnixStream` pair instead of real hardware.
    #[cfg(test)]
    pub fn from_io(io: Box<dyn ReadWrite>) -> Self {
        Self { io }
    }

    fn transact(&mut self, frame_type: u8, payload: &[u8], timeout: Duration) -> Result<(u8, Vec<u8>)> {
        let frame = frame::build_frame(frame_type, payload);
        std::io::Write::write_all(&mut *self.io, &frame).context("serial write failed")?;
        frame::read_frame(&mut *self.io, timeout)
    }

    /// `SESSION_AUTH` (0x21): present the 32-byte shared secret and expect
    /// `SESSION_ACK` (0x22) with status `0x00`.
    pub fn authenticate(&mut self, secret: &[u8; 32]) -> Result<()> {
        let (ty, status) = self.transact(FRAME_TYPE_SESSION_AUTH, secret, CONTROL_TIMEOUT)?;
        if ty != FRAME_TYPE_SESSION_ACK {
            bail!("expected SESSION_ACK (0x22), got {ty:#04x}");
        }
        match status.first().copied() {
            Some(0x00) => Ok(()),
            Some(0x01) => bail!("device rejected the bridge secret (wrong secret)"),
            Some(0x02) => bail!("device has no bridge secret provisioned — set one over USB first"),
            other => bail!("unexpected SESSION_ACK status {other:?}"),
        }
    }

    /// `PROVISION_LIST` (0x05 → 0x07): discover provisioned masters. Returns
    /// their x-only public keys as hex (decoded from the reported npubs).
    pub fn list_master_pubkeys(&mut self) -> Result<Vec<String>> {
        let (ty, payload) = self.transact(FRAME_TYPE_PROVISION_LIST, &[], CONTROL_TIMEOUT)?;
        if ty != FRAME_TYPE_PROVISION_LIST_RESPONSE {
            bail!("expected PROVISION_LIST_RESPONSE (0x07), got {ty:#04x}");
        }
        let infos: Vec<Value> = serde_json::from_slice(&payload).context("parsing provision-list JSON")?;
        let mut pubkeys = Vec::new();
        for info in infos {
            if let Some(npub_str) = info.get("npub").and_then(Value::as_str) {
                match npub::npub_to_hex(npub_str) {
                    Ok(hex) => pubkeys.push(hex),
                    Err(e) => tracing::warn!("skipping un-decodable npub {npub_str}: {e}"),
                }
            }
        }
        if pubkeys.is_empty() {
            bail!("device reported no provisioned masters");
        }
        Ok(pubkeys)
    }

    /// `FIRMWARE_INFO` (0x59 → 0x5A): read-only version/board query.
    pub fn firmware_info(&mut self) -> Result<Value> {
        let (ty, payload) = self.transact(FRAME_TYPE_FIRMWARE_INFO, &[], CONTROL_TIMEOUT)?;
        if ty != FRAME_TYPE_FIRMWARE_INFO_RESPONSE {
            bail!("expected FIRMWARE_INFO_RESPONSE (0x5A), got {ty:#04x}");
        }
        serde_json::from_slice(&payload).context("parsing firmware-info JSON")
    }

    /// Run a NIP-46 request through the device's inline signing path. Returns
    /// the fully-signed response event JSON (publish verbatim), or `None` if
    /// the device NACKed (unknown master, decrypt failure, or policy denial).
    pub fn sign(&mut self, encrypted_request_payload: &[u8]) -> Result<Option<String>> {
        let (ty, resp) = self.transact(
            FRAME_TYPE_ENCRYPTED_REQUEST,
            encrypted_request_payload,
            SIGN_TIMEOUT,
        )?;
        match ty {
            FRAME_TYPE_SIGN_ENVELOPE_RESPONSE => {
                let json = String::from_utf8(resp).context("response event was not UTF-8")?;
                Ok(Some(json))
            }
            FRAME_TYPE_NACK => Ok(None),
            other => bail!("unexpected response to ENCRYPTED_REQUEST: {other:#04x}"),
        }
    }
}
