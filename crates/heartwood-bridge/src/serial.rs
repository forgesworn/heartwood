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

    fn transact(
        &mut self,
        frame_type: u8,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<(u8, Vec<u8>)> {
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
        let infos: Vec<Value> =
            serde_json::from_slice(&payload).context("parsing provision-list JSON")?;
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
        let (ty, resp) =
            self.transact(FRAME_TYPE_ENCRYPTED_REQUEST, encrypted_request_payload, SIGN_TIMEOUT)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{
        build_frame, parse_complete, FRAME_OVERHEAD, FRAME_TYPE_ENCRYPTED_REQUEST,
        FRAME_TYPE_FIRMWARE_INFO_RESPONSE, FRAME_TYPE_NACK, FRAME_TYPE_PROVISION_LIST,
        FRAME_TYPE_PROVISION_LIST_RESPONSE, FRAME_TYPE_SESSION_ACK, FRAME_TYPE_SESSION_AUTH,
        FRAME_TYPE_SIGN_ENVELOPE_RESPONSE,
    };
    use serde_json::json;
    use std::collections::VecDeque;

    // NIP-19 vector: this npub decodes to MASTER_HEX (shared with the e2e test).
    const MASTER_NPUB: &str = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";
    const MASTER_HEX: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    const SECRET: [u8; 32] = [0x42; 32];

    /// A fully in-process mock device. Each complete frame the session writes is
    /// handed to `handler`, whose optional `(type, payload)` reply is queued for
    /// the session to read straight back. There are no sockets or threads:
    /// `write_all` runs the handler synchronously, so the reply is already
    /// buffered by the time the session reads it. This drives the *real* frame
    /// codec in both directions, so every `SerialSession` branch is exercised
    /// against genuinely-encoded frames.
    /// `(frame_type, payload) -> optional (reply_type, reply_payload)`.
    type FrameHandler = Box<dyn FnMut(u8, Vec<u8>) -> Option<(u8, Vec<u8>)> + Send>;

    struct MockDevice {
        handler: FrameHandler,
        inbound: Vec<u8>,       // host → device bytes, until a whole frame lands
        outbound: VecDeque<u8>, // device → host reply bytes awaiting a read
    }

    impl MockDevice {
        fn new<H>(handler: H) -> Self
        where
            H: FnMut(u8, Vec<u8>) -> Option<(u8, Vec<u8>)> + Send + 'static,
        {
            Self { handler: Box::new(handler), inbound: Vec::new(), outbound: VecDeque::new() }
        }

        /// Pull one complete frame off `inbound` (if present), run the handler,
        /// and queue its reply. Returns whether a frame was consumed.
        fn consume_one_frame(&mut self) -> bool {
            if self.inbound.len() < FRAME_OVERHEAD {
                return false;
            }
            let payload_len = u16::from_be_bytes([self.inbound[3], self.inbound[4]]) as usize;
            let total = FRAME_OVERHEAD + payload_len;
            if self.inbound.len() < total {
                return false;
            }
            let (ty, payload) =
                parse_complete(&self.inbound[..total]).expect("session emitted a malformed frame");
            self.inbound.drain(..total);
            if let Some((reply_ty, reply_payload)) = (self.handler)(ty, payload) {
                self.outbound.extend(build_frame(reply_ty, &reply_payload));
            }
            true
        }
    }

    impl std::io::Read for MockDevice {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            match self.outbound.pop_front() {
                Some(b) => {
                    buf[0] = b;
                    Ok(1)
                }
                // No reply queued: model a serial read timeout so `read_frame`
                // keeps waiting rather than treating it as EOF.
                None => Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "no reply queued")),
            }
        }
    }

    impl std::io::Write for MockDevice {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.inbound.extend_from_slice(buf);
            while self.consume_one_frame() {}
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A session wired to a scripted mock device.
    fn session_with<H>(handler: H) -> SerialSession
    where
        H: FnMut(u8, Vec<u8>) -> Option<(u8, Vec<u8>)> + Send + 'static,
    {
        SerialSession::from_io(Box::new(MockDevice::new(handler)))
    }

    /// A session whose device always replies with the same frame.
    fn always_replies(reply_ty: u8, payload: Vec<u8>) -> SerialSession {
        session_with(move |_, _| Some((reply_ty, payload.clone())))
    }

    // --- authenticate (0x21 → 0x22) --------------------------------------

    #[test]
    fn authenticate_accepts_status_zero() {
        let mut session = session_with(|ty, payload| {
            assert_eq!(ty, FRAME_TYPE_SESSION_AUTH, "sends SESSION_AUTH");
            assert_eq!(payload.as_slice(), &SECRET[..], "presents the secret verbatim");
            Some((FRAME_TYPE_SESSION_ACK, vec![0x00]))
        });
        session.authenticate(&SECRET).expect("status 0x00 is success");
    }

    #[test]
    fn authenticate_wrong_secret_is_a_named_error() {
        let mut session = always_replies(FRAME_TYPE_SESSION_ACK, vec![0x01]);
        let err = session.authenticate(&SECRET).unwrap_err().to_string();
        assert!(err.contains("wrong secret"), "{err}");
    }

    #[test]
    fn authenticate_unprovisioned_is_a_named_error() {
        let mut session = always_replies(FRAME_TYPE_SESSION_ACK, vec![0x02]);
        let err = session.authenticate(&SECRET).unwrap_err().to_string();
        assert!(err.contains("no bridge secret"), "{err}");
    }

    #[test]
    fn authenticate_unknown_status_is_rejected() {
        let mut session = always_replies(FRAME_TYPE_SESSION_ACK, vec![0x7f]);
        assert!(session.authenticate(&SECRET).is_err());
    }

    #[test]
    fn authenticate_empty_ack_payload_is_rejected() {
        // status.first() == None must not be read as success.
        let mut session = always_replies(FRAME_TYPE_SESSION_ACK, vec![]);
        assert!(session.authenticate(&SECRET).is_err());
    }

    #[test]
    fn authenticate_wrong_frame_type_is_rejected() {
        let mut session = always_replies(FRAME_TYPE_NACK, vec![]);
        let err = session.authenticate(&SECRET).unwrap_err().to_string();
        assert!(err.contains("SESSION_ACK"), "{err}");
    }

    // --- list_master_pubkeys (0x05 → 0x07) -------------------------------

    #[test]
    fn list_decodes_npub_to_hex() {
        let infos = json!([{ "slot": 0, "label": "test", "mode": 1, "npub": MASTER_NPUB }]);
        let mut session =
            always_replies(FRAME_TYPE_PROVISION_LIST_RESPONSE, infos.to_string().into_bytes());
        assert_eq!(session.list_master_pubkeys().unwrap(), vec![MASTER_HEX.to_string()]);
    }

    #[test]
    fn list_skips_undecodable_npub_but_keeps_the_good_one() {
        let infos = json!([
            { "npub": "npub1thisisnotvalidbech32" },
            { "npub": MASTER_NPUB },
        ]);
        let mut session =
            always_replies(FRAME_TYPE_PROVISION_LIST_RESPONSE, infos.to_string().into_bytes());
        assert_eq!(session.list_master_pubkeys().unwrap(), vec![MASTER_HEX.to_string()]);
    }

    #[test]
    fn list_empty_is_an_error() {
        let mut session = always_replies(FRAME_TYPE_PROVISION_LIST_RESPONSE, b"[]".to_vec());
        let err = session.list_master_pubkeys().unwrap_err().to_string();
        assert!(err.contains("no provisioned masters"), "{err}");
    }

    #[test]
    fn list_invalid_json_is_an_error() {
        let mut session = always_replies(FRAME_TYPE_PROVISION_LIST_RESPONSE, b"not json".to_vec());
        assert!(session.list_master_pubkeys().is_err());
    }

    #[test]
    fn list_wrong_frame_type_is_rejected() {
        let mut session = always_replies(FRAME_TYPE_NACK, vec![]);
        let err = session.list_master_pubkeys().unwrap_err().to_string();
        assert!(err.contains("PROVISION_LIST_RESPONSE"), "{err}");
    }

    // --- sign (0x10 → 0x35 | 0x15) ---------------------------------------

    #[test]
    fn sign_returns_event_json_on_envelope_response() {
        let event = r#"{"id":"cc","kind":24133,"sig":"dd"}"#;
        let mut session = session_with(move |ty, _| {
            assert_eq!(ty, FRAME_TYPE_ENCRYPTED_REQUEST, "sends ENCRYPTED_REQUEST");
            Some((FRAME_TYPE_SIGN_ENVELOPE_RESPONSE, event.as_bytes().to_vec()))
        });
        assert_eq!(session.sign(b"payload").unwrap().as_deref(), Some(event));
    }

    #[test]
    fn sign_returns_none_on_nack() {
        // A device NACK (unknown master / decrypt failure / policy denial) is a
        // clean "no result", not an error — the worker just logs and moves on.
        let mut session = always_replies(FRAME_TYPE_NACK, vec![]);
        assert_eq!(session.sign(b"payload").unwrap(), None);
    }

    #[test]
    fn sign_unexpected_frame_type_is_an_error() {
        let mut session = always_replies(FRAME_TYPE_SESSION_ACK, vec![0x00]);
        let err = session.sign(b"payload").unwrap_err().to_string();
        assert!(err.contains("unexpected response"), "{err}");
    }

    #[test]
    fn sign_non_utf8_response_is_an_error() {
        let mut session = always_replies(FRAME_TYPE_SIGN_ENVELOPE_RESPONSE, vec![0xff, 0xfe]);
        assert!(session.sign(b"payload").is_err());
    }

    // --- firmware_info (0x59 → 0x5A) -------------------------------------

    #[test]
    fn firmware_info_parses_json() {
        let info = json!({ "version": "0.9.7", "board": "esp8266" });
        let mut session =
            always_replies(FRAME_TYPE_FIRMWARE_INFO_RESPONSE, info.to_string().into_bytes());
        let got = session.firmware_info().unwrap();
        assert_eq!(got["version"], "0.9.7");
    }

    #[test]
    fn firmware_info_wrong_frame_type_is_rejected() {
        let mut session = always_replies(FRAME_TYPE_NACK, vec![]);
        assert!(session.firmware_info().is_err());
    }

    // --- whole-session reuse ---------------------------------------------

    #[test]
    fn one_session_handles_auth_list_then_repeated_signs() {
        // The e2e exercises a single sign. This proves the codec re-synchronises
        // across many transactions on one long-lived session, as the real
        // serial worker drives it.
        let mut session = session_with(|ty, _| match ty {
            FRAME_TYPE_SESSION_AUTH => Some((FRAME_TYPE_SESSION_ACK, vec![0x00])),
            FRAME_TYPE_PROVISION_LIST => Some((
                FRAME_TYPE_PROVISION_LIST_RESPONSE,
                json!([{ "npub": MASTER_NPUB }]).to_string().into_bytes(),
            )),
            FRAME_TYPE_ENCRYPTED_REQUEST => {
                Some((FRAME_TYPE_SIGN_ENVELOPE_RESPONSE, b"{\"ok\":true}".to_vec()))
            }
            _ => Some((FRAME_TYPE_NACK, vec![])),
        });
        session.authenticate(&SECRET).unwrap();
        assert_eq!(session.list_master_pubkeys().unwrap(), vec![MASTER_HEX.to_string()]);
        for _ in 0..3 {
            assert_eq!(session.sign(b"req").unwrap().as_deref(), Some("{\"ok\":true}"));
        }
    }
}
