//! Blocking APDU session to a Ledger device running the Heartwood app.
//!
//! The Ledger takes the place of the ESP behind the bridge: the same
//! `ENCRYPTED_REQUEST` (0x10) body goes to the device and the same signed
//! kind:24133 envelope comes back — only the wire changes, from serial frames
//! to chunked APDUs (CLA 0xE0; INS 0x10 carries the body in ≤250-byte chunks,
//! INS 0x11 collects the response). All cryptography and policy — NIP-44,
//! NIP-46 dispatch, TOFU signing approval — happen on the Ledger.
//!
//! Transport is Ledger's TCP framing (`u32`-BE length + APDU out;
//! `u32`-BE length + data + 2-byte status word back), which is what Speculos
//! serves and what the e2e proof runs against. A USB HID transport for
//! physical devices is bench-gated follow-up work — it needs hardware to
//! verify and `hidapi` in every release image.
//!
//! There is no session secret: a Ledger authenticates its *user* (PIN) and
//! gates signing on-device (TOFU approval in the app), so `authenticate` has
//! no equivalent and `bridge.secret` is not used with this transport.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::serial::ReadWrite;

const CLA: u8 = 0xE0;
const INS_GET_VERSION: u8 = 0x03;
const INS_GET_APP_NAME: u8 = 0x04;
const INS_GET_PUBKEY: u8 = 0x05;
const INS_PROCESS: u8 = 0x10;
const INS_GET_RESULT: u8 = 0x11;

const SW_OK: u16 = 0x9000;
/// The app's "request failed" status (decrypt failure, bad request, sign
/// failure) — the NACK equivalent.
const SW_PROCESS_FAIL: u16 = 0xB012;

/// Request-body chunk ceiling, mirroring the app's `CHUNK`.
const CHUNK: usize = 250;

/// Signing can block on the device's TOFU approval screen — allow a human on
/// physical buttons plenty of time.
pub const SIGN_TIMEOUT: Duration = Duration::from_secs(120);

pub struct LedgerSession {
    io: Box<dyn ReadWrite>,
}

impl LedgerSession {
    /// Connect to a Ledger APDU TCP endpoint (Speculos, or a TCP↔HID proxy).
    pub fn open_tcp(addr: &str) -> Result<Self> {
        let stream = std::net::TcpStream::connect(addr)
            .with_context(|| format!("connecting to Ledger APDU endpoint {addr}"))?;
        stream.set_read_timeout(Some(SIGN_TIMEOUT)).context("setting Ledger read timeout")?;
        Ok(Self { io: Box::new(stream) })
    }

    /// Build a session over an arbitrary byte stream (tests).
    #[cfg(test)]
    pub fn from_io(io: Box<dyn ReadWrite>) -> Self {
        Self { io }
    }

    /// One APDU exchange over the length-prefixed TCP framing.
    fn exchange(&mut self, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Result<(Vec<u8>, u16)> {
        if data.len() > 255 {
            bail!("APDU data too long ({} bytes)", data.len());
        }
        let mut apdu = Vec::with_capacity(5 + data.len());
        apdu.extend_from_slice(&[CLA, ins, p1, p2, data.len() as u8]);
        apdu.extend_from_slice(data);

        let mut msg = (apdu.len() as u32).to_be_bytes().to_vec();
        msg.extend_from_slice(&apdu);
        self.io.write_all(&msg).context("APDU write failed")?;
        self.io.flush().context("APDU flush failed")?;

        let mut len_buf = [0u8; 4];
        self.io.read_exact(&mut len_buf).context("APDU response length read failed")?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 64 * 1024 {
            bail!("implausible APDU response length {len}");
        }
        let mut payload = vec![0u8; len];
        self.io.read_exact(&mut payload).context("APDU response read failed")?;
        let mut sw = [0u8; 2];
        self.io.read_exact(&mut sw).context("APDU status read failed")?;
        Ok((payload, u16::from_be_bytes(sw)))
    }

    fn expect_ok(&mut self, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Result<Vec<u8>> {
        let (payload, sw) = self.exchange(ins, p1, p2, data)?;
        if sw != SW_OK {
            bail!("APDU ins {ins:#04x} failed with status {sw:#06x}");
        }
        Ok(payload)
    }

    /// The single master identity: the app's x-only pubkey at the heartwood
    /// derivation path, as hex. (Shaped as a list to match the serial session's
    /// multi-master contract.)
    pub fn list_master_pubkeys(&mut self) -> Result<Vec<String>> {
        let pk = self.expect_ok(INS_GET_PUBKEY, 0, 0, &[])?;
        if pk.len() != 32 {
            bail!("expected a 32-byte pubkey, got {} bytes", pk.len());
        }
        Ok(vec![hex_lower(&pk)])
    }

    /// App name + version, shaped like the firmware-info JSON.
    pub fn firmware_info(&mut self) -> Result<Value> {
        let name = self.expect_ok(INS_GET_APP_NAME, 0, 0, &[])?;
        let version = self.expect_ok(INS_GET_VERSION, 0, 0, &[])?;
        let version = match version.as_slice() {
            [major, minor, patch] => format!("{major}.{minor}.{patch}"),
            other => format!("{other:?}"),
        };
        Ok(json!({
            "board": format!("ledger:{}", String::from_utf8_lossy(&name)),
            "version": version,
        }))
    }

    /// Run a NIP-46 request through the app's inline signing path. Returns the
    /// fully-signed response event JSON (publish verbatim), or `None` if the
    /// app rejected the request (decrypt failure, bad request, sign failure).
    pub fn sign(&mut self, encrypted_request_payload: &[u8]) -> Result<Option<String>> {
        let chunks: Vec<&[u8]> = encrypted_request_payload.chunks(CHUNK).collect();
        let mut total = 0usize;
        for (i, chunk) in chunks.iter().enumerate() {
            let last = i + 1 == chunks.len();
            let p2 = if last { 0x00 } else { 0x80 };
            let (payload, sw) = self.exchange(INS_PROCESS, i as u8, p2, chunk)?;
            match sw {
                SW_OK if last => {
                    let bytes: [u8; 2] =
                        payload.as_slice().try_into().context("expected a 2-byte result length")?;
                    total = u16::from_be_bytes(bytes) as usize;
                }
                SW_OK => {}
                SW_PROCESS_FAIL => return Ok(None),
                other => bail!("PROCESS chunk {i} failed with status {other:#06x}"),
            }
        }

        let mut out = Vec::with_capacity(total);
        let mut chunk_idx = 0u8;
        while out.len() < total {
            let part = self.expect_ok(INS_GET_RESULT, chunk_idx, 0, &[])?;
            if part.is_empty() {
                bail!("GET_RESULT returned no data before the promised {total} bytes");
            }
            out.extend_from_slice(&part);
            chunk_idx = chunk_idx.checked_add(1).context("response exceeds 255 chunks")?;
        }
        String::from_utf8(out).context("response event was not UTF-8").map(Some)
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// `apdu -> (response data, status word)`.
    type ApduHandler = Box<dyn FnMut(&[u8]) -> (Vec<u8>, u16) + Send>;

    /// In-process mock Ledger: each complete length-prefixed APDU the session
    /// writes is handed to `handler`, whose `(data, sw)` reply is queued for
    /// the session to read straight back — the same no-sockets pattern as the
    /// serial mock, driving the real TCP framing in both directions.
    struct MockLedger {
        handler: ApduHandler,
        inbound: Vec<u8>,
        outbound: VecDeque<u8>,
    }

    impl MockLedger {
        fn new<H: FnMut(&[u8]) -> (Vec<u8>, u16) + Send + 'static>(handler: H) -> Self {
            Self { handler: Box::new(handler), inbound: Vec::new(), outbound: VecDeque::new() }
        }
    }

    impl std::io::Read for MockLedger {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = buf.len().min(self.outbound.len());
            if n == 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "no reply queued"));
            }
            for slot in buf.iter_mut().take(n) {
                *slot = self.outbound.pop_front().unwrap();
            }
            Ok(n)
        }
    }

    impl std::io::Write for MockLedger {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.inbound.extend_from_slice(buf);
            // A complete message is 4 length bytes + that many APDU bytes.
            while self.inbound.len() >= 4 {
                let len = u32::from_be_bytes(self.inbound[..4].try_into().unwrap()) as usize;
                if self.inbound.len() < 4 + len {
                    break;
                }
                let apdu: Vec<u8> = self.inbound.drain(..4 + len).skip(4).collect();
                let (data, sw) = (self.handler)(&apdu);
                self.outbound.extend((data.len() as u32).to_be_bytes());
                self.outbound.extend(&data);
                self.outbound.extend(sw.to_be_bytes());
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn session<H: FnMut(&[u8]) -> (Vec<u8>, u16) + Send + 'static>(h: H) -> LedgerSession {
        LedgerSession::from_io(Box::new(MockLedger::new(h)))
    }

    #[test]
    fn lists_the_single_master_pubkey() {
        let mut s = session(|apdu| {
            assert_eq!(apdu[..4], [CLA, INS_GET_PUBKEY, 0, 0]);
            (vec![0xAB; 32], SW_OK)
        });
        assert_eq!(s.list_master_pubkeys().unwrap(), vec!["ab".repeat(32)]);
    }

    #[test]
    fn firmware_info_shapes_name_and_version() {
        let mut s = session(|apdu| match apdu[1] {
            INS_GET_APP_NAME => (b"Heartwood".to_vec(), SW_OK),
            INS_GET_VERSION => (vec![0, 1, 0], SW_OK),
            other => panic!("unexpected ins {other:#04x}"),
        });
        let info = s.firmware_info().unwrap();
        assert_eq!(info["board"], "ledger:Heartwood");
        assert_eq!(info["version"], "0.1.0");
    }

    #[test]
    fn sign_chunks_request_and_collects_response() {
        let response = b"{\"kind\":24133}".repeat(40); // > one 250-byte chunk
        let resp = response.clone();
        let mut received = Vec::new();
        let mut s = session(move |apdu| {
            let (ins, p1, p2) = (apdu[1], apdu[2], apdu[3]);
            match ins {
                INS_PROCESS => {
                    assert_eq!(p1 as usize, received.len() / CHUNK, "chunk index");
                    received.extend_from_slice(&apdu[5..]);
                    if p2 == 0x00 {
                        assert_eq!(received.len(), 300, "reassembled request");
                        ((resp.len() as u16).to_be_bytes().to_vec(), SW_OK)
                    } else {
                        (vec![], SW_OK)
                    }
                }
                INS_GET_RESULT => {
                    let start = p1 as usize * CHUNK;
                    let end = (start + CHUNK).min(resp.len());
                    (resp[start..end].to_vec(), SW_OK)
                }
                other => panic!("unexpected ins {other:#04x}"),
            }
        });
        let signed = s.sign(&vec![0x77; 300]).unwrap().unwrap();
        assert_eq!(signed.as_bytes(), response.as_slice());
    }

    #[test]
    fn process_fail_maps_to_nack() {
        let mut s = session(|_| (vec![], SW_PROCESS_FAIL));
        assert!(s.sign(&[0u8; 80]).unwrap().is_none());
    }

    #[test]
    fn unexpected_status_is_an_error() {
        let mut s = session(|_| (vec![], 0x6D00));
        assert!(s.sign(&[0u8; 80]).is_err());
    }
}
