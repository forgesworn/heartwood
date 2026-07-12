//! Blocking APDU session to a Ledger device running the Heartwood app.
//!
//! The Ledger takes the place of the ESP behind the bridge: the same
//! `ENCRYPTED_REQUEST` (0x10) body goes to the device and the same signed
//! kind:24133 envelope comes back — only the wire changes, from serial frames
//! to chunked APDUs (CLA 0xE0; INS 0x10 carries the body in ≤250-byte chunks,
//! INS 0x11 collects the response). All cryptography and policy — NIP-44,
//! NIP-46 dispatch, TOFU signing approval — happen on the Ledger.
//!
//! Two carriers for the same APDUs:
//!
//! - **TCP framing** (`u32`-BE length + APDU out; `u32`-BE length + data +
//!   2-byte status word back) — what Speculos serves and what the e2e proof
//!   runs against.
//! - **HID reports** over Linux `hidraw` — a physical device on USB. Plain
//!   `std` file I/O against `/dev/hidrawN` (no `hidapi` dependency): 64-byte
//!   reports carrying channel 0x0101, tag 0x05 and a sequence number, with the
//!   APDU stream length-prefixed across them. Framing is unit-tested; the
//!   hardware end is bench-gated. Reads block without a timeout (plain `File`
//!   has none) — a wedged device parks the worker thread until the supervisor
//!   restarts the daemon, the documented trade-off for staying dependency-free.
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

/// One raw-APDU round trip. The two carriers differ only in how the APDU
/// bytes are framed on the wire.
trait ApduCarrier: Send {
    fn exchange_apdu(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u16)>;
}

/// Speculos's framing: `u32`-BE length + APDU; reply is `u32`-BE data length,
/// the data, then the 2-byte status word.
struct TcpCarrier {
    io: Box<dyn ReadWrite>,
}

impl ApduCarrier for TcpCarrier {
    fn exchange_apdu(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u16)> {
        let mut msg = (apdu.len() as u32).to_be_bytes().to_vec();
        msg.extend_from_slice(apdu);
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
}

/// Ledger's USB HID framing over Linux `hidraw`: 64-byte reports of
/// `channel(2) tag(1) seq(2) payload…`, the APDU stream prefixed with its
/// `u16`-BE length and split across payloads; the reply reassembles the same
/// way (its stream = `u16`-BE length + data + 2-byte status word).
///
/// hidraw quirk: Ledger uses unnumbered reports, so every `write` carries a
/// leading zero report-number byte (65 bytes out); `read` returns the bare
/// 64-byte report.
struct HidrawCarrier {
    io: Box<dyn ReadWrite>,
}

const HID_CHANNEL: u16 = 0x0101;
const HID_TAG_APDU: u8 = 0x05;
const HID_REPORT: usize = 64;
/// Payload bytes per report after the 5-byte header.
const HID_PAYLOAD: usize = HID_REPORT - 5;

impl ApduCarrier for HidrawCarrier {
    fn exchange_apdu(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u16)> {
        let mut stream = (apdu.len() as u16).to_be_bytes().to_vec();
        stream.extend_from_slice(apdu);
        for (seq, chunk) in stream.chunks(HID_PAYLOAD).enumerate() {
            let mut report = [0u8; HID_REPORT + 1]; // [0] = report number (unnumbered → 0)
            report[1..3].copy_from_slice(&HID_CHANNEL.to_be_bytes());
            report[3] = HID_TAG_APDU;
            report[4..6].copy_from_slice(&(seq as u16).to_be_bytes());
            report[6..6 + chunk.len()].copy_from_slice(chunk);
            self.io.write_all(&report).context("HID report write failed")?;
        }
        self.io.flush().context("HID flush failed")?;

        let mut stream = Vec::new();
        let mut expected_seq = 0u16;
        let total = loop {
            let mut report = [0u8; HID_REPORT];
            self.io.read_exact(&mut report).context("HID report read failed")?;
            let channel = u16::from_be_bytes([report[0], report[1]]);
            let seq = u16::from_be_bytes([report[3], report[4]]);
            if channel != HID_CHANNEL || report[2] != HID_TAG_APDU {
                bail!("unexpected HID report (channel {channel:#06x}, tag {:#04x})", report[2]);
            }
            if seq != expected_seq {
                bail!("HID report out of sequence: expected {expected_seq}, got {seq}");
            }
            expected_seq = expected_seq.wrapping_add(1);
            stream.extend_from_slice(&report[5..]);
            if stream.len() >= 2 {
                let total = u16::from_be_bytes([stream[0], stream[1]]) as usize;
                if stream.len() >= 2 + total {
                    break total;
                }
            }
        };
        if total < 2 {
            bail!("HID response shorter than a status word ({total} bytes)");
        }
        let data = stream[2..2 + total - 2].to_vec();
        let sw = u16::from_be_bytes([stream[total], stream[total + 1]]);
        Ok((data, sw))
    }
}

pub struct LedgerSession {
    carrier: Box<dyn ApduCarrier>,
}

impl LedgerSession {
    /// Connect to a Ledger APDU TCP endpoint (Speculos, or a TCP↔HID proxy).
    pub fn open_tcp(addr: &str) -> Result<Self> {
        let stream = std::net::TcpStream::connect(addr)
            .with_context(|| format!("connecting to Ledger APDU endpoint {addr}"))?;
        stream.set_read_timeout(Some(SIGN_TIMEOUT)).context("setting Ledger read timeout")?;
        Ok(Self { carrier: Box::new(TcpCarrier { io: Box::new(stream) }) })
    }

    /// Open a physical Ledger over Linux `hidraw`. `path` is a device node
    /// (`/dev/hidrawN`), or `auto` to take the first hidraw whose vendor id is
    /// Ledger's (0x2c97). If the auto-pick grabs the wrong interface on a
    /// multi-interface device, name the node explicitly.
    pub fn open_hid(path: &str) -> Result<Self> {
        let resolved = if path == "auto" { find_ledger_hidraw()? } else { path.to_string() };
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&resolved)
            .with_context(|| format!("opening {resolved} (is the udev rule installed?)"))?;
        tracing::info!("ledger hidraw device: {resolved}");
        Ok(Self { carrier: Box::new(HidrawCarrier { io: Box::new(file) }) })
    }

    /// Build a session over an arbitrary byte stream with TCP framing (tests).
    #[cfg(test)]
    pub fn from_io(io: Box<dyn ReadWrite>) -> Self {
        Self { carrier: Box::new(TcpCarrier { io }) }
    }

    /// Build a session over an arbitrary byte stream with HID framing (tests).
    #[cfg(test)]
    pub fn from_hid_io(io: Box<dyn ReadWrite>) -> Self {
        Self { carrier: Box::new(HidrawCarrier { io }) }
    }

    /// One APDU exchange.
    fn exchange(&mut self, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Result<(Vec<u8>, u16)> {
        if data.len() > 255 {
            bail!("APDU data too long ({} bytes)", data.len());
        }
        let mut apdu = Vec::with_capacity(5 + data.len());
        apdu.extend_from_slice(&[CLA, ins, p1, p2, data.len() as u8]);
        apdu.extend_from_slice(data);
        self.carrier.exchange_apdu(&apdu)
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

/// First hidraw node whose HID vendor id is Ledger's (0x2c97), by scanning
/// `/sys/class/hidraw/*/device/uevent` (`HID_ID=0003:00002C97:…`).
fn find_ledger_hidraw() -> Result<String> {
    let entries = std::fs::read_dir("/sys/class/hidraw")
        .context("no /sys/class/hidraw — the ledger-hid transport is Linux-only")?;
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect();
    names.sort();
    for name in &names {
        let uevent = std::fs::read_to_string(format!("/sys/class/hidraw/{name}/device/uevent"))
            .unwrap_or_default();
        if uevent.to_ascii_uppercase().contains(":00002C97:") {
            return Ok(format!("/dev/{name}"));
        }
    }
    bail!("no Ledger hidraw device found (vendor 0x2c97) — plug in and unlock the device")
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

    // ------------------------------------------------------------------
    // HID framing
    // ------------------------------------------------------------------

    /// Mock device end of the hidraw framing: reassembles the APDU from the
    /// 65-byte writes (report number + report), hands it to the handler, and
    /// queues the reply stream back as 64-byte reports.
    struct MockHid {
        handler: ApduHandler,
        inbound: Vec<u8>,
        stream: Vec<u8>,
        outbound: VecDeque<u8>,
    }

    impl MockHid {
        fn new<H: FnMut(&[u8]) -> (Vec<u8>, u16) + Send + 'static>(handler: H) -> Self {
            Self {
                handler: Box::new(handler),
                inbound: Vec::new(),
                stream: Vec::new(),
                outbound: VecDeque::new(),
            }
        }
    }

    impl std::io::Read for MockHid {
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

    impl std::io::Write for MockHid {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.inbound.extend_from_slice(buf);
            while self.inbound.len() > HID_REPORT {
                let report: Vec<u8> = self.inbound.drain(..HID_REPORT + 1).collect();
                assert_eq!(report[0], 0, "hidraw report number for unnumbered device");
                assert_eq!(report[1..3], HID_CHANNEL.to_be_bytes(), "channel");
                assert_eq!(report[3], HID_TAG_APDU, "tag");
                let seq = u16::from_be_bytes([report[4], report[5]]) as usize;
                assert_eq!(seq, self.stream.len().div_ceil(HID_PAYLOAD), "write seq");
                self.stream.extend_from_slice(&report[6..]);

                if self.stream.len() < 2 {
                    continue;
                }
                let total = u16::from_be_bytes([self.stream[0], self.stream[1]]) as usize;
                if self.stream.len() < 2 + total {
                    continue;
                }
                let apdu: Vec<u8> = self.stream.drain(..).skip(2).take(total).collect();
                let (data, sw) = (self.handler)(&apdu);
                let mut reply = ((data.len() + 2) as u16).to_be_bytes().to_vec();
                reply.extend_from_slice(&data);
                reply.extend_from_slice(&sw.to_be_bytes());
                for (seq, chunk) in reply.chunks(HID_PAYLOAD).enumerate() {
                    let mut report = [0u8; HID_REPORT];
                    report[..2].copy_from_slice(&HID_CHANNEL.to_be_bytes());
                    report[2] = HID_TAG_APDU;
                    report[3..5].copy_from_slice(&(seq as u16).to_be_bytes());
                    report[5..5 + chunk.len()].copy_from_slice(chunk);
                    self.outbound.extend(report);
                }
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn hid_session<H: FnMut(&[u8]) -> (Vec<u8>, u16) + Send + 'static>(h: H) -> LedgerSession {
        LedgerSession::from_hid_io(Box::new(MockHid::new(h)))
    }

    #[test]
    fn hid_single_report_round_trip() {
        let mut s = hid_session(|apdu| {
            assert_eq!(apdu[..4], [CLA, INS_GET_PUBKEY, 0, 0]);
            (vec![0xCD; 32], SW_OK)
        });
        assert_eq!(s.list_master_pubkeys().unwrap(), vec!["cd".repeat(32)]);
    }

    #[test]
    fn hid_multi_report_apdu_and_response() {
        // 200 data bytes → a 207-byte APDU stream → 4 reports out; a 300-byte
        // response → 6 reports back. Exercises chunk/reassembly both ways.
        let response = vec![0x5A; 300];
        let resp = response.clone();
        let mut s = hid_session(move |apdu| {
            assert_eq!(apdu.len(), 5 + 200, "reassembled APDU");
            assert_eq!(apdu[5..], vec![0x77; 200], "APDU data intact");
            (resp.clone(), SW_OK)
        });
        let (payload, sw) = s.exchange(INS_PROCESS, 0, 0, &[0x77; 200]).unwrap();
        assert_eq!(sw, SW_OK);
        assert_eq!(payload, response);
    }

    #[test]
    fn hid_out_of_sequence_reply_is_an_error() {
        // A device reply whose first report claims seq 1.
        struct BadSeq(VecDeque<u8>);
        impl std::io::Read for BadSeq {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = buf.len().min(self.0.len());
                for slot in buf.iter_mut().take(n) {
                    *slot = self.0.pop_front().unwrap();
                }
                Ok(n)
            }
        }
        impl std::io::Write for BadSeq {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut report = [0u8; HID_REPORT];
        report[..2].copy_from_slice(&HID_CHANNEL.to_be_bytes());
        report[2] = HID_TAG_APDU;
        report[3..5].copy_from_slice(&1u16.to_be_bytes()); // wrong: first reply seq must be 0
        let mut s = LedgerSession::from_hid_io(Box::new(BadSeq(report.into_iter().collect())));
        let err = s.exchange(INS_GET_PUBKEY, 0, 0, &[]).unwrap_err();
        assert!(err.to_string().contains("out of sequence"), "{err}");
    }
}
