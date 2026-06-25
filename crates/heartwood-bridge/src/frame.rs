//! Binary serial frame protocol shared with the Heartwood device firmware.
//!
//! Wire format (big-endian lengths, IEEE CRC-32):
//!
//! ```text
//! [magic "HW" (2)] [type (1)] [len u16 (2)] [payload (len)] [crc32 (4)]
//! ```
//!
//! The CRC covers the **type, length and payload only — NOT the magic
//! preamble**, matching the firmware in `heartwood-esp32`
//! (`common/src/frame.rs`). (Note: `heartwood-device`'s in-file web serial
//! codec hashes *including* the magic, which is incompatible with the device;
//! this codec follows the firmware, which is authoritative.) The frame-type
//! constants below are a subset of `heartwood-esp32`'s `common/src/types.rs`.

use std::time::{Duration, Instant};

use anyhow::{bail, Result};

/// Frame preamble: ASCII "HW".
pub const FRAME_MAGIC: [u8; 2] = [0x48, 0x57];

/// Header before the payload: magic(2) + type(1) + len(2).
pub const HEADER_LEN: usize = 2 + 1 + 2;

/// Fixed overhead around a payload: header(5) + crc(4).
pub const FRAME_OVERHEAD: usize = HEADER_LEN + 4;

// --- Frame types the bridge uses (subset of the firmware's full set) ---
pub const FRAME_TYPE_NACK: u8 = 0x15;
pub const FRAME_TYPE_PROVISION_LIST: u8 = 0x05;
pub const FRAME_TYPE_PROVISION_LIST_RESPONSE: u8 = 0x07;
pub const FRAME_TYPE_ENCRYPTED_REQUEST: u8 = 0x10;
pub const FRAME_TYPE_SESSION_AUTH: u8 = 0x21;
pub const FRAME_TYPE_SESSION_ACK: u8 = 0x22;
pub const FRAME_TYPE_SIGN_ENVELOPE_RESPONSE: u8 = 0x35;
pub const FRAME_TYPE_FIRMWARE_INFO: u8 = 0x59;
pub const FRAME_TYPE_FIRMWARE_INFO_RESPONSE: u8 = 0x5A;

/// Build a framed serial message ready to write to the port.
pub fn build_frame(frame_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(FRAME_OVERHEAD + payload.len());
    frame.extend_from_slice(&FRAME_MAGIC);
    frame.push(frame_type);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    // CRC covers type + length + payload, but NOT the 2 magic bytes.
    let checksum = crc32fast::hash(&frame[FRAME_MAGIC.len()..]);
    frame.extend_from_slice(&checksum.to_be_bytes());
    frame
}

/// Validate and extract a single, complete frame that occupies exactly `buf`.
///
/// `buf` must start at the magic bytes and contain one whole frame (the caller
/// computes the length from the header). Returns `(frame_type, payload)`.
pub fn parse_complete(buf: &[u8]) -> Result<(u8, Vec<u8>)> {
    if buf.len() < FRAME_OVERHEAD {
        bail!("frame buffer too short ({} bytes)", buf.len());
    }
    if buf[0] != FRAME_MAGIC[0] || buf[1] != FRAME_MAGIC[1] {
        bail!("bad frame magic");
    }
    let frame_type = buf[2];
    let payload_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let total = FRAME_OVERHEAD + payload_len;
    if buf.len() != total {
        bail!("frame length mismatch: header says {total}, got {}", buf.len());
    }
    let expected =
        u32::from_be_bytes([buf[total - 4], buf[total - 3], buf[total - 2], buf[total - 1]]);
    // CRC covers type + length + payload, but NOT the 2 magic bytes.
    let actual = crc32fast::hash(&buf[FRAME_MAGIC.len()..total - 4]);
    if actual != expected {
        bail!("CRC mismatch (expected {expected:#010x}, got {actual:#010x})");
    }
    Ok((frame_type, buf[HEADER_LEN..total - 4].to_vec()))
}

/// Read one complete frame from the serial port, blocking up to `timeout`.
///
/// Bytes are accumulated and resynchronised on the magic preamble, so stray
/// bytes before a frame (e.g. a boot banner) are skipped rather than fatal.
pub fn read_frame<R: std::io::Read + ?Sized>(
    port: &mut R,
    timeout: Duration,
) -> Result<(u8, Vec<u8>)> {
    let deadline = Instant::now() + timeout;
    let mut buf: Vec<u8> = Vec::with_capacity(128);

    loop {
        if Instant::now() >= deadline {
            bail!("timed out waiting for a frame from the device");
        }

        let mut byte = [0u8; 1];
        match std::io::Read::read(port, &mut byte) {
            Ok(1) => buf.push(byte[0]),
            Ok(_) => continue,
            // A read timeout (serial ports) or WouldBlock (sockets with a read
            // timeout) just means "nothing yet" — keep waiting until the deadline.
            Err(ref e)
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock =>
            {
                continue
            }
            Err(e) => return Err(anyhow::Error::new(e).context("serial read error")),
        }

        // Need at least the header to know the total length.
        if buf.len() < FRAME_OVERHEAD {
            continue;
        }
        // Resynchronise on the magic preamble.
        if buf[0] != FRAME_MAGIC[0] || buf[1] != FRAME_MAGIC[1] {
            buf.remove(0);
            continue;
        }
        let payload_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        let total = FRAME_OVERHEAD + payload_len;
        if buf.len() < total {
            continue;
        }
        return parse_complete(&buf[..total]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_then_parse_round_trips() {
        let payload = b"hello device";
        let frame = build_frame(FRAME_TYPE_ENCRYPTED_REQUEST, payload);
        // magic(2)+type(1)+len(2)+payload(12)+crc(4)
        assert_eq!(frame.len(), FRAME_OVERHEAD + payload.len());
        let (ty, got) = parse_complete(&frame).unwrap();
        assert_eq!(ty, FRAME_TYPE_ENCRYPTED_REQUEST);
        assert_eq!(got, payload);
    }

    #[test]
    fn empty_payload_round_trips() {
        let frame = build_frame(FRAME_TYPE_PROVISION_LIST, &[]);
        let (ty, got) = parse_complete(&frame).unwrap();
        assert_eq!(ty, FRAME_TYPE_PROVISION_LIST);
        assert!(got.is_empty());
    }

    #[test]
    fn corrupt_payload_fails_crc() {
        let mut frame = build_frame(FRAME_TYPE_NACK, b"abc");
        let mid = 6; // somewhere in the payload
        frame[mid] ^= 0xff;
        assert!(parse_complete(&frame).is_err());
    }

    #[test]
    fn bad_magic_rejected() {
        let mut frame = build_frame(FRAME_TYPE_NACK, b"x");
        frame[0] = 0x00;
        assert!(parse_complete(&frame).is_err());
    }

    #[test]
    fn crc_excludes_magic_matching_firmware() {
        // The firmware (heartwood-esp32 common/src/frame.rs) hashes
        // type + length + payload, NOT the magic preamble. Pin that exact
        // scheme so the bridge stays wire-compatible with real hardware.
        let frame_type = FRAME_TYPE_ENCRYPTED_REQUEST;
        let payload = b"abc";
        let frame = build_frame(frame_type, payload);

        let total = frame.len();
        let emitted = u32::from_be_bytes([
            frame[total - 4],
            frame[total - 3],
            frame[total - 2],
            frame[total - 1],
        ]);

        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&[frame_type]);
        hasher.update(&(payload.len() as u16).to_be_bytes());
        hasher.update(payload);
        assert_eq!(emitted, hasher.finalize(), "CRC must exclude the magic bytes");
    }
}
