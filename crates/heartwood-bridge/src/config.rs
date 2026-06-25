//! Bridge configuration, read from the shared instance data directory.
//!
//! The bridge is a sidecar to `heartwood-device` and shares its data dir
//! (`HEARTWOOD_DATA_DIR`, default `/var/lib/heartwood`, or `…/<instance>`). It
//! reads three things and holds no key material of its own:
//!
//!   - `master.payload` — the unlocked payload. In HSM mode this is the string
//!     `hsm:<serial_port>` (no secret); any other value means this instance is
//!     not an HSM instance and the bridge has nothing to do.
//!   - `config.json` — the operator's relay list (`relays`).
//!   - `bridge.secret` — the 32-byte serial bridge-session secret (64-char hex,
//!     or 32 raw bytes), the same value provisioned into the device's NVS.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;

/// Relays used when `config.json` names none (matches the Pi web binary).
pub const DEFAULT_RELAYS: &[&str] =
    &["wss://relay.damus.io", "wss://nos.lol", "wss://relay.trotters.cc"];

pub struct Config {
    pub data_dir: PathBuf,
    pub serial_port: String,
    pub relays: Vec<String>,
    pub bridge_secret: [u8; 32],
}

impl Config {
    pub fn load() -> Result<Self> {
        let data_dir = PathBuf::from(
            std::env::var("HEARTWOOD_DATA_DIR")
                .unwrap_or_else(|_| "/var/lib/heartwood".to_string()),
        );
        let serial_port = read_hsm_serial_port(&data_dir)?;
        let relays = read_relays(&data_dir);
        let bridge_secret = read_bridge_secret(&data_dir)?;
        Ok(Self { data_dir, serial_port, relays, bridge_secret })
    }
}

fn read_hsm_serial_port(data_dir: &Path) -> Result<String> {
    let path = data_dir.join("master.payload");
    let payload = std::fs::read_to_string(&path)
        .with_context(|| format!("reading {} (is the device unlocked?)", path.display()))?;
    match payload.trim().strip_prefix("hsm:") {
        Some(port) if !port.is_empty() => Ok(port.to_string()),
        Some(_) => bail!("master.payload has an empty 'hsm:' serial port"),
        None => bail!(
            "instance is not in HSM mode (master.payload is not 'hsm:<port>') — \
             the bridge only serves HSM-mode instances"
        ),
    }
}

fn read_relays(data_dir: &Path) -> Vec<String> {
    let path = data_dir.join("config.json");
    let configured = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .and_then(|v| v.get("relays").cloned())
        .and_then(|v| serde_json::from_value::<Vec<String>>(v).ok());
    match configured {
        Some(relays) if !relays.is_empty() => relays,
        _ => DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect(),
    }
}

fn read_bridge_secret(data_dir: &Path) -> Result<[u8; 32]> {
    let path = data_dir.join("bridge.secret");
    let raw = std::fs::read(&path).with_context(|| {
        format!("reading {} — provision the bridge secret over USB first", path.display())
    })?;
    parse_bridge_secret(&raw)
}

/// Accept either 64 hex chars (whitespace ignored) or exactly 32 raw bytes.
fn parse_bridge_secret(raw: &[u8]) -> Result<[u8; 32]> {
    let stripped: Vec<u8> = raw.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
    if stripped.len() == 64 && stripped.iter().all(|b| b.is_ascii_hexdigit()) {
        let mut out = [0u8; 32];
        for (i, chunk) in stripped.chunks(2).enumerate() {
            let hi = (chunk[0] as char).to_digit(16).ok_or_else(|| anyhow!("bad hex digit"))?;
            let lo = (chunk[1] as char).to_digit(16).ok_or_else(|| anyhow!("bad hex digit"))?;
            out[i] = ((hi << 4) | lo) as u8;
        }
        return Ok(out);
    }
    if raw.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(raw);
        return Ok(out);
    }
    bail!("bridge.secret must be 64 hex chars or exactly 32 raw bytes (got {} bytes)", raw.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_secret_with_trailing_newline() {
        let hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n";
        let s = parse_bridge_secret(hex.as_bytes()).unwrap();
        assert_eq!(s[0], 0x00);
        assert_eq!(s[1], 0x11);
        assert_eq!(s[31], 0xff);
    }

    #[test]
    fn parses_raw_32_byte_secret() {
        let raw = [7u8; 32];
        assert_eq!(parse_bridge_secret(&raw).unwrap(), raw);
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(parse_bridge_secret(b"too short").is_err());
        assert!(parse_bridge_secret(&[0u8; 31]).is_err());
    }
}
