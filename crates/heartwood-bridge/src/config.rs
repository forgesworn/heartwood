//! Bridge configuration — self-contained, browser-free.
//!
//! The bridge is a headless daemon for the USB-only ("no WiFi") signer tier: it
//! connects the Nostr relays to a USB-tethered hardware signer and holds no key
//! material of its own. It is configured from its own data dir
//! (`HEARTWOOD_DATA_DIR`, default `/var/lib/heartwood`), with environment
//! overrides for the systemd/Docker case — no web UI involved. It reads:
//!
//!   - the **transport** — `HEARTWOOD_TRANSPORT`, else `config.json`'s
//!     `transport` field, else `serial`. `serial` talks HW frames to an
//!     ESP over USB; `ledger-tcp` talks APDUs to a Ledger running the
//!     Heartwood app (Speculos, or a TCP↔HID proxy).
//!   - the **device address** — `HEARTWOOD_SERIAL_PORT`, else `config.json`'s
//!     `serial_port` field. Required; the bridge has nothing to talk to without
//!     it. A serial device path (`/dev/ttyUSB0`) for `serial`, a `host:port`
//!     for `ledger-tcp`.
//!   - the **relays** — `HEARTWOOD_RELAYS` (comma-separated), else
//!     `config.json`'s `relays` array, else [`DEFAULT_RELAYS`].
//!   - `bridge.secret` — the 32-byte serial bridge-session secret (64-char hex
//!     or 32 raw bytes), the same value the `provision` CLI writes into the
//!     device's NVS over USB. Serial only: a Ledger authenticates its user
//!     (PIN) and gates signing on-device, so no session secret exists there.
//!
//! `config.json` (`{ "serial_port": "/dev/ttyUSB0", "relays": [...] }`) is a
//! plain file the operator or the `provision` CLI writes — there is no
//! privileged process that must own it.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;

/// Relays used when neither the env nor `config.json` names any.
pub const DEFAULT_RELAYS: &[&str] =
    &["wss://relay.damus.io", "wss://nos.lol", "wss://relay.trotters.cc"];

/// How the bridge reaches the signing device.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Transport {
    /// HW serial frames to an ESP32/ESP8266 over USB.
    Serial,
    /// APDUs to a Ledger running the Heartwood app, over Ledger's TCP framing.
    LedgerTcp,
    /// APDUs to a physical Ledger over Linux hidraw (USB HID).
    LedgerHid,
}

pub struct Config {
    pub data_dir: PathBuf,
    pub transport: Transport,
    /// Serial device path for [`Transport::Serial`]; `host:port` for
    /// [`Transport::LedgerTcp`].
    pub serial_port: String,
    pub relays: Vec<String>,
    /// The serial session secret. `None` for [`Transport::LedgerTcp`].
    pub bridge_secret: Option<[u8; 32]>,
}

impl Config {
    pub fn load() -> Result<Self> {
        let data_dir = PathBuf::from(
            std::env::var("HEARTWOOD_DATA_DIR")
                .unwrap_or_else(|_| "/var/lib/heartwood".to_string()),
        );
        let file = read_config_json(&data_dir);
        let transport = resolve_transport(&file)?;
        let serial_port = resolve_serial_port(&file)?;
        let relays = resolve_relays(&file);
        let bridge_secret = match transport {
            Transport::Serial => Some(read_bridge_secret(&data_dir)?),
            Transport::LedgerTcp | Transport::LedgerHid => None,
        };
        Ok(Self { data_dir, transport, serial_port, relays, bridge_secret })
    }
}

/// Transport: `HEARTWOOD_TRANSPORT` env wins, else `config.json.transport`,
/// else serial.
fn resolve_transport(file: &Option<Value>) -> Result<Transport> {
    let raw =
        std::env::var("HEARTWOOD_TRANSPORT").ok().filter(|s| !s.trim().is_empty()).or_else(|| {
            file.as_ref()
                .and_then(|v| v.get("transport"))
                .and_then(|v| v.as_str())
                .map(str::to_string)
        });
    match raw.as_deref().map(str::trim) {
        None | Some("serial") => Ok(Transport::Serial),
        Some("ledger-tcp") => Ok(Transport::LedgerTcp),
        Some("ledger-hid") => Ok(Transport::LedgerHid),
        Some(other) => {
            bail!("unknown transport '{other}' (expected 'serial', 'ledger-tcp' or 'ledger-hid')")
        }
    }
}

/// Parse `config.json` if present (missing/malformed → `None`, defaults apply).
fn read_config_json(data_dir: &Path) -> Option<Value> {
    std::fs::read_to_string(data_dir.join("config.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
}

/// Serial port: `HEARTWOOD_SERIAL_PORT` env wins, else `config.json.serial_port`.
fn resolve_serial_port(file: &Option<Value>) -> Result<String> {
    if let Ok(port) = std::env::var("HEARTWOOD_SERIAL_PORT") {
        let port = port.trim().to_string();
        if !port.is_empty() {
            return Ok(port);
        }
    }
    let from_file = file
        .as_ref()
        .and_then(|v| v.get("serial_port"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    from_file.context(
        "no serial port configured — set HEARTWOOD_SERIAL_PORT (e.g. /dev/ttyUSB0) \
         or add \"serial_port\" to config.json in the data dir",
    )
}

/// Relays: `HEARTWOOD_RELAYS` (comma-separated) wins, else `config.json.relays`,
/// else [`DEFAULT_RELAYS`].
fn resolve_relays(file: &Option<Value>) -> Vec<String> {
    if let Ok(raw) = std::env::var("HEARTWOOD_RELAYS") {
        let relays: Vec<String> =
            raw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        if !relays.is_empty() {
            return relays;
        }
    }
    let from_file = file
        .as_ref()
        .and_then(|v| v.get("relays").cloned())
        .and_then(|v| serde_json::from_value::<Vec<String>>(v).ok());
    match from_file {
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

    // The env overrides are read from the process environment; these tests
    // exercise the config.json + default branches with the env unset, which is
    // the deterministic part. `remove_var` guards against a stray override.
    fn clear_env() {
        std::env::remove_var("HEARTWOOD_SERIAL_PORT");
        std::env::remove_var("HEARTWOOD_RELAYS");
    }

    #[test]
    fn serial_port_from_config_json() {
        clear_env();
        let file = serde_json::json!({ "serial_port": "/dev/ttyUSB0" });
        assert_eq!(resolve_serial_port(&Some(file)).unwrap(), "/dev/ttyUSB0");
    }

    #[test]
    fn serial_port_missing_is_an_error() {
        clear_env();
        assert!(resolve_serial_port(&None).is_err());
        let empty = serde_json::json!({ "serial_port": "  " });
        assert!(resolve_serial_port(&Some(empty)).is_err());
    }

    #[test]
    fn relays_from_config_json() {
        clear_env();
        let file = serde_json::json!({ "relays": ["wss://a.example", "wss://b.example"] });
        assert_eq!(
            resolve_relays(&Some(file)),
            vec!["wss://a.example".to_string(), "wss://b.example".to_string()]
        );
    }

    #[test]
    fn relays_default_when_absent_or_empty() {
        clear_env();
        assert_eq!(resolve_relays(&None), DEFAULT_RELAYS);
        let empty = serde_json::json!({ "relays": [] });
        assert_eq!(resolve_relays(&Some(empty)), DEFAULT_RELAYS);
    }
}
