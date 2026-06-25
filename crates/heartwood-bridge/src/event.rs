//! NIP-46 request events and the `0x10` (ENCRYPTED_REQUEST) frame payload.
//!
//! The bridge does no cryptography. It extracts the three things the device
//! needs from a relay event — the addressed master, the client (author) and
//! the NIP-44 ciphertext — and lays them out for the firmware's inline signing
//! path. The device decrypts, handles the request, re-encrypts and signs the
//! response envelope itself.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;

/// The Nostr event kind carrying NIP-46 requests (and the signed response
/// envelope the device returns).
pub const NIP46_KIND: u64 = 24133;

/// A NIP-46 request addressed to one of our device masters, reduced to exactly
/// what the firmware needs.
#[derive(Debug, Clone)]
pub struct Nip46Request {
    /// Event id (hex) — used only for cross-relay de-duplication.
    pub id: String,
    /// The NIP-46 client (event author), x-only pubkey hex.
    pub client_pubkey_hex: String,
    /// The addressed device master (`p` tag), x-only pubkey hex.
    pub master_pubkey_hex: String,
    /// NIP-44 ciphertext (base64), forwarded to the device verbatim.
    pub content: String,
}

impl Nip46Request {
    /// Parse and validate a relay event JSON.
    ///
    /// Returns `Ok(None)` when the event is simply not a NIP-46 request for a
    /// master we hold (silently ignored), and `Err` only for input that claims
    /// to be one but is malformed.
    pub fn from_event(event: &Value, known_masters: &[String]) -> Result<Option<Self>> {
        if event.get("kind").and_then(Value::as_u64) != Some(NIP46_KIND) {
            return Ok(None);
        }

        // Must be addressed (`p` tag) to one of our masters, else not ours.
        let master_pubkey_hex = match find_master_p_tag(event, known_masters) {
            Some(m) => m,
            None => return Ok(None),
        };

        let client = event
            .get("pubkey")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("event missing pubkey"))?;
        if !is_hex32(client) {
            bail!("event pubkey is not 32-byte hex");
        }
        let content = event
            .get("content")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("event missing content"))?
            .to_string();
        let id = event.get("id").and_then(Value::as_str).unwrap_or_default().to_string();

        Ok(Some(Self { id, client_pubkey_hex: client.to_string(), master_pubkey_hex, content }))
    }

    /// Build the `0x10` ENCRYPTED_REQUEST payload:
    /// `[master_pk 32][client_pk 32][created_at u64-be 8][ciphertext bytes…]`.
    ///
    /// `created_at` becomes the device's *response* envelope timestamp (the
    /// firmware has no reliable clock), so callers pass the current unix time.
    pub fn encrypted_request_payload(&self, created_at: u64) -> Result<Vec<u8>> {
        let master = hex32(&self.master_pubkey_hex).context("master pubkey")?;
        let client = hex32(&self.client_pubkey_hex).context("client pubkey")?;
        let mut payload = Vec::with_capacity(32 + 32 + 8 + self.content.len());
        payload.extend_from_slice(&master);
        payload.extend_from_slice(&client);
        payload.extend_from_slice(&created_at.to_be_bytes());
        payload.extend_from_slice(self.content.as_bytes());
        Ok(payload)
    }
}

/// Find a `p` tag whose value is one of our masters.
fn find_master_p_tag(event: &Value, known_masters: &[String]) -> Option<String> {
    event
        .get("tags")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_array)
        .find_map(|tag| {
            let name = tag.first()?.as_str()?;
            let val = tag.get(1)?.as_str()?;
            (name == "p" && known_masters.iter().any(|m| m == val)).then(|| val.to_string())
        })
}

fn is_hex32(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn hex32(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64 {
        bail!("expected 64 hex chars, got {}", s.len());
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16).ok_or_else(|| anyhow!("bad hex digit"))?;
        let lo = (chunk[1] as char).to_digit(16).ok_or_else(|| anyhow!("bad hex digit"))?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const MASTER: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    const CLIENT: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    fn req_event() -> Value {
        json!({
            "id": "aa".repeat(32),
            "pubkey": CLIENT,
            "created_at": 1_700_000_000u64,
            "kind": 24133,
            "tags": [["p", MASTER]],
            "content": "AgIc1pha+base64ciphertext==",
            "sig": "ff".repeat(64),
        })
    }

    #[test]
    fn parses_request_for_known_master() {
        let masters = vec![MASTER.to_string()];
        let req = Nip46Request::from_event(&req_event(), &masters).unwrap().unwrap();
        assert_eq!(req.master_pubkey_hex, MASTER);
        assert_eq!(req.client_pubkey_hex, CLIENT);
        assert_eq!(req.content, "AgIc1pha+base64ciphertext==");
        assert_eq!(req.id, "aa".repeat(32));
    }

    #[test]
    fn ignores_other_kinds() {
        let mut e = req_event();
        e["kind"] = json!(1);
        let masters = vec![MASTER.to_string()];
        assert!(Nip46Request::from_event(&e, &masters).unwrap().is_none());
    }

    #[test]
    fn ignores_events_for_other_masters() {
        let masters = vec!["bb".repeat(32)];
        assert!(Nip46Request::from_event(&req_event(), &masters).unwrap().is_none());
    }

    #[test]
    fn payload_layout_is_correct() {
        let masters = vec![MASTER.to_string()];
        let req = Nip46Request::from_event(&req_event(), &masters).unwrap().unwrap();
        let created_at = 1_700_000_123u64;
        let p = req.encrypted_request_payload(created_at).unwrap();

        assert_eq!(p.len(), 32 + 32 + 8 + req.content.len());
        assert_eq!(&p[0..32], &hex32(MASTER).unwrap());
        assert_eq!(&p[32..64], &hex32(CLIENT).unwrap());
        assert_eq!(u64::from_be_bytes(p[64..72].try_into().unwrap()), created_at);
        assert_eq!(&p[72..], req.content.as_bytes());
    }
}
