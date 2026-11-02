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

/// NIP-42 relay authentication event kind.
pub const RELAY_AUTH_KIND: u64 = 22242;
/// Upper bound on the relay URL and the challenge the bridge will hand the
/// device: each travels with a one-byte length on the wire, and a sane relay
/// challenge is a few dozen characters.
const MAX_AUTH_FIELD: usize = 255;

/// Build the `RELAY_AUTH` frame payload asking the device to sign a NIP-42
/// kind 22242 event as `master`:
/// `[master_pk 32][created_at u64-be 8][url_len u8][relay_url][challenge…]`.
///
/// The device builds the event itself (tags `relay` and `challenge` only,
/// empty content), so the host chooses nothing but these three values.
pub fn relay_auth_payload(
    master_pubkey_hex: &str,
    relay_url: &str,
    challenge: &str,
    created_at: u64,
) -> Result<Vec<u8>> {
    let master = hex32(master_pubkey_hex).context("master pubkey")?;
    check_relay_url(relay_url)?;
    check_challenge(challenge)?;
    let mut payload = Vec::with_capacity(32 + 8 + 1 + relay_url.len() + challenge.len());
    payload.extend_from_slice(&master);
    payload.extend_from_slice(&created_at.to_be_bytes());
    payload.push(relay_url.len() as u8);
    payload.extend_from_slice(relay_url.as_bytes());
    payload.extend_from_slice(challenge.as_bytes());
    Ok(payload)
}

fn check_relay_url(url: &str) -> Result<()> {
    if !(url.starts_with("wss://") || url.starts_with("ws://")) {
        bail!("relay url must be ws:// or wss://");
    }
    if url.len() > MAX_AUTH_FIELD || !url.bytes().all(|b| b.is_ascii_graphic()) {
        bail!("relay url is too long or not printable ASCII");
    }
    Ok(())
}

/// A relay challenge must be non-empty printable ASCII of bounded length.
pub fn check_challenge(challenge: &str) -> Result<()> {
    if challenge.is_empty()
        || challenge.len() > MAX_AUTH_FIELD
        || !challenge.bytes().all(|b| b.is_ascii_graphic())
    {
        bail!("relay challenge is empty, too long or not printable ASCII");
    }
    Ok(())
}

/// Sanity-check the signed 22242 the device returned before handing it to a
/// relay: right kind, right author, and exactly the relay and challenge we
/// asked for. Returns the event id (the relay's `OK` echoes it). The bridge
/// cannot verify the signature (it has no curve code); the relay does.
pub fn check_signed_relay_auth(
    event_json: &str,
    master_pubkey_hex: &str,
    relay_url: &str,
    challenge: &str,
) -> Result<String> {
    let event: Value = serde_json::from_str(event_json).context("AUTH event is not JSON")?;
    if event.get("kind").and_then(Value::as_u64) != Some(RELAY_AUTH_KIND) {
        bail!("AUTH event is not kind {RELAY_AUTH_KIND}");
    }
    if event.get("pubkey").and_then(Value::as_str) != Some(master_pubkey_hex) {
        bail!("AUTH event is not signed by the requested master");
    }
    let tag = |name: &str| -> Option<&str> {
        event
            .get("tags")?
            .as_array()?
            .iter()
            .filter_map(Value::as_array)
            .find_map(|t| (t.first()?.as_str()? == name).then(|| t.get(1)?.as_str()).flatten())
    };
    if tag("relay") != Some(relay_url) || tag("challenge") != Some(challenge) {
        bail!("AUTH event carries the wrong relay or challenge tag");
    }
    match event.get("id").and_then(Value::as_str) {
        Some(id) if is_hex32(id) => Ok(id.to_string()),
        _ => bail!("AUTH event has no valid id"),
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

    #[test]
    fn relay_auth_payload_layout_is_correct() {
        let url = "wss://relay.example.com";
        let p = relay_auth_payload(MASTER, url, "chal-123", 1_700_000_321).unwrap();
        assert_eq!(&p[0..32], &hex32(MASTER).unwrap());
        assert_eq!(u64::from_be_bytes(p[32..40].try_into().unwrap()), 1_700_000_321);
        assert_eq!(p[40] as usize, url.len());
        assert_eq!(&p[41..41 + url.len()], url.as_bytes());
        assert_eq!(&p[41 + url.len()..], b"chal-123");
    }

    #[test]
    fn relay_auth_payload_rejects_bad_inputs() {
        let url = "wss://relay.example.com";
        assert!(relay_auth_payload(MASTER, "https://relay.example.com", "c", 1).is_err());
        assert!(relay_auth_payload(MASTER, url, "", 1).is_err());
        assert!(relay_auth_payload(MASTER, url, "has space", 1).is_err());
        assert!(relay_auth_payload(MASTER, url, &"c".repeat(256), 1).is_err());
        let long_url = format!("wss://{}", "a".repeat(250));
        assert!(relay_auth_payload(MASTER, &long_url, "c", 1).is_err());
        assert!(relay_auth_payload("nothex", url, "c", 1).is_err());
    }

    fn auth_event(kind: u64, pubkey: &str, relay: &str, challenge: &str) -> String {
        json!({
            "id": "ab".repeat(32),
            "pubkey": pubkey,
            "created_at": 1_700_000_000u64,
            "kind": kind,
            "tags": [["relay", relay], ["challenge", challenge]],
            "content": "",
            "sig": "cd".repeat(64),
        })
        .to_string()
    }

    #[test]
    fn signed_relay_auth_check_accepts_the_requested_event() {
        let url = "wss://relay.example.com";
        let ev = auth_event(22242, MASTER, url, "c1");
        assert_eq!(check_signed_relay_auth(&ev, MASTER, url, "c1").unwrap(), "ab".repeat(32));
    }

    #[test]
    fn signed_relay_auth_check_rejects_mismatches() {
        let url = "wss://relay.example.com";
        let other = "wss://other.example.com";
        for ev in [
            auth_event(24133, MASTER, url, "c1"),
            auth_event(22242, CLIENT, url, "c1"),
            auth_event(22242, MASTER, other, "c1"),
            auth_event(22242, MASTER, url, "c2"),
            "not json".to_string(),
        ] {
            assert!(check_signed_relay_auth(&ev, MASTER, url, "c1").is_err(), "{ev}");
        }
    }
}
