//! NIP-19 `npub` decoding.
//!
//! The bridge never holds key material, but it must know the device's master
//! *public* key to build the relay subscription filter (`#p`) and the
//! per-request `0x10` frame. The device reports its identities as bech32
//! `npub1…` strings over `PROVISION_LIST`; this module turns one back into the
//! 32-byte x-only public key, hex-encoded as Nostr events carry it.

use anyhow::{bail, Context, Result};

/// Decode a bech32 `npub1…` string into its 32-byte x-only public key,
/// returned as lowercase hex (64 chars).
pub fn npub_to_hex(npub: &str) -> Result<String> {
    let (hrp, data) = bech32::decode(npub).context("value is not valid bech32")?;
    if hrp.as_str() != "npub" {
        bail!("expected an 'npub' but the hrp was '{}'", hrp.as_str());
    }
    if data.len() != 32 {
        bail!("npub decodes to {} bytes, expected 32", data.len());
    }
    Ok(hex_encode(&data))
}

/// Lowercase hex encoding (no external dependency for such a small helper).
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// The NIP-46 connection string a client pastes to reach this signer:
/// `bunker://<master-pubkey-hex>?relay=<url>&relay=<url>`. Relay URLs are
/// percent-encoded (`:` and `/`) the way clients emit their own bunker URIs.
pub fn bunker_uri(master_hex: &str, relays: &[String]) -> String {
    let mut uri = format!("bunker://{master_hex}");
    for (i, relay) in relays.iter().enumerate() {
        uri.push(if i == 0 { '?' } else { '&' });
        uri.push_str("relay=");
        uri.push_str(&relay.replace(':', "%3A").replace('/', "%2F"));
    }
    uri
}

#[cfg(test)]
mod tests {
    use super::*;

    // Canonical NIP-19 test vector.
    const NPUB: &str = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";
    const HEX: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";

    #[test]
    fn decodes_nip19_vector() {
        assert_eq!(npub_to_hex(NPUB).unwrap(), HEX);
    }

    #[test]
    fn rejects_non_npub_hrp() {
        // A valid bech32 string with the wrong hrp (an nsec) must be refused.
        let nsec = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
        assert!(npub_to_hex(nsec).is_err());
    }

    #[test]
    fn rejects_garbage() {
        assert!(npub_to_hex("not-an-npub").is_err());
    }

    #[test]
    fn hex_encode_is_lowercase_and_padded() {
        assert_eq!(hex_encode(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
    }

    #[test]
    fn bunker_uri_encodes_relays() {
        let relays = vec!["wss://relay.damus.io".to_string(), "wss://nos.lol".to_string()];
        assert_eq!(
            bunker_uri(HEX, &relays),
            format!("bunker://{HEX}?relay=wss%3A%2F%2Frelay.damus.io&relay=wss%3A%2F%2Fnos.lol")
        );
    }

    #[test]
    fn bunker_uri_without_relays_is_bare() {
        assert_eq!(bunker_uri(HEX, &[]), format!("bunker://{HEX}"));
    }
}
