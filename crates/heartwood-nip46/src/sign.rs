//! Nostr event signing — compute event ID (NIP-01) and BIP-340 Schnorr sign.

use k256::schnorr::SigningKey;
use sha2::{Digest, Sha256};
use signature::Signer;
use zeroize::Zeroize;

/// Sign a Nostr event template, returning a complete signed event.
///
/// The template must contain: `kind` (number), `created_at` (number),
/// `tags` (array), `content` (string).
///
/// The returned object contains the canonical NIP-01 fields:
/// `id`, `pubkey`, `created_at`, `kind`, `tags`, `content`, `sig`.
///
/// The private key bytes are never written to any output field. All
/// intermediate copies of key material are zeroised before the function
/// returns.
pub fn sign_event(
    private_key: &[u8; 32],
    template: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let kind = template["kind"].as_u64().ok_or("missing or invalid 'kind'")?;
    let created_at = template["created_at"].as_u64().ok_or("missing or invalid 'created_at'")?;
    let tags = template.get("tags").ok_or("missing 'tags'")?;
    let content = template["content"].as_str().ok_or("missing or invalid 'content'")?;

    let signing_key =
        SigningKey::from_bytes(private_key).map_err(|e| format!("invalid private key: {e}"))?;
    let pubkey_bytes: [u8; 32] = signing_key.verifying_key().to_bytes().into();
    let pubkey_hex = hex::encode(pubkey_bytes);

    // NIP-01 event ID: SHA-256 of the serialised commitment array.
    // Format: [0, pubkey_hex, created_at, kind, tags, content]
    let commitment = serde_json::json!([0, pubkey_hex, created_at, kind, tags, content]);
    let commitment_bytes =
        serde_json::to_string(&commitment).map_err(|e| format!("serialisation failed: {e}"))?;

    let mut hasher = Sha256::new();
    hasher.update(commitment_bytes.as_bytes());
    let mut event_id: [u8; 32] = hasher.finalize().into();
    let id_hex = hex::encode(event_id);

    let sig: k256::schnorr::Signature = signing_key.sign(&event_id);
    let sig_hex = hex::encode(sig.to_bytes());

    // Zeroize the event-id buffer; it was derived from public data but
    // acts as the signing message, so treat it with the same care as
    // any intermediate secret.
    event_id.zeroize();

    Ok(serde_json::json!({
        "id": id_hex,
        "pubkey": pubkey_hex,
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": content,
        "sig": sig_hex
    }))
}
