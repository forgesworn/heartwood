// crates/heartwood-nip46/tests/handler_test.rs
//! Comprehensive handler tests covering all NIP-46 methods and Heartwood extensions.

use std::collections::HashSet;

use heartwood_core::root::from_nsec_bytes;
use heartwood_nip46::methods::Nip46Request;
use heartwood_nip46::server::HeartwoodServer;

/// 64-char lowercase hex public key used as the test client identity.
const CLIENT: &str = "d6b3a6496c529d8e7f6e10cc7bb89f794ef931770c700f68a859cd24234a2645";

/// Build a server pre-loaded with the 0x01-fill root (frozen protocol vector).
fn test_server() -> HeartwoodServer {
    let root = from_nsec_bytes(&[0x01u8; 32]).expect("root creation must succeed");
    HeartwoodServer::with_root(root)
}

/// Build a server pre-loaded with the root and all permissions granted to CLIENT.
fn test_server_with_perms() -> HeartwoodServer {
    let mut server = test_server();
    server.grant_all_permissions(CLIENT);
    server
}

/// Deserialise a raw JSON string into a `Nip46Request`.
fn req(json: &str) -> Nip46Request {
    serde_json::from_str(json).unwrap()
}

// ---------------------------------------------------------------------------
// 1. get_public_key — returns the known master npub for the 0x01-fill root
// ---------------------------------------------------------------------------
#[test]
fn get_public_key_returns_master_npub() {
    let mut server = test_server();
    let resp = server.handle_request("req-1", CLIENT, req(r#"{"method":"get_public_key"}"#));

    assert!(resp.error().is_none(), "unexpected error: {:?}", resp.error());
    let npub = resp.result().and_then(|v| v.as_str()).unwrap();
    // Frozen vector from full_vectors_test.rs
    assert_eq!(npub, "npub13sp7q3awvrqpa9p2svm7w8ghudghlnrraekwl7qh8w7j8747vjwskvzy2u");
}

// ---------------------------------------------------------------------------
// 2. derive blocked without permission (default session)
// ---------------------------------------------------------------------------
#[test]
fn derive_blocked_without_permission() {
    let mut server = test_server();
    let resp = server.handle_request(
        "req-2",
        CLIENT,
        req(r#"{"method":"heartwood_derive","params":["social",0]}"#),
    );

    assert!(resp.result().is_none());
    assert!(resp.error().is_some());
    let err = resp.error().unwrap();
    assert!(err.contains("not permitted"), "expected 'not permitted' in error, got: {err}");
}

// ---------------------------------------------------------------------------
// 3. derive returns the correct npub (frozen vector)
// ---------------------------------------------------------------------------
#[test]
fn derive_returns_correct_npub() {
    let mut server = test_server_with_perms();
    let resp = server.handle_request(
        "req-3",
        CLIENT,
        req(r#"{"method":"heartwood_derive","params":["social",0]}"#),
    );

    assert!(resp.error().is_none(), "unexpected error: {:?}", resp.error());
    let result = resp.result().unwrap();
    // Frozen vector: social/0 for 0x01-fill root
    assert_eq!(
        result["npub"].as_str().unwrap(),
        "npub1ehzv62sphgdc4lfjnxmxcwx3xpp6rxktdp7rxnc9yl8l4arykdeqyfhrxy"
    );
    assert_eq!(result["purpose"].as_str().unwrap(), "social");
    assert_eq!(result["index"].as_u64().unwrap(), 0);
}

// ---------------------------------------------------------------------------
// 4. derive_persona returns identity with personaName
// ---------------------------------------------------------------------------
#[test]
fn derive_persona_returns_identity_with_persona_name() {
    let mut server = test_server_with_perms();
    let resp = server.handle_request(
        "req-4",
        CLIENT,
        req(r#"{"method":"heartwood_derive_persona","params":["alice"]}"#),
    );

    assert!(resp.error().is_none(), "unexpected error: {:?}", resp.error());
    let result = resp.result().unwrap();
    assert_eq!(result["personaName"].as_str().unwrap(), "alice");
    assert!(result["npub"].as_str().unwrap().starts_with("npub1"));
    // Purpose should be the namespaced string
    assert_eq!(result["purpose"].as_str().unwrap(), "nostr:persona:alice");
    assert_eq!(result["index"].as_u64().unwrap(), 0);
}

// ---------------------------------------------------------------------------
// 5. list_identities: empty initially, grows after derive
// ---------------------------------------------------------------------------
#[test]
fn list_identities_empty_initially() {
    let mut server = test_server();
    let resp =
        server.handle_request("req-5", CLIENT, req(r#"{"method":"heartwood_list_identities"}"#));

    assert!(resp.error().is_none(), "unexpected error: {:?}", resp.error());
    let list = resp.result().unwrap().as_array().unwrap();
    assert!(list.is_empty(), "expected empty list, got {}", list.len());
}

#[test]
fn list_identities_grows_after_derive() {
    let mut server = test_server_with_perms();

    server.handle_request(
        "req-5a",
        CLIENT,
        req(r#"{"method":"heartwood_derive","params":["social",0]}"#),
    );
    server.handle_request(
        "req-5b",
        CLIENT,
        req(r#"{"method":"heartwood_derive","params":["signing",0]}"#),
    );

    let resp =
        server.handle_request("req-5c", CLIENT, req(r#"{"method":"heartwood_list_identities"}"#));

    assert!(resp.error().is_none(), "unexpected error: {:?}", resp.error());
    let list = resp.result().unwrap().as_array().unwrap();
    assert_eq!(list.len(), 2);
}

// ---------------------------------------------------------------------------
// 6. switch changes active identity
// ---------------------------------------------------------------------------
#[test]
fn switch_changes_active_identity() {
    let mut server = test_server_with_perms();

    // Derive social/0.
    let derive_resp = server.handle_request(
        "req-6a",
        CLIENT,
        req(r#"{"method":"heartwood_derive","params":["social",0]}"#),
    );
    let derived_npub = derive_resp.result().unwrap()["npub"].as_str().unwrap().to_string();

    // Switch to social identity by purpose name.
    let switch_resp = server.handle_request(
        "req-6b",
        CLIENT,
        req(r#"{"method":"heartwood_switch","params":["social",0]}"#),
    );
    assert!(switch_resp.error().is_none(), "switch error: {:?}", switch_resp.error());

    // get_public_key should now return the derived npub.
    let pk_resp = server.handle_request("req-6c", CLIENT, req(r#"{"method":"get_public_key"}"#));
    let active_npub = pk_resp.result().and_then(|v| v.as_str()).unwrap();
    assert_eq!(active_npub, derived_npub);
    assert_eq!(active_npub, "npub1ehzv62sphgdc4lfjnxmxcwx3xpp6rxktdp7rxnc9yl8l4arykdeqyfhrxy");
}

// ---------------------------------------------------------------------------
// 7. switch back to master
// ---------------------------------------------------------------------------
#[test]
fn switch_back_to_master() {
    let mut server = test_server_with_perms();

    // Derive and switch to social/0.
    server.handle_request(
        "req-7a",
        CLIENT,
        req(r#"{"method":"heartwood_derive","params":["social",0]}"#),
    );
    server.handle_request(
        "req-7b",
        CLIENT,
        req(r#"{"method":"heartwood_switch","params":["social",0]}"#),
    );

    // Switch back to master.
    let master_resp = server.handle_request(
        "req-7c",
        CLIENT,
        req(r#"{"method":"heartwood_switch","params":["master"]}"#),
    );
    assert!(master_resp.error().is_none(), "switch error: {:?}", master_resp.error());

    // get_public_key should return the master npub again.
    let pk_resp = server.handle_request("req-7d", CLIENT, req(r#"{"method":"get_public_key"}"#));
    let npub = pk_resp.result().and_then(|v| v.as_str()).unwrap();
    assert_eq!(npub, "npub13sp7q3awvrqpa9p2svm7w8ghudghlnrraekwl7qh8w7j8747vjwskvzy2u");
}

// ---------------------------------------------------------------------------
// 8. sign_event with derived identity
// ---------------------------------------------------------------------------
#[test]
fn sign_event_with_derived_identity() {
    let mut server = test_server_with_perms();

    // Derive and switch to social/0.
    server.handle_request(
        "req-8a",
        CLIENT,
        req(r#"{"method":"heartwood_derive","params":["social",0]}"#),
    );
    server.handle_request(
        "req-8b",
        CLIENT,
        req(r#"{"method":"heartwood_switch","params":["social",0]}"#),
    );

    // Build a sign_event request with a JSON-string param (NIP-46 wire format).
    let template = serde_json::json!({
        "kind": 1,
        "created_at": 1700000000u64,
        "tags": [],
        "content": "hello from heartwood"
    });
    let req_json = serde_json::json!({
        "method": "sign_event",
        "params": [template.to_string()]
    });
    let request: Nip46Request = serde_json::from_str(&req_json.to_string()).unwrap();
    let resp = server.handle_request("req-8c", CLIENT, request);

    assert!(resp.error().is_none(), "sign error: {:?}", resp.error());
    let event = resp.result().unwrap();
    assert_eq!(event["kind"].as_u64().unwrap(), 1);
    assert_eq!(event["created_at"].as_u64().unwrap(), 1700000000);
    assert_eq!(event["content"].as_str().unwrap(), "hello from heartwood");

    // id, sig, pubkey all present and correct length.
    assert_eq!(event["id"].as_str().unwrap().len(), 64);
    assert_eq!(event["sig"].as_str().unwrap().len(), 128);
    // pubkey must match the derived social/0 identity (hex, not bech32).
    // This is the x-only public key from the frozen protocol vector for social/0.
    assert_eq!(
        event["pubkey"].as_str().unwrap(),
        "cdc4cd2a01ba1b8afd3299b66c38d13043a19acb687c334f0527cffaf464b372"
    );
}

// ---------------------------------------------------------------------------
// 9. sign_event fails without active identity
// ---------------------------------------------------------------------------
#[test]
fn sign_event_fails_without_active_identity() {
    let mut server = test_server();

    let template = serde_json::json!({
        "kind": 1,
        "created_at": 1700000000u64,
        "tags": [],
        "content": "test"
    });
    let req_json = serde_json::json!({
        "method": "sign_event",
        "params": [template.to_string()]
    });
    let request: Nip46Request = serde_json::from_str(&req_json.to_string()).unwrap();
    let resp = server.handle_request("req-9", CLIENT, request);

    assert!(resp.result().is_none());
    assert!(resp.error().is_some());
    let err = resp.error().unwrap();
    assert!(
        err.contains("no active identity"),
        "expected 'no active identity' in error, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// 10. create_proof returns valid proof structure
// ---------------------------------------------------------------------------
#[test]
fn create_proof_returns_valid_proof_structure() {
    let mut server = test_server_with_perms();

    server.handle_request(
        "req-10a",
        CLIENT,
        req(r#"{"method":"heartwood_derive","params":["social",0]}"#),
    );
    server.handle_request(
        "req-10b",
        CLIENT,
        req(r#"{"method":"heartwood_switch","params":["social",0]}"#),
    );

    let resp = server.handle_request(
        "req-10c",
        CLIENT,
        req(r#"{"method":"heartwood_create_proof","params":[]}"#),
    );

    assert!(resp.error().is_none(), "proof error: {:?}", resp.error());
    let proof = resp.result().unwrap();
    assert!(proof["masterPubkey"].as_str().is_some(), "masterPubkey missing");
    assert!(proof["childPubkey"].as_str().is_some(), "childPubkey missing");
    assert!(proof["signature"].as_str().is_some(), "signature missing");
    assert!(proof["attestation"].as_str().is_some(), "attestation missing");

    // masterPubkey and childPubkey should be 64-char lowercase hex.
    let master = proof["masterPubkey"].as_str().unwrap();
    let child = proof["childPubkey"].as_str().unwrap();
    assert_eq!(master.len(), 64, "masterPubkey should be 64 hex chars");
    assert_eq!(child.len(), 64, "childPubkey should be 64 hex chars");
    // Signature should be 128-char hex.
    assert_eq!(
        proof["signature"].as_str().unwrap().len(),
        128,
        "signature should be 128 hex chars"
    );
}

// ---------------------------------------------------------------------------
// 11. verify_proof validates a proof we just created
// ---------------------------------------------------------------------------
#[test]
fn verify_proof_validates_created_proof() {
    let mut server = test_server_with_perms();

    server.handle_request(
        "req-11a",
        CLIENT,
        req(r#"{"method":"heartwood_derive","params":["social",0]}"#),
    );
    server.handle_request(
        "req-11b",
        CLIENT,
        req(r#"{"method":"heartwood_switch","params":["social",0]}"#),
    );

    let create_resp = server.handle_request(
        "req-11c",
        CLIENT,
        req(r#"{"method":"heartwood_create_proof","params":[]}"#),
    );
    assert!(create_resp.error().is_none());
    let proof_obj = create_resp.result().unwrap().clone();

    // Verify the proof by passing the object directly.
    let verify_req_json = serde_json::json!({
        "method": "heartwood_verify_proof",
        "params": [proof_obj]
    });
    let verify_request: Nip46Request = serde_json::from_str(&verify_req_json.to_string()).unwrap();
    let verify_resp = server.handle_request("req-11d", CLIENT, verify_request);

    assert!(verify_resp.error().is_none(), "verify error: {:?}", verify_resp.error());
    assert!(verify_resp.result().and_then(|v| v.as_bool()).unwrap(), "proof should verify as true");
}

// ---------------------------------------------------------------------------
// 12. nip44/nip04 return "not yet implemented"
// ---------------------------------------------------------------------------
#[test]
fn nip44_encrypt_returns_not_implemented() {
    let mut server = test_server();
    let resp = server.handle_request(
        "req-12a",
        CLIENT,
        req(r#"{"method":"nip44_encrypt","params":["pubkey","plaintext"]}"#),
    );
    assert!(resp.result().is_none());
    let err = resp.error().unwrap();
    assert!(err.contains("not yet implemented"), "expected 'not yet implemented', got: {err}");
}

#[test]
fn nip44_decrypt_returns_not_implemented() {
    let mut server = test_server();
    let resp = server.handle_request(
        "req-12b",
        CLIENT,
        req(r#"{"method":"nip44_decrypt","params":["pubkey","ciphertext"]}"#),
    );
    assert!(resp.result().is_none());
    assert!(resp.error().unwrap().contains("not yet implemented"));
}

#[test]
fn nip04_encrypt_returns_not_implemented() {
    let mut server = test_server();
    let resp = server.handle_request(
        "req-12c",
        CLIENT,
        req(r#"{"method":"nip04_encrypt","params":["pubkey","plaintext"]}"#),
    );
    assert!(resp.result().is_none());
    assert!(resp.error().unwrap().contains("not yet implemented"));
}

#[test]
fn nip04_decrypt_returns_not_implemented() {
    let mut server = test_server();
    let resp = server.handle_request(
        "req-12d",
        CLIENT,
        req(r#"{"method":"nip04_decrypt","params":["pubkey","ciphertext"]}"#),
    );
    assert!(resp.result().is_none());
    assert!(resp.error().unwrap().contains("not yet implemented"));
}

// ---------------------------------------------------------------------------
// 13. no root returns error
// ---------------------------------------------------------------------------
#[test]
fn no_root_returns_error() {
    let mut server = HeartwoodServer::new(); // no root loaded
    let resp = server.handle_request("req-13", CLIENT, req(r#"{"method":"get_public_key"}"#));
    assert!(resp.result().is_none());
    let err = resp.error().unwrap();
    assert!(err.contains("no root key loaded"), "expected 'no root key loaded', got: {err}");
}

// ---------------------------------------------------------------------------
// 14. rate limit blocks excess requests (60 allowed, 61st fails)
// ---------------------------------------------------------------------------
#[test]
fn rate_limit_blocks_excess_requests() {
    let mut server = test_server();

    // Send 60 requests — all should succeed.
    for i in 0..60 {
        let resp = server.handle_request(
            &format!("req-14-{i}"),
            CLIENT,
            req(r#"{"method":"get_public_key"}"#),
        );
        assert!(resp.error().is_none(), "request {i} failed unexpectedly: {:?}", resp.error());
    }

    // The 61st request should be rate-limited.
    let resp = server.handle_request("req-14-60", CLIENT, req(r#"{"method":"get_public_key"}"#));
    assert!(resp.result().is_none());
    let err = resp.error().unwrap();
    assert!(err.contains("rate limit exceeded"), "expected 'rate limit exceeded', got: {err}");
}

// ---------------------------------------------------------------------------
// Bonus: switch by npub also works
// ---------------------------------------------------------------------------
#[test]
fn switch_by_exact_npub() {
    let mut server = test_server_with_perms();

    let derive_resp = server.handle_request(
        "req-bonus-a",
        CLIENT,
        req(r#"{"method":"heartwood_derive","params":["social",0]}"#),
    );
    let derived_npub = derive_resp.result().unwrap()["npub"].as_str().unwrap().to_string();

    // Switch back to master first so we can verify the switch works.
    // (There's no explicit switch needed — active is already None; we just
    // switch using the npub directly.)
    let switch_json = serde_json::json!({
        "method": "heartwood_switch",
        "params": [derived_npub]
    });
    let switch_req: Nip46Request = serde_json::from_str(&switch_json.to_string()).unwrap();
    let switch_resp = server.handle_request("req-bonus-b", CLIENT, switch_req);
    assert!(switch_resp.error().is_none(), "switch error: {:?}", switch_resp.error());

    let pk_resp =
        server.handle_request("req-bonus-c", CLIENT, req(r#"{"method":"get_public_key"}"#));
    let active = pk_resp.result().and_then(|v| v.as_str()).unwrap();
    assert_eq!(active, derived_npub);
}

// ---------------------------------------------------------------------------
// Bonus: create_proof fails without an active identity
// ---------------------------------------------------------------------------
#[test]
fn create_proof_fails_without_active_identity() {
    let mut server = test_server_with_perms();
    let resp = server.handle_request(
        "req-proof-no-active",
        CLIENT,
        req(r#"{"method":"heartwood_create_proof","params":[]}"#),
    );
    assert!(resp.result().is_none());
    assert!(resp.error().unwrap().contains("no active identity"), "got: {:?}", resp.error());
}

// ---------------------------------------------------------------------------
// Bonus: recover populates the derived cache
// ---------------------------------------------------------------------------
#[test]
fn recover_populates_cache() {
    let mut server = test_server_with_perms();

    // Recover with lookahead of 2 (2 indices × 4 purposes = 8 entries).
    let recover_req_json = serde_json::json!({
        "method": "heartwood_recover",
        "params": [2]
    });
    let recover_request: Nip46Request =
        serde_json::from_str(&recover_req_json.to_string()).unwrap();
    let resp = server.handle_request("req-recover", CLIENT, recover_request);

    assert!(resp.error().is_none(), "recover error: {:?}", resp.error());
    let result = resp.result().unwrap().as_array().unwrap();
    assert_eq!(result.len(), 8, "expected 8 entries (4 purposes × 2 indices)");

    // Cache should now have 8 entries.
    let list_resp = server.handle_request(
        "req-recover-list",
        CLIENT,
        req(r#"{"method":"heartwood_list_identities"}"#),
    );
    let list = list_resp.result().unwrap().as_array().unwrap();
    assert_eq!(list.len(), 8);
}

// ---------------------------------------------------------------------------
// Kind restriction enforcement in sign_event
// ---------------------------------------------------------------------------

#[test]
fn sign_event_blocked_for_restricted_kind() {
    let mut server = test_server_with_perms();

    // Derive and switch to an identity so sign_event has an active key.
    server.handle_request(
        "derive",
        CLIENT,
        req(r#"{"method":"heartwood_derive","params":["social", 0]}"#),
    );
    let switch = server.handle_request(
        "switch",
        CLIENT,
        req(r#"{"method":"heartwood_switch","params":["social"]}"#),
    );
    assert!(switch.error().is_none());

    // Restrict this client to kind 1 only.
    let mut allowed = HashSet::new();
    allowed.insert(1u32);
    server.restrict_signing_kinds(CLIENT, allowed);

    // Kind 1 should succeed.
    let template_k1 = serde_json::json!({
        "kind": 1,
        "created_at": 1700000000u64,
        "tags": [],
        "content": "hello"
    });
    let sign_k1 = server.handle_request(
        "sign-k1",
        CLIENT,
        Nip46Request::SignEvent(vec![serde_json::Value::String(template_k1.to_string())]),
    );
    assert!(sign_k1.error().is_none(), "kind 1 should be allowed: {:?}", sign_k1.error());

    // Kind 3 should be blocked.
    let template_k3 = serde_json::json!({
        "kind": 3,
        "created_at": 1700000000u64,
        "tags": [],
        "content": ""
    });
    let sign_k3 = server.handle_request(
        "sign-k3",
        CLIENT,
        Nip46Request::SignEvent(vec![serde_json::Value::String(template_k3.to_string())]),
    );
    assert!(sign_k3.error().is_some(), "kind 3 should be blocked");
    assert!(
        sign_k3.error().unwrap().contains("not permitted"),
        "error should mention permission: {:?}",
        sign_k3.error()
    );
}
