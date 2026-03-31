use heartwood_nip46::methods::{Nip46Request, Nip46Response};
use heartwood_nip46::permissions::ClientPermissions;
use heartwood_nip46::session::{ClientSession, SessionManager};

// --- Nip46Request Debug redaction ---

#[test]
fn request_debug_redacts_params() {
    let json = r#"{"method":"sign_event","params":["secret_event_json"]}"#;
    let req: Nip46Request = serde_json::from_str(json).unwrap();
    let debug = format!("{:?}", req);
    assert!(!debug.contains("secret_event_json"));
    assert!(debug.contains("SignEvent"));
    assert!(debug.contains("1 params"));
}

#[test]
fn request_debug_no_params_variant() {
    let json = r#"{"method":"get_public_key"}"#;
    let req: Nip46Request = serde_json::from_str(json).unwrap();
    let debug = format!("{:?}", req);
    assert!(debug.contains("GetPublicKey"));
}

// --- Nip46Response nsec filtering ---

#[test]
fn response_blocks_nsec_in_result() {
    let resp = Nip46Response::ok("1", serde_json::json!({
        "nsec": "nsec1abc123"
    }));
    assert!(resp.result().is_none());
    assert!(resp.error().is_some());
    assert!(resp.error().unwrap().contains("secret key material"));
}

#[test]
fn response_blocks_nsec_in_nested_array() {
    let resp = Nip46Response::ok("1", serde_json::json!(["nsec1abc123"]));
    assert!(resp.result().is_none());
}

#[test]
fn response_allows_clean_result() {
    let resp = Nip46Response::ok("1", serde_json::json!({
        "pubkey": "d6b3a6496c529d8e7f6e10cc7bb89f794ef931770c700f68a859cd24234a2645"
    }));
    assert!(resp.result().is_some());
    assert!(resp.error().is_none());
}

#[test]
fn response_debug_redacts_result() {
    let resp = Nip46Response::ok("1", serde_json::json!("sensitive"));
    let debug = format!("{:?}", resp);
    assert!(!debug.contains("sensitive"));
    assert!(debug.contains("[redacted]"));
}

// --- Session pubkey validation ---

#[test]
fn session_rejects_invalid_pubkey() {
    assert!(ClientSession::new("not_a_hex_pubkey").is_none());
    assert!(ClientSession::new("").is_none());
    assert!(ClientSession::new("ABCD".repeat(16)).is_none()); // uppercase
    assert!(ClientSession::new("zzzz".repeat(16)).is_none()); // non-hex
}

#[test]
fn session_accepts_valid_pubkey() {
    let valid = "d6b3a6496c529d8e7f6e10cc7bb89f794ef931770c700f68a859cd24234a2645";
    assert!(ClientSession::new(valid).is_some());
}

// --- Session manager limits ---

#[test]
fn session_manager_enforces_max_sessions() {
    let mut mgr = SessionManager::new();
    for i in 0..32u8 {
        let pubkey = format!("{:064x}", i);
        let session = ClientSession::new(pubkey).unwrap();
        assert!(mgr.add(session));
    }
    // 33rd should fail
    let pubkey = format!("{:064x}", 99u8);
    let session = ClientSession::new(pubkey).unwrap();
    assert!(!mgr.add(session));
}

#[test]
fn session_manager_allows_replacement() {
    let mut mgr = SessionManager::new();
    let pubkey = "d6b3a6496c529d8e7f6e10cc7bb89f794ef931770c700f68a859cd24234a2645";
    let session = ClientSession::new(pubkey).unwrap();
    assert!(mgr.add(session));
    // Same pubkey should replace, not count as new
    let session2 = ClientSession::new(pubkey).unwrap();
    assert!(mgr.add(session2));
}

// --- Method-level permissions ---

#[test]
fn default_permissions_block_privileged_methods() {
    let perms = ClientPermissions::default();
    // Standard methods allowed
    assert!(perms.can_call_method("sign_event"));
    assert!(perms.can_call_method("get_public_key"));
    assert!(perms.can_call_method("nip44_encrypt"));
    assert!(perms.can_call_method("heartwood_list_identities"));
    assert!(perms.can_call_method("heartwood_verify_proof"));
    // Privileged methods blocked by default
    assert!(!perms.can_call_method("heartwood_derive"));
    assert!(!perms.can_call_method("heartwood_derive_persona"));
    assert!(!perms.can_call_method("heartwood_switch"));
    assert!(!perms.can_call_method("heartwood_create_proof"));
    assert!(!perms.can_call_method("heartwood_recover"));
}

#[test]
fn explicit_method_opt_in_allows_privileged() {
    let mut perms = ClientPermissions::new();
    let mut methods = std::collections::HashSet::new();
    methods.insert("heartwood_derive".to_string());
    perms.allowed_methods = Some(methods);
    assert!(perms.can_call_method("heartwood_derive"));
    assert!(!perms.can_call_method("heartwood_recover"));
}

// --- Rate limiting ---

#[test]
fn rate_limit_enforces_cap() {
    let mut perms = ClientPermissions::new();
    perms.rate_limit = 3;
    assert!(perms.check_rate_limit());
    assert!(perms.check_rate_limit());
    assert!(perms.check_rate_limit());
    assert!(!perms.check_rate_limit()); // 4th should fail
}
