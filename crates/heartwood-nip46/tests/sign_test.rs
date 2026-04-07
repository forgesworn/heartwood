use nip46_signer::sign::sign_event;
use serde_json::json;

#[test]
fn sign_event_produces_valid_nostr_event() {
    let private_key = [0x01u8; 32];
    let template = json!({
        "kind": 1,
        "created_at": 1700000000,
        "tags": [],
        "content": "hello from heartwood"
    });

    let result = sign_event(&private_key, &template);
    assert!(result.is_ok(), "sign_event failed: {:?}", result.err());

    let event = result.unwrap();
    assert_eq!(event["kind"], 1);
    assert_eq!(event["created_at"], 1700000000);
    assert_eq!(event["content"], "hello from heartwood");
    assert!(event["id"].as_str().unwrap().len() == 64);
    assert!(event["sig"].as_str().unwrap().len() == 128);
    assert!(event["pubkey"].as_str().unwrap().len() == 64);
}

#[test]
fn sign_event_rejects_missing_kind() {
    let private_key = [0x01u8; 32];
    let template = json!({
        "created_at": 1700000000,
        "tags": [],
        "content": "no kind"
    });
    assert!(sign_event(&private_key, &template).is_err());
}
