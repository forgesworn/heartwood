use nsec_tree_rs::{from_nsec_bytes, unwrap_nsec, wrap_nsec};
use zeroize::Zeroizing;

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/wrapped-nsec-v1.json")).unwrap()
}

#[test]
fn restores_independent_typescript_format_vector_as_exact_raw_key() {
    let v = fixture();
    let master = Zeroizing::new([0x11; 32]);
    let root = from_nsec_bytes(&master).unwrap();
    let imported = unwrap_nsec(&root, v["record"].as_str().unwrap(), None).unwrap();
    assert_eq!(*imported.private_key, [0x22; 32]);
    assert_eq!(hex::encode(imported.public_key), v["importedPublicHex"]);
    assert!(unwrap_nsec(&root, v["record"].as_str().unwrap(), Some(&root.master_pubkey)).is_err());
}

#[test]
fn wraps_with_fresh_entropy_and_rejects_wrong_root_and_tampering() {
    let root = from_nsec_bytes(&[0x11; 32]).unwrap();
    let wrong = from_nsec_bytes(&[0x33; 32]).unwrap();
    let raw = Zeroizing::new([0x22; 32]);
    let record = wrap_nsec(&root, &raw).unwrap();
    assert_ne!(record, wrap_nsec(&root, &raw).unwrap());
    let imported = unwrap_nsec(&root, &record, None).unwrap();
    assert_eq!(*imported.private_key, *raw);
    assert!(unwrap_nsec(&wrong, &record, None).is_err());
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let bytes = URL_SAFE_NO_PAD.decode(&record[6..]).unwrap();
    for i in 0..bytes.len() {
        let mut altered = bytes.clone();
        altered[i] ^= 1;
        let bad = format!("nstw1:{}", URL_SAFE_NO_PAD.encode(altered));
        assert!(unwrap_nsec(&root, &bad, None).is_err());
    }
    for bad in [format!("{record}="), format!("{record}\n"), "nstw1:!".into(), "".into()] {
        assert!(unwrap_nsec(&root, &bad, None).is_err());
    }
    assert!(wrap_nsec(&root, &[0; 32]).is_err());
    assert!(wrap_nsec(&root, &[255; 32]).is_err());
}
