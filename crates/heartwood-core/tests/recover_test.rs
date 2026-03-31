use heartwood_core::derive::derive;
use heartwood_core::recover::recover;
use heartwood_core::root::from_nsec_bytes;

fn root_01() -> heartwood_core::types::TreeRoot {
    let nsec_bytes = [0x01u8; 32];
    from_nsec_bytes(&nsec_bytes).expect("root creation must succeed")
}

#[test]
fn finds_derived_identities_at_expected_indices() {
    let root = root_01();

    // Derive a known identity first
    let expected = derive(&root, "social", 3).expect("derive must succeed");

    // Recover should find it
    let purposes = vec!["social".to_string()];
    let recovered = recover(&root, &purposes, Some(5)).expect("recover must succeed");

    let social_ids = recovered.get("social").expect("social must exist");
    assert_eq!(social_ids.len(), 5);
    assert_eq!(social_ids[3].npub, expected.npub);
    assert_eq!(social_ids[3].nsec, expected.nsec);
    assert_eq!(social_ids[3].index, 3);
}

#[test]
fn returns_entries_for_all_requested_purposes() {
    let root = root_01();
    let purposes = vec![
        "social".to_string(),
        "commerce".to_string(),
        "auth".to_string(),
    ];
    let recovered = recover(&root, &purposes, Some(3)).expect("recover must succeed");

    assert_eq!(recovered.len(), 3);
    assert!(recovered.contains_key("social"));
    assert!(recovered.contains_key("commerce"));
    assert!(recovered.contains_key("auth"));

    for identities in recovered.values() {
        assert_eq!(identities.len(), 3);
    }
}

#[test]
fn invalid_scan_range_zero_fails() {
    let root = root_01();
    let purposes = vec!["social".to_string()];
    assert!(recover(&root, &purposes, Some(0)).is_err());
}

#[test]
fn invalid_scan_range_too_large_fails() {
    let root = root_01();
    let purposes = vec!["social".to_string()];
    assert!(recover(&root, &purposes, Some(10_001)).is_err());
}

#[test]
fn default_scan_range_is_20() {
    let root = root_01();
    let purposes = vec!["social".to_string()];
    let recovered = recover(&root, &purposes, None).expect("recover must succeed");
    let social_ids = recovered.get("social").expect("social must exist");
    assert_eq!(social_ids.len(), 20);
}
