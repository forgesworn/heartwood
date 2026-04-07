use nsec_tree_rs::derive::{derive, derive_from_identity};
use nsec_tree_rs::root::from_nsec_bytes;

/// Frozen test vectors — MUST match TypeScript nsec-tree byte-for-byte.
/// Root key: 0x01-fill (32 bytes of 0x01).
fn root_01() -> nsec_tree_rs::types::TreeRoot {
    let nsec_bytes = [0x01u8; 32];
    from_nsec_bytes(&nsec_bytes).expect("root creation must succeed")
}

// Vector 1: nsec root 0x01-fill, purpose=social, index=0
#[test]
fn vector_1_social_index_0() {
    let root = root_01();

    assert_eq!(
        root.master_pubkey,
        "npub13sp7q3awvrqpa9p2svm7w8ghudghlnrraekwl7qh8w7j8747vjwskvzy2u"
    );

    let child = derive(&root, "social", 0).expect("derive must succeed");
    assert_eq!(child.nsec(), "nsec1nr5ck3mw4v7zhj6syrj2v7dyrd6wa0anpgregnzrv8ysv5qjvhnsafv7mx");
    assert_eq!(child.npub, "npub1ehzv62sphgdc4lfjnxmxcwx3xpp6rxktdp7rxnc9yl8l4arykdeqyfhrxy");
    assert_eq!(child.index, 0);
    assert_eq!(child.purpose, "social");
}

// Vector 2: nsec root 0x01-fill, purpose=commerce, index=0
#[test]
fn vector_2_commerce_index_0() {
    let root = root_01();
    let child = derive(&root, "commerce", 0).expect("derive must succeed");
    assert_eq!(child.nsec(), "nsec1l3329mrljxtscjzln469xf5drf4qwfe7aq5u73xgw6zl0p6c7p8sd6vumk");
    assert_eq!(child.index, 0);
    assert_eq!(child.purpose, "commerce");
}

// Vector 3: nsec root 0x01-fill, purpose=social, index=1
#[test]
fn vector_3_social_index_1() {
    let root = root_01();
    let child = derive(&root, "social", 1).expect("derive must succeed");
    assert_eq!(child.nsec(), "nsec1sq4zl5cay4ghh54mndcedsmhumxz7vnj3wgkctp75uw2wqmk0yts3ny5vz");
    assert_eq!(child.index, 1);
    assert_eq!(child.purpose, "social");
}

// Different purposes produce different keys
#[test]
fn different_purposes_differ() {
    let root = root_01();
    let social = derive(&root, "social", 0).expect("derive must succeed");
    let commerce = derive(&root, "commerce", 0).expect("derive must succeed");
    assert_ne!(social.npub, commerce.npub);
    assert_ne!(social.nsec(), commerce.nsec());
}

// Different indices produce different keys
#[test]
fn different_indices_differ() {
    let root = root_01();
    let idx0 = derive(&root, "social", 0).expect("derive must succeed");
    let idx1 = derive(&root, "social", 1).expect("derive must succeed");
    assert_ne!(idx0.npub, idx1.npub);
    assert_ne!(idx0.nsec(), idx1.nsec());
}

// Invalid purpose is rejected
#[test]
fn empty_purpose_rejected() {
    let root = root_01();
    assert!(derive(&root, "", 0).is_err());
}

#[test]
fn null_byte_purpose_rejected() {
    let root = root_01();
    assert!(derive(&root, "social\0evil", 0).is_err());
}

// derive_from_identity produces deterministic results
#[test]
fn derive_from_identity_deterministic() {
    let root = root_01();
    let parent = derive(&root, "social", 0).expect("derive must succeed");
    let child_a =
        derive_from_identity(&parent, "sub-purpose", 0).expect("derive_from_identity must succeed");
    let child_b =
        derive_from_identity(&parent, "sub-purpose", 0).expect("derive_from_identity must succeed");
    assert_eq!(child_a.nsec(), child_b.nsec());
    assert_eq!(child_a.npub, child_b.npub);
}

// derive_from_identity produces distinct keys from parent
#[test]
fn derive_from_identity_distinct_from_parent() {
    let root = root_01();
    let parent = derive(&root, "social", 0).expect("derive must succeed");
    let child =
        derive_from_identity(&parent, "sub-purpose", 0).expect("derive_from_identity must succeed");
    assert_ne!(parent.npub, child.npub);
    assert_ne!(parent.nsec(), child.nsec());
}
