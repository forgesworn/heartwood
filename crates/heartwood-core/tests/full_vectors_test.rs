//! Frozen test vector suite — all 5 vectors via the public API.
//!
//! These vectors MUST match the TypeScript nsec-tree implementation byte-for-byte.
//! If any of these tests break, a backwards-incompatible change has been introduced.

use heartwood_core::*;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn root_01() -> TreeRoot {
    let nsec_bytes = [0x01u8; 32];
    from_nsec_bytes(&nsec_bytes).expect("root creation must succeed")
}

// ---------------------------------------------------------------------------
// Vector 1: nsec root 0x01-fill, purpose=social, index=0
// ---------------------------------------------------------------------------
#[test]
fn vector_1_social_index_0() {
    let root = root_01();

    assert_eq!(
        root.master_pubkey,
        "npub13sp7q3awvrqpa9p2svm7w8ghudghlnrraekwl7qh8w7j8747vjwskvzy2u"
    );

    let child = derive(&root, "social", 0).expect("derive must succeed");
    assert_eq!(
        child.nsec,
        "nsec1nr5ck3mw4v7zhj6syrj2v7dyrd6wa0anpgregnzrv8ysv5qjvhnsafv7mx"
    );
    assert_eq!(
        child.npub,
        "npub1ehzv62sphgdc4lfjnxmxcwx3xpp6rxktdp7rxnc9yl8l4arykdeqyfhrxy"
    );
    assert_eq!(child.index, 0);
    assert_eq!(child.purpose, "social");
}

// ---------------------------------------------------------------------------
// Vector 2: nsec root 0x01-fill, purpose=commerce, index=0
// ---------------------------------------------------------------------------
#[test]
fn vector_2_commerce_index_0() {
    let root = root_01();
    let child = derive(&root, "commerce", 0).expect("derive must succeed");
    assert_eq!(
        child.nsec,
        "nsec1l3329mrljxtscjzln469xf5drf4qwfe7aq5u73xgw6zl0p6c7p8sd6vumk"
    );
    assert_eq!(child.index, 0);
    assert_eq!(child.purpose, "commerce");
}

// ---------------------------------------------------------------------------
// Vector 3: nsec root 0x01-fill, purpose=social, index=1
// ---------------------------------------------------------------------------
#[test]
fn vector_3_social_index_1() {
    let root = root_01();
    let child = derive(&root, "social", 1).expect("derive must succeed");
    assert_eq!(
        child.nsec,
        "nsec1sq4zl5cay4ghh54mndcedsmhumxz7vnj3wgkctp75uw2wqmk0yts3ny5vz"
    );
    assert_eq!(child.index, 1);
    assert_eq!(child.purpose, "social");
}

// ---------------------------------------------------------------------------
// Vector 4: mnemonic root, purpose=social, index=0
// ---------------------------------------------------------------------------
#[test]
fn vector_4_mnemonic_social_index_0() {
    let root = from_mnemonic(MNEMONIC, None).expect("mnemonic root must succeed");

    assert_eq!(
        root.master_pubkey,
        "npub186c5ke7vjsk98z8qx4ctdrggsl2qlu627g6xvg6yumrj5c5c6etqcfaclx"
    );

    let child = derive(&root, "social", 0).expect("derive must succeed");
    assert_eq!(
        child.nsec,
        "nsec17rnusheefhuryyhpprnq5l3zvpzhg24xm9n7588amun6uedvdtyqnpcsm4"
    );
    assert_eq!(child.purpose, "social");
    assert_eq!(child.index, 0);
}

// ---------------------------------------------------------------------------
// Vector 5: path independence — mnemonic root and nsec root from NIP-06 key
//           MUST differ (different derivation paths)
// ---------------------------------------------------------------------------
#[test]
fn vector_5_path_independence() {
    // NIP-06 key derived at m/44'/1237'/0'/0/0 from the same mnemonic
    let nip06_hex = "5f29af3b9676180290e77a4efad265c4c2ff28a5302461f73597fda26bb25731";
    let nip06_bytes: [u8; 32] = hex::decode(nip06_hex)
        .expect("valid hex")
        .try_into()
        .expect("32 bytes");

    let nsec_root = from_nsec_bytes(&nip06_bytes).expect("nsec root must succeed");
    let mnemonic_root = from_mnemonic(MNEMONIC, None).expect("mnemonic root must succeed");

    assert_eq!(
        nsec_root.master_pubkey,
        "npub1fezyufqcfk9nqwamc6n6fwtm3yr2hrj8tc5xf0t3qs75tqvkz2hq40tnpd"
    );

    // The mnemonic root and nsec root MUST differ — they use different derivation paths
    assert_ne!(nsec_root.master_pubkey, mnemonic_root.master_pubkey);
}
