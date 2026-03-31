use heartwood_core::derive::derive;
use heartwood_core::root::{from_mnemonic, from_nsec_bytes};

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// Vector 4: mnemonic root, purpose=social, index=0
#[test]
fn vector_4_mnemonic_social_index_0() {
    let root = from_mnemonic(MNEMONIC, None).expect("mnemonic root must succeed");

    assert_eq!(
        root.master_pubkey,
        "npub186c5ke7vjsk98z8qx4ctdrggsl2qlu627g6xvg6yumrj5c5c6etqcfaclx"
    );

    let child = derive(&root, "social", 0).expect("derive must succeed");
    assert_eq!(child.nsec, "nsec17rnusheefhuryyhpprnq5l3zvpzhg24xm9n7588amun6uedvdtyqnpcsm4");
    assert_eq!(child.purpose, "social");
    assert_eq!(child.index, 0);
}

// Vector 5: path independence — mnemonic root and nsec root from NIP-06 key MUST differ
#[test]
fn vector_5_path_independence() {
    // NIP-06 key derived at m/44'/1237'/0'/0/0 from the same mnemonic
    let nip06_hex = "5f29af3b9676180290e77a4efad265c4c2ff28a5302461f73597fda26bb25731";
    let nip06_bytes: [u8; 32] =
        hex::decode(nip06_hex).expect("valid hex").try_into().expect("32 bytes");

    let nsec_root = from_nsec_bytes(&nip06_bytes).expect("nsec root must succeed");
    let mnemonic_root = from_mnemonic(MNEMONIC, None).expect("mnemonic root must succeed");

    // The nsec root from the NIP-06 key must produce a specific master pubkey
    assert_eq!(
        nsec_root.master_pubkey,
        "npub1fezyufqcfk9nqwamc6n6fwtm3yr2hrj8tc5xf0t3qs75tqvkz2hq40tnpd"
    );

    // The mnemonic root and nsec root MUST differ — they use different derivation paths
    assert_ne!(nsec_root.master_pubkey, mnemonic_root.master_pubkey);
}

// Mnemonic with passphrase produces different root
#[test]
fn mnemonic_with_passphrase_differs() {
    let root_no_pass = from_mnemonic(MNEMONIC, None).expect("no passphrase");
    let root_with_pass = from_mnemonic(MNEMONIC, Some("test")).expect("with passphrase");
    assert_ne!(root_no_pass.master_pubkey, root_with_pass.master_pubkey);
}

// Invalid mnemonic is rejected
#[test]
fn invalid_mnemonic_rejected() {
    assert!(from_mnemonic("not a valid mnemonic phrase at all", None).is_err());
}

// Mnemonic root is deterministic
#[test]
fn mnemonic_root_deterministic() {
    let root_a = from_mnemonic(MNEMONIC, None).expect("root a");
    let root_b = from_mnemonic(MNEMONIC, None).expect("root b");
    assert_eq!(root_a.master_pubkey, root_b.master_pubkey);
}
