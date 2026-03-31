use heartwood_core::derive::derive;
use heartwood_core::proof::{create_blind_proof, create_full_proof, verify_proof};
use heartwood_core::root::from_nsec_bytes;

fn root_01() -> heartwood_core::types::TreeRoot {
    let nsec_bytes = [0x01u8; 32];
    from_nsec_bytes(&nsec_bytes).expect("root creation must succeed")
}

#[test]
fn blind_proof_round_trip() {
    let root = root_01();
    let child = derive(&root, "social", 0).expect("derive must succeed");
    let proof = create_blind_proof(&root, &child).expect("proof must succeed");

    // Attestation format: nsec-tree:own|{master_hex}|{child_hex}
    assert!(proof.attestation.starts_with("nsec-tree:own|"));
    // Split on the namespace prefix first, then pipe-delimited payload
    let payload = proof.attestation.strip_prefix("nsec-tree:own|").unwrap();
    let parts: Vec<&str> = payload.split('|').collect();
    assert_eq!(parts.len(), 2);
    // master and child hex are 64 chars each
    assert_eq!(parts[0].len(), 64);
    assert_eq!(parts[1].len(), 64);

    // Signature is 128 hex chars (64 bytes)
    assert_eq!(proof.signature.len(), 128);

    // No purpose/index in blind proof
    assert!(proof.purpose.is_none());
    assert!(proof.index.is_none());

    // Verify succeeds
    assert!(verify_proof(&proof).expect("verify must not error"));
}

#[test]
fn full_proof_round_trip() {
    let root = root_01();
    let child = derive(&root, "social", 0).expect("derive must succeed");
    let proof = create_full_proof(&root, &child).expect("proof must succeed");

    // Attestation format: nsec-tree:link|{master_hex}|{child_hex}|{purpose}|{index}
    assert!(proof.attestation.starts_with("nsec-tree:link|"));
    let payload = proof.attestation.strip_prefix("nsec-tree:link|").unwrap();
    let parts: Vec<&str> = payload.split('|').collect();
    assert_eq!(parts.len(), 4);
    assert_eq!(parts[2], "social");
    assert_eq!(parts[3], "0");

    // Purpose and index present
    assert_eq!(proof.purpose.as_deref(), Some("social"));
    assert_eq!(proof.index, Some(0));

    // Signature is 128 hex chars
    assert_eq!(proof.signature.len(), 128);

    // Verify succeeds
    assert!(verify_proof(&proof).expect("verify must not error"));
}

#[test]
fn tampered_attestation_fails() {
    let root = root_01();
    let child = derive(&root, "social", 0).expect("derive must succeed");
    let mut proof = create_blind_proof(&root, &child).expect("proof must succeed");

    // Tamper with the attestation
    proof.attestation = proof.attestation.replace("own", "pwn");

    // Verify returns false (not an error)
    assert!(!verify_proof(&proof).expect("verify must not error"));
}
