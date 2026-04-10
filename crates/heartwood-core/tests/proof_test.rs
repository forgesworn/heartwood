use nsec_tree_rs::derive::derive;
use nsec_tree_rs::proof::{create_blind_proof, create_full_proof, verify_proof};
use nsec_tree_rs::root::from_nsec_bytes;
use nsec_tree_rs::types::{Identity, LinkageProof};
use zeroize::Zeroizing;

fn root_01() -> nsec_tree_rs::types::TreeRoot {
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

/// Build an Identity with an arbitrary purpose, bypassing derive()'s
/// validation. The secret owner can construct this locally; the test
/// confirms the proof layer rejects problematic purposes.
fn identity_with_purpose(purpose: &str) -> Identity {
    let root = root_01();
    let child = derive(&root, "social", 0).expect("derive must succeed");
    Identity {
        npub: child.npub,
        private_key: Zeroizing::new(*child.private_key),
        public_key: child.public_key,
        purpose: purpose.to_string(),
        index: 0,
    }
}

#[test]
fn create_full_proof_rejects_pipe_in_purpose() {
    let root = root_01();
    let bad = identity_with_purpose("foo|bar");
    match create_full_proof(&root, &bad) {
        Err(e) => {
            let s = format!("{e}");
            assert!(
                s.contains('|') || s.contains("attestation delimiter"),
                "unexpected error: {s}"
            );
        }
        Ok(_) => panic!("expected pipe in purpose to be rejected"),
    }
}

#[test]
fn create_full_proof_rejects_control_chars_in_purpose() {
    let root = root_01();
    let bad_newline = identity_with_purpose("foo\nbar");
    assert!(create_full_proof(&root, &bad_newline).is_err());
    let bad_tab = identity_with_purpose("foo\tbar");
    assert!(create_full_proof(&root, &bad_tab).is_err());
    let bad_del = identity_with_purpose("foo\x7fbar");
    assert!(create_full_proof(&root, &bad_del).is_err());
}

#[test]
fn verify_proof_rejects_mismatched_purpose_field() {
    // Caller-supplied proof.purpose differs from what the signed attestation
    // embeds. Rust verify_proof must catch this via canonical reconstruction
    // rather than trusting proof.purpose.
    let root = root_01();
    let child = derive(&root, "social", 0).expect("derive must succeed");
    let mut proof = create_full_proof(&root, &child).expect("proof must succeed");

    // Flip purpose field but leave attestation intact
    proof.purpose = Some("commerce".to_string());

    assert!(!verify_proof(&proof).expect("verify must not error"));
}

#[test]
fn verify_proof_rejects_mismatched_index_field() {
    let root = root_01();
    let child = derive(&root, "social", 0).expect("derive must succeed");
    let mut proof = create_full_proof(&root, &child).expect("proof must succeed");

    proof.index = Some(42);

    assert!(!verify_proof(&proof).expect("verify must not error"));
}

#[test]
fn verify_proof_rejects_proof_with_pipe_in_purpose_field() {
    // A crafted proof where proof.purpose contains `|` should be rejected by
    // canonical_attestation → validate_proof_purpose, regardless of whether
    // the attached signature would verify over the attestation string.
    let root = root_01();
    let child = derive(&root, "social", 0).expect("derive must succeed");
    let mut proof = create_full_proof(&root, &child).expect("proof must succeed");

    proof.purpose = Some("social|injected".to_string());
    // Also overwrite attestation so the literal strings match the fields —
    // this is the strongest adversary model for this attack.
    proof.attestation = format!(
        "nsec-tree:link|{}|{}|social|injected|0",
        proof.master_pubkey, proof.child_pubkey
    );

    assert!(!verify_proof(&proof).expect("verify must not error"));
}

#[test]
fn verify_proof_rejects_mismatched_hasonly_optional_pair() {
    let root = root_01();
    let child = derive(&root, "social", 0).expect("derive must succeed");

    // purpose present, index absent (blind-style with a stray purpose)
    let mut a = create_full_proof(&root, &child).expect("proof must succeed");
    a.index = None;
    assert!(!verify_proof(&a).expect("verify must not error"));

    // index present, purpose absent
    let mut b = create_full_proof(&root, &child).expect("proof must succeed");
    b.purpose = None;
    assert!(!verify_proof(&b).expect("verify must not error"));
}

#[test]
fn verify_proof_rejects_uppercase_hex_in_fields() {
    let root = root_01();
    let child = derive(&root, "social", 0).expect("derive must succeed");
    let mut proof: LinkageProof = create_blind_proof(&root, &child).expect("proof must succeed");

    proof.master_pubkey = proof.master_pubkey.to_uppercase();

    assert!(!verify_proof(&proof).expect("verify must not error"));
}
