use nsec_tree_rs::validate::{validate_proof_purpose, validate_purpose};

#[test]
fn valid_purposes() {
    assert!(validate_purpose("social").is_ok());
    assert!(validate_purpose("commerce").is_ok());
    assert!(validate_purpose("nostr:persona:personal").is_ok());
    assert!(validate_purpose("a").is_ok());
}

#[test]
fn empty_purpose_fails() {
    assert!(validate_purpose("").is_err());
}

#[test]
fn whitespace_only_fails() {
    assert!(validate_purpose("   ").is_err());
    assert!(validate_purpose("\t").is_err());
}

#[test]
fn null_byte_in_purpose_fails() {
    assert!(validate_purpose("social\0evil").is_err());
}

#[test]
fn too_long_purpose_fails() {
    let long = "a".repeat(256);
    assert!(validate_purpose(&long).is_err());
}

#[test]
fn max_length_purpose_passes() {
    let max = "a".repeat(255);
    assert!(validate_purpose(&max).is_ok());
}

#[test]
fn pipe_in_purpose_fails() {
    assert!(validate_purpose("evil|9999").is_err());
    assert!(validate_purpose("|").is_err());
    assert!(validate_purpose("social|0").is_err());
}

#[test]
fn validate_proof_purpose_accepts_clean_purposes() {
    assert!(validate_proof_purpose("social").is_ok());
    assert!(validate_proof_purpose("nostr:persona:alice").is_ok());
    assert!(validate_proof_purpose("trott:rider").is_ok());
}

#[test]
fn validate_proof_purpose_rejects_pipe() {
    // Inherited from validate_purpose
    assert!(validate_proof_purpose("foo|bar").is_err());
}

#[test]
fn validate_proof_purpose_rejects_control_chars() {
    assert!(validate_proof_purpose("foo\nbar").is_err());
    assert!(validate_proof_purpose("foo\tbar").is_err());
    assert!(validate_proof_purpose("foo\rbar").is_err());
    assert!(validate_proof_purpose("foo\x01bar").is_err());
    assert!(validate_proof_purpose("foo\x7fbar").is_err());
}

#[test]
fn validate_proof_purpose_inherits_base_rules() {
    assert!(validate_proof_purpose("").is_err());
    assert!(validate_proof_purpose("   ").is_err());
    assert!(validate_proof_purpose("a\0b").is_err());
    assert!(validate_proof_purpose(&"a".repeat(256)).is_err());
}
