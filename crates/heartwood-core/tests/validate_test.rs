use heartwood_core::validate::validate_purpose;

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
