use heartwood_core::encoding::{decode_npub, decode_nsec, encode_npub, encode_nsec};

#[test]
fn round_trip_nsec() {
    let key = [0x01u8; 32];
    let nsec = encode_nsec(&key);
    assert!(nsec.starts_with("nsec1"));
    let decoded = decode_nsec(&nsec).unwrap();
    assert_eq!(*decoded, key);
}

#[test]
fn round_trip_npub() {
    let key = [0x02u8; 32];
    let npub = encode_npub(&key);
    assert!(npub.starts_with("npub1"));
    let decoded = decode_npub(&npub).unwrap();
    assert_eq!(decoded, key);
}

#[test]
fn decode_invalid_prefix_fails() {
    let key = [0x01u8; 32];
    let nsec = encode_nsec(&key);
    // Try decoding an nsec as npub -- should fail
    assert!(decode_npub(&nsec).is_err());
}
