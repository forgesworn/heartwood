use nsec_tree_rs::generate_mnemonic;

#[test]
fn generate_mnemonic_returns_24_words() {
    let words = generate_mnemonic().expect("should generate mnemonic");
    assert_eq!(words.len(), 24, "expected 24 words, got {}", words.len());
}

#[test]
fn generate_mnemonic_words_are_valid_bip39() {
    let words = generate_mnemonic().expect("should generate mnemonic");
    let mnemonic_str = words.join(" ");
    // Parsing validates checksum and word membership
    let parsed: bip39::Mnemonic = mnemonic_str.parse().expect("should be valid BIP-39");
    assert_eq!(parsed.word_count(), 24);
}

#[test]
fn generate_mnemonic_is_not_deterministic() {
    let a = generate_mnemonic().expect("first");
    let b = generate_mnemonic().expect("second");
    assert_ne!(a, b, "two calls should produce different mnemonics");
}
