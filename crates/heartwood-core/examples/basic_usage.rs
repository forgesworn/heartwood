//! Basic Heartwood usage: create a tree root, derive identities, and prove ownership.
//!
//! Run with: `cargo run -p heartwood-core --example basic_usage`

fn main() -> Result<(), nsec_tree_rs::HeartwoodError> {
    // --- 1. Create a tree root from a BIP-39 mnemonic ---
    //
    // The mnemonic is the master secret. Everything derives from it.
    // In production this comes from the device setup flow; here we use
    // the standard BIP-39 test vector.
    let mnemonic = "abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon about";

    let root = nsec_tree_rs::from_mnemonic(mnemonic, None)?;
    println!("Master pubkey: {}", root.master_pubkey);

    // --- 2. Derive child identities by purpose and index ---
    //
    // Each (purpose, index) pair produces a deterministic, unique keypair.
    // Different purposes create unlinkable identity sets.
    let social = nsec_tree_rs::derive(&root, "social", 0)?;
    println!("\nSocial identity:");
    println!("  npub: {}", social.npub);
    println!("  purpose: {}, index: {}", social.purpose, social.index);

    let commerce = nsec_tree_rs::derive(&root, "commerce", 0)?;
    println!("\nCommerce identity:");
    println!("  npub: {}", commerce.npub);

    // Same purpose + different index = different identity, same category
    let social_alt = nsec_tree_rs::derive(&root, "social", 1)?;
    assert_ne!(social.npub, social_alt.npub);
    println!("\nSocial alt (index 1): {}", social_alt.npub);

    // --- 3. Named personas ---
    //
    // Personas are a convenience wrapper: derive_persona("work") is
    // equivalent to derive("nostr:persona:work", 0).
    let work = nsec_tree_rs::derive_persona(&root, "work", None)?;
    println!("\nWork persona: {}", work.identity.npub);

    // Sub-identities from a persona (two-level hierarchy)
    let work_dms = nsec_tree_rs::derive_from_persona(&work, "dms", None)?;
    println!("  Work DMs sub-identity: {}", work_dms.npub);

    // --- 4. Linkage proofs ---
    //
    // Prove that a child key belongs to the master, without revealing
    // the derivation path (blind) or with it (full).
    let blind_proof = nsec_tree_rs::create_blind_proof(&root, &social)?;
    assert!(nsec_tree_rs::verify_proof(&blind_proof)?);
    println!(
        "\nBlind proof verified: master {} owns child {}",
        &blind_proof.master_pubkey[..12],
        &blind_proof.child_pubkey[..12]
    );

    let full_proof = nsec_tree_rs::create_full_proof(&root, &social)?;
    assert!(nsec_tree_rs::verify_proof(&full_proof)?);
    println!(
        "Full proof: purpose={}, index={}",
        full_proof.purpose.as_deref().unwrap_or("?"),
        full_proof.index.unwrap_or(0)
    );

    // --- 5. Recovery ---
    //
    // Scan a set of purposes to rediscover all derived identities.
    // Useful after restoring from mnemonic backup.
    let found = nsec_tree_rs::recover(
        &root,
        &["social".to_string(), "commerce".to_string()],
        None, // default scan range (20 indices per purpose)
    )?;
    println!("\nRecovery scan found {} entries", found.len());

    // --- 6. Cleanup ---
    //
    // TreeRoot::destroy() zeroises the master secret from memory.
    root.destroy();

    Ok(())
}
