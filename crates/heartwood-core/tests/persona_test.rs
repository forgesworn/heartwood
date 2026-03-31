use heartwood_core::persona::{derive_from_persona, derive_persona};
use heartwood_core::root::from_nsec_bytes;

fn root_01() -> heartwood_core::types::TreeRoot {
    let nsec_bytes = [0x01u8; 32];
    from_nsec_bytes(&nsec_bytes).expect("root creation must succeed")
}

#[test]
fn persona_purpose_prefixed_correctly() {
    let root = root_01();
    let persona = derive_persona(&root, "personal", None).expect("persona must succeed");
    assert_eq!(persona.identity.purpose, "nostr:persona:personal");
    assert_eq!(persona.name, "personal");
    assert_eq!(persona.index, 0);
}

#[test]
fn different_names_produce_different_keys() {
    let root = root_01();
    let personal = derive_persona(&root, "personal", None).expect("personal must succeed");
    let work = derive_persona(&root, "work", None).expect("work must succeed");
    assert_ne!(personal.identity.npub, work.identity.npub);
    assert_ne!(personal.identity.nsec(), work.identity.nsec());
}

#[test]
fn derive_from_persona_creates_distinct_sub_identity() {
    let root = root_01();
    let persona = derive_persona(&root, "personal", None).expect("persona must succeed");
    let sub = derive_from_persona(&persona, "relay-auth", None).expect("sub-identity must succeed");
    assert_ne!(persona.identity.npub, sub.npub);
    assert_ne!(persona.identity.nsec(), sub.nsec());
}

#[test]
fn persona_derivation_is_deterministic() {
    let root_a = root_01();
    let root_b = root_01();
    let persona_a = derive_persona(&root_a, "personal", Some(5)).expect("a must succeed");
    let persona_b = derive_persona(&root_b, "personal", Some(5)).expect("b must succeed");
    assert_eq!(persona_a.identity.npub, persona_b.identity.npub);
    assert_eq!(persona_a.identity.nsec(), persona_b.identity.nsec());
    assert_eq!(persona_a.index, 5);
    assert_eq!(persona_b.index, 5);
}

#[test]
fn persona_name_with_pipe_rejected() {
    let root = root_01();
    let result = derive_persona(&root, "alice|evil", None);
    match result {
        Err(e) => assert!(e.to_string().contains("persona name must not contain '|'")),
        Ok(_) => panic!("expected pipe in persona name to be rejected"),
    }
}
