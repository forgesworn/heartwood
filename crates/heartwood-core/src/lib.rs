// crates/heartwood-core/src/lib.rs
pub mod types;
pub mod encoding;
pub mod validate;
pub mod derive;
pub mod root;
pub mod proof;
pub mod persona;
pub mod recover;

pub use types::{TreeRoot, Identity, Persona, LinkageProof, HeartwoodError};
pub use root::{from_nsec, from_nsec_bytes, from_mnemonic};
pub use derive::{derive, derive_from_identity};
pub use proof::{create_blind_proof, create_full_proof, verify_proof};
pub use persona::{derive_persona, derive_from_persona};
pub use recover::recover;
pub use encoding::{encode_nsec, decode_nsec, encode_npub, decode_npub};
