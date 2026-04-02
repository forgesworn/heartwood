// crates/heartwood-core/src/lib.rs
pub mod derive;
pub mod encoding;
pub mod persona;
pub mod proof;
pub mod recover;
pub mod root;
pub mod types;
pub mod validate;

pub use derive::{derive, derive_from_identity};
pub use encoding::{decode_npub, decode_nsec, encode_npub, encode_nsec};
pub use persona::{derive_from_persona, derive_persona};
pub use proof::{create_blind_proof, create_full_proof, verify_proof};
pub use recover::recover;
pub use root::{from_mnemonic, from_nsec, from_nsec_bytes, generate_mnemonic, npub_from_nsec};
pub use types::{HeartwoodError, Identity, LinkageProof, Persona, TreeRoot};
