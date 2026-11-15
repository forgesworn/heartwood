# Wrapped raw-key reference

This branch adds `wrap_nsec` and `unwrap_nsec` to **nsec-tree-rs**, the reference
crate at `crates/heartwood-core`. No binary in this workspace uses that crate.
This does **not** add a Heartwood bridge command or device backup capability.

The canonical preview format is `nsec-tree/WRAPPED-NSEC.md` in the sibling
repository. The shared public fixture is copied unchanged into
`crates/heartwood-core/tests/fixtures/wrapped-nsec-v1.json`. Both implementations
encrypt to the same bytes and restore the exact raw key. A root and its
encrypted record are both required; neither derivation nor scanning recovers
an unrelated key without that record.

For a device integration, retain the original root construction. A stored
tree-root secret must not pass through `from_nsec_bytes` again. Restored keys
must enter a raw (`Bunker`) slot, never a tree-deriving slot. Wrap, validate and
restore on the signer without returning plaintext to the bridge. Require
advertised capability, physical owner consent, an empty destination slot and
an atomic write. Restore creates no app permissions. Sapwood must save and
read back the file against the intended npub before calling it a backup.
Firmware, Sapwood, Bark and Cambium are unchanged by this reference patch.

Validation: `cargo test --workspace --locked` and
`cargo clippy -p nsec-tree-rs --all-targets -- -D warnings` passed locally.
This covers format interoperability and rejection, not physical-device
recovery or an independent security review.

The existing manifest already requested k256 0.14 and bip32 0.6 while the
checked-in lock retained k256 0.13 and bip32 0.5. Resolving the new AES-GCM/HKDF
dependencies also aligned that stale lock with the existing manifest. The
workspace test run includes this resulting dependency graph.
