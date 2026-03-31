// crates/heartwood-core/src/recover.rs
use std::collections::HashMap;

use crate::derive::derive;
use crate::types::{HeartwoodError, Identity, TreeRoot, DEFAULT_SCAN_RANGE, MAX_SCAN_RANGE};

/// Recover identities by scanning a range of indices for each purpose.
///
/// For each purpose string, derives identities at indices 0..scan_range.
/// Returns a map from purpose to the vector of derived identities.
///
/// Default scan_range is 20 (DEFAULT_SCAN_RANGE).
/// Valid range: 1..=10000 (MAX_SCAN_RANGE).
pub fn recover(
    root: &TreeRoot,
    purposes: &[String],
    scan_range: Option<u32>,
) -> Result<HashMap<String, Vec<Identity>>, HeartwoodError> {
    let range = scan_range.unwrap_or(DEFAULT_SCAN_RANGE);

    if !(1..=MAX_SCAN_RANGE).contains(&range) {
        return Err(HeartwoodError::InvalidScanRange);
    }

    let mut results = HashMap::new();

    for purpose in purposes {
        let mut identities = Vec::with_capacity(range as usize);
        for index in 0..range {
            let identity = derive(root, purpose, index)?;
            identities.push(identity);
        }
        results.insert(purpose.clone(), identities);
    }

    Ok(results)
}
