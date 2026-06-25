//! Bounded de-duplication set for request event ids.
//!
//! The same NIP-46 request usually arrives from several relays at once. We must
//! forward it to the device exactly once, so each relay task checks ids against
//! this shared set before queuing work. The set is bounded with FIFO eviction
//! so it cannot grow without limit on a long-running daemon.

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Seen {
    inner: Arc<Mutex<Inner>>,
    capacity: usize,
}

struct Inner {
    set: HashSet<String>,
    order: VecDeque<String>,
}

impl Seen {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner { set: HashSet::new(), order: VecDeque::new() })),
            capacity: capacity.max(1),
        }
    }

    /// Record an id. Returns `true` if it was not already present — i.e. the
    /// caller is the first to see it and should process the request.
    pub fn insert(&self, id: &str) -> bool {
        if id.is_empty() {
            // An id-less event cannot be de-duplicated; let it through rather
            // than silently swallow it.
            return true;
        }
        let mut inner = self.inner.lock().unwrap();
        if inner.set.contains(id) {
            return false;
        }
        inner.set.insert(id.to_string());
        inner.order.push_back(id.to_string());
        while inner.order.len() > self.capacity {
            if let Some(old) = inner.order.pop_front() {
                inner.set.remove(&old);
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_insert_is_new_then_duplicate() {
        let seen = Seen::new(16);
        assert!(seen.insert("abc"));
        assert!(!seen.insert("abc"));
        assert!(seen.insert("def"));
    }

    #[test]
    fn evicts_oldest_past_capacity() {
        let seen = Seen::new(2);
        assert!(seen.insert("a"));
        assert!(seen.insert("b"));
        assert!(seen.insert("c")); // evicts "a"
        assert!(seen.insert("a")); // "a" is new again after eviction
        assert!(!seen.insert("c")); // "c" still remembered
    }

    #[test]
    fn empty_id_always_passes() {
        let seen = Seen::new(4);
        assert!(seen.insert(""));
        assert!(seen.insert(""));
    }
}
