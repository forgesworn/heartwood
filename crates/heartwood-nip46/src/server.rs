// crates/heartwood-nip46/src/server.rs
//! Heartwood NIP-46 server state and request dispatcher.

use std::sync::Mutex;

use heartwood_core::{
    create_blind_proof, create_full_proof, derive, derive_persona, recover, verify_proof, Identity,
    LinkageProof, TreeRoot,
};
use serde_json::json;

use crate::methods::{Nip46Request, Nip46Response};
use crate::session::{ClientSession, SessionManager};

/// A cached derived identity, along with its optional persona name.
struct DerivedEntry {
    identity: Identity,
    persona_name: Option<String>,
}

/// The Heartwood NIP-46 server state.
///
/// Holds the master tree root, a cache of derived identities, a pointer to
/// the active signing identity, and all client sessions.
pub struct HeartwoodServer {
    /// The master tree root. `None` until a secret is loaded.
    root: Option<TreeRoot>,

    /// Index into `derived` for the currently active signing identity.
    /// `None` means no derived identity is active (master pubkey context only).
    /// Will be used by the transport layer when forwarding NIP-46 events.
    #[allow(dead_code)]
    active: Option<usize>,

    /// Cached derived identities in derivation order.
    derived: Vec<DerivedEntry>,

    /// Per-client session manager.
    sessions: Mutex<SessionManager>,
}

impl HeartwoodServer {
    /// Create a new server instance with no loaded root key.
    pub fn new() -> Self {
        Self {
            root: None,
            active: None,
            derived: Vec::new(),
            sessions: Mutex::new(SessionManager::new()),
        }
    }

    /// Create a server instance pre-loaded with a root key.
    pub fn with_root(root: TreeRoot) -> Self {
        Self {
            root: Some(root),
            active: None,
            derived: Vec::new(),
            sessions: Mutex::new(SessionManager::new()),
        }
    }

    /// Access sessions, recovering from mutex poisoning.
    ///
    /// A poisoned mutex means a thread panicked whilst holding the lock.
    /// For a signing appliance we recover rather than propagate the panic,
    /// since the session data is not corrupted by an unrelated panic.
    fn lock_sessions(&self) -> std::sync::MutexGuard<'_, SessionManager> {
        self.sessions.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Map a `Nip46Request` variant to its canonical method name string.
    ///
    /// Used to look up method-level permissions in `ClientPermissions`.
    fn method_name_of(request: &Nip46Request) -> &'static str {
        match request {
            Nip46Request::GetPublicKey => "get_public_key",
            Nip46Request::SignEvent(_) => "sign_event",
            Nip46Request::Nip44Encrypt(_) => "nip44_encrypt",
            Nip46Request::Nip44Decrypt(_) => "nip44_decrypt",
            Nip46Request::Nip04Encrypt(_) => "nip04_encrypt",
            Nip46Request::Nip04Decrypt(_) => "nip04_decrypt",
            Nip46Request::HeartwoodDerive(_) => "heartwood_derive",
            Nip46Request::HeartwoodDerivePersona(_) => "heartwood_derive_persona",
            Nip46Request::HeartwoodListIdentities => "heartwood_list_identities",
            Nip46Request::HeartwoodSwitch(_) => "heartwood_switch",
            Nip46Request::HeartwoodCreateProof(_) => "heartwood_create_proof",
            Nip46Request::HeartwoodVerifyProof(_) => "heartwood_verify_proof",
            Nip46Request::HeartwoodRecover(_) => "heartwood_recover",
        }
    }

    /// Dispatch a NIP-46 request and return the response.
    ///
    /// Flow:
    /// 1. Check root is loaded.
    /// 2. Look up or create a `ClientSession` for `client_pubkey`.
    /// 3. Touch the session and check the rate limit.
    /// 4. Check method-level permission.
    /// 5. Dispatch to the appropriate handler.
    pub fn handle_request(
        &mut self,
        request_id: &str,
        client_pubkey: &str,
        request: Nip46Request,
    ) -> Nip46Response {
        // 1. Root must be loaded.
        if self.root.is_none() {
            return Nip46Response::err(request_id, "no root key loaded");
        }

        let method = Self::method_name_of(&request);

        // 2/3/4. Session management and permission checks.
        {
            let mut sessions = self.lock_sessions();

            // Create session if this client is new.
            if sessions.get(client_pubkey).is_none() {
                match ClientSession::new(client_pubkey) {
                    Some(session) => {
                        if !sessions.add(session) {
                            return Nip46Response::err(
                                request_id,
                                "session limit reached; try again later",
                            );
                        }
                    }
                    None => {
                        return Nip46Response::err(request_id, "invalid client public key");
                    }
                }
            }

            let session =
                sessions.get_mut(client_pubkey).expect("session was just inserted or exists");

            // Touch the session to update the idle timer.
            session.touch();

            // Rate limit check.
            if !session.permissions.check_rate_limit() {
                return Nip46Response::err(request_id, "rate limit exceeded");
            }

            // Method permission check.
            if !session.permissions.can_call_method(method) {
                return Nip46Response::err(
                    request_id,
                    format!("method '{method}' not permitted for this client"),
                );
            }

            // Kind restriction check for sign_event.
            if let Nip46Request::SignEvent(ref params) = request {
                if let Some(kind) = extract_event_kind(params) {
                    if !session.permissions.can_sign_kind(kind) {
                        return Nip46Response::err(
                            request_id,
                            format!("signing kind {kind} not permitted for this client"),
                        );
                    }
                }
            }
        }

        // 5. Dispatch. Root is guaranteed Some at this point.
        match request {
            Nip46Request::GetPublicKey => self.handle_get_public_key(request_id),
            Nip46Request::SignEvent(params) => self.handle_sign_event(request_id, params),
            Nip46Request::Nip44Encrypt(_) => {
                Nip46Response::err(request_id, "nip44_encrypt: not yet implemented")
            }
            Nip46Request::Nip44Decrypt(_) => {
                Nip46Response::err(request_id, "nip44_decrypt: not yet implemented")
            }
            Nip46Request::Nip04Encrypt(_) => {
                Nip46Response::err(request_id, "nip04_encrypt: not yet implemented")
            }
            Nip46Request::Nip04Decrypt(_) => {
                Nip46Response::err(request_id, "nip04_decrypt: not yet implemented")
            }
            Nip46Request::HeartwoodDerive(params) => self.handle_derive(request_id, params),
            Nip46Request::HeartwoodDerivePersona(params) => {
                self.handle_derive_persona(request_id, params)
            }
            Nip46Request::HeartwoodListIdentities => self.handle_list_identities(request_id),
            Nip46Request::HeartwoodSwitch(params) => self.handle_switch(request_id, params),
            Nip46Request::HeartwoodCreateProof(params) => {
                self.handle_create_proof(request_id, params)
            }
            Nip46Request::HeartwoodVerifyProof(params) => {
                self.handle_verify_proof(request_id, params)
            }
            Nip46Request::HeartwoodRecover(params) => self.handle_recover(request_id, params),
        }
    }

    // -------------------------------------------------------------------------
    // Method handlers
    // -------------------------------------------------------------------------

    /// Return the active identity's npub, or the master pubkey if no derived
    /// identity is active.
    fn handle_get_public_key(&self, request_id: &str) -> Nip46Response {
        let npub = match self.active {
            Some(idx) => self.derived[idx].identity.npub.clone(),
            None => self.root.as_ref().expect("root checked").master_pubkey.clone(),
        };
        Nip46Response::ok(request_id, json!(npub))
    }

    /// Parse an event template from `params[0]` and produce a signed Nostr event.
    ///
    /// NIP-46 wire format sends params as JSON strings; this handler also
    /// accepts an inline JSON object for convenience.
    ///
    /// Requires an active derived identity — the master root secret is never
    /// used as a NIP-46 signing key.
    fn handle_sign_event(&self, request_id: &str, params: Vec<serde_json::Value>) -> Nip46Response {
        let raw = params.into_iter().next().unwrap_or(serde_json::Value::Null);

        let template: serde_json::Value = if raw.is_string() {
            match serde_json::from_str(raw.as_str().unwrap()) {
                Ok(v) => v,
                Err(e) => {
                    return Nip46Response::err(
                        request_id,
                        format!("sign_event: invalid event JSON: {e}"),
                    )
                }
            }
        } else if raw.is_object() {
            raw
        } else {
            return Nip46Response::err(request_id, "sign_event: missing event template");
        };

        // Require an active derived identity.
        let private_key: &[u8; 32] = match self.active {
            Some(idx) => &self.derived[idx].identity.private_key,
            None => {
                return Nip46Response::err(
                    request_id,
                    "sign_event: no active identity; call heartwood_switch first",
                )
            }
        };

        match crate::sign::sign_event(private_key, &template) {
            Ok(event) => Nip46Response::ok(request_id, event),
            Err(e) => Nip46Response::err(request_id, format!("sign_event: {e}")),
        }
    }

    /// Derive a new child identity at a given purpose and index.
    ///
    /// Params: `[purpose: string, index?: number]`
    fn handle_derive(&mut self, request_id: &str, params: Vec<serde_json::Value>) -> Nip46Response {
        let purpose = match params.first().and_then(|v| v.as_str()) {
            Some(p) => p.to_string(),
            None => return Nip46Response::err(request_id, "heartwood_derive: missing 'purpose'"),
        };
        let index = params.get(1).and_then(|v| v.as_u64()).unwrap_or(0) as u32;

        let root = self.root.as_ref().expect("root checked");
        match derive(root, &purpose, index) {
            Ok(identity) => {
                let npub = identity.npub.clone();
                let actual_index = identity.index;
                self.derived.push(DerivedEntry { identity, persona_name: None });
                Nip46Response::ok(
                    request_id,
                    json!({
                        "npub": npub,
                        "purpose": purpose,
                        "index": actual_index,
                    }),
                )
            }
            Err(e) => Nip46Response::err(request_id, format!("heartwood_derive: {e}")),
        }
    }

    /// Derive a named persona identity.
    ///
    /// Params: `[name: string, index?: number]`
    fn handle_derive_persona(
        &mut self,
        request_id: &str,
        params: Vec<serde_json::Value>,
    ) -> Nip46Response {
        let name = match params.first().and_then(|v| v.as_str()) {
            Some(n) => n.to_string(),
            None => {
                return Nip46Response::err(request_id, "heartwood_derive_persona: missing 'name'")
            }
        };
        let index = params.get(1).and_then(|v| v.as_u64()).map(|i| i as u32);

        let root = self.root.as_ref().expect("root checked");
        match derive_persona(root, &name, index) {
            Ok(persona) => {
                let npub = persona.identity.npub.clone();
                let purpose = persona.identity.purpose.clone();
                let actual_index = persona.index;
                self.derived.push(DerivedEntry {
                    identity: persona.identity,
                    persona_name: Some(name.clone()),
                });
                Nip46Response::ok(
                    request_id,
                    json!({
                        "npub": npub,
                        "purpose": purpose,
                        "index": actual_index,
                        "personaName": name,
                    }),
                )
            }
            Err(e) => Nip46Response::err(request_id, format!("heartwood_derive_persona: {e}")),
        }
    }

    /// Return a JSON array describing all cached derived identities.
    fn handle_list_identities(&self, request_id: &str) -> Nip46Response {
        let list: Vec<serde_json::Value> = self
            .derived
            .iter()
            .map(|entry| {
                let mut obj = json!({
                    "npub": entry.identity.npub,
                    "purpose": entry.identity.purpose,
                    "index": entry.identity.index,
                });
                if let Some(name) = &entry.persona_name {
                    obj["personaName"] = json!(name);
                }
                obj
            })
            .collect();
        Nip46Response::ok(request_id, json!(list))
    }

    /// Switch the active signing identity.
    ///
    /// Params: `[target: string, index_hint?: number]`
    ///
    /// `target` may be:
    /// - `"master"` — resets active to `None` (master pubkey context).
    /// - An exact npub bech32 string matching an entry in the cache.
    /// - A persona name matching an entry in the cache.
    /// - A purpose string, with an optional index hint (default 0).
    fn handle_switch(&mut self, request_id: &str, params: Vec<serde_json::Value>) -> Nip46Response {
        let target = match params.first().and_then(|v| v.as_str()) {
            Some(t) => t.to_string(),
            None => return Nip46Response::err(request_id, "heartwood_switch: missing target"),
        };
        let index_hint = params.get(1).and_then(|v| v.as_u64()).map(|i| i as u32);

        if target == "master" {
            self.active = None;
            let npub = self.root.as_ref().expect("root checked").master_pubkey.clone();
            return Nip46Response::ok(request_id, json!({ "npub": npub }));
        }

        // Search by exact npub.
        if let Some(idx) = self.derived.iter().position(|e| e.identity.npub == target) {
            self.active = Some(idx);
            return Nip46Response::ok(
                request_id,
                json!({ "npub": self.derived[idx].identity.npub }),
            );
        }

        // Search by persona name.
        if let Some(idx) =
            self.derived.iter().position(|e| e.persona_name.as_deref() == Some(target.as_str()))
        {
            self.active = Some(idx);
            return Nip46Response::ok(
                request_id,
                json!({ "npub": self.derived[idx].identity.npub }),
            );
        }

        // Search by purpose string with optional index hint.
        let desired_index = index_hint.unwrap_or(0);
        if let Some(idx) = self
            .derived
            .iter()
            .position(|e| e.identity.purpose == target && e.identity.index == desired_index)
        {
            self.active = Some(idx);
            return Nip46Response::ok(
                request_id,
                json!({ "npub": self.derived[idx].identity.npub }),
            );
        }

        Nip46Response::err(
            request_id,
            format!("heartwood_switch: identity '{target}' not found in cache"),
        )
    }

    /// Create a linkage proof between the master root and the active derived identity.
    ///
    /// Params: `[proof_type?: "blind" | "full"]` — defaults to `"blind"`.
    fn handle_create_proof(
        &self,
        request_id: &str,
        params: Vec<serde_json::Value>,
    ) -> Nip46Response {
        let proof_type = params.first().and_then(|v| v.as_str()).unwrap_or("blind");

        let child = match self.active {
            Some(idx) => &self.derived[idx].identity,
            None => {
                return Nip46Response::err(
                    request_id,
                    "heartwood_create_proof: no active identity; call heartwood_switch first",
                )
            }
        };

        let root = self.root.as_ref().expect("root checked");

        let result = if proof_type == "full" {
            create_full_proof(root, child)
        } else {
            create_blind_proof(root, child)
        };

        match result {
            Ok(proof) => {
                let mut obj = json!({
                    "masterPubkey": proof.master_pubkey,
                    "childPubkey": proof.child_pubkey,
                    "attestation": proof.attestation,
                    "signature": proof.signature,
                });
                if let Some(p) = proof.purpose {
                    obj["purpose"] = json!(p);
                }
                if let Some(i) = proof.index {
                    obj["index"] = json!(i);
                }
                Nip46Response::ok(request_id, obj)
            }
            Err(e) => Nip46Response::err(request_id, format!("heartwood_create_proof: {e}")),
        }
    }

    /// Verify a linkage proof supplied by the client.
    ///
    /// Params: `[proof_json: string | object]`
    fn handle_verify_proof(
        &self,
        request_id: &str,
        params: Vec<serde_json::Value>,
    ) -> Nip46Response {
        let raw = params.into_iter().next().unwrap_or(serde_json::Value::Null);

        let proof_val: serde_json::Value = if raw.is_string() {
            match serde_json::from_str(raw.as_str().unwrap()) {
                Ok(v) => v,
                Err(e) => {
                    return Nip46Response::err(
                        request_id,
                        format!("heartwood_verify_proof: invalid proof JSON: {e}"),
                    )
                }
            }
        } else if raw.is_object() {
            raw
        } else {
            return Nip46Response::err(
                request_id,
                "heartwood_verify_proof: missing proof parameter",
            );
        };

        let master_pubkey = match proof_val["masterPubkey"].as_str() {
            Some(s) => s.to_string(),
            None => {
                return Nip46Response::err(
                    request_id,
                    "heartwood_verify_proof: missing 'masterPubkey'",
                )
            }
        };
        let child_pubkey = match proof_val["childPubkey"].as_str() {
            Some(s) => s.to_string(),
            None => {
                return Nip46Response::err(
                    request_id,
                    "heartwood_verify_proof: missing 'childPubkey'",
                )
            }
        };
        let attestation = match proof_val["attestation"].as_str() {
            Some(s) => s.to_string(),
            None => {
                return Nip46Response::err(
                    request_id,
                    "heartwood_verify_proof: missing 'attestation'",
                )
            }
        };
        let signature = match proof_val["signature"].as_str() {
            Some(s) => s.to_string(),
            None => {
                return Nip46Response::err(
                    request_id,
                    "heartwood_verify_proof: missing 'signature'",
                )
            }
        };

        let proof = LinkageProof {
            master_pubkey,
            child_pubkey,
            purpose: proof_val["purpose"].as_str().map(str::to_string),
            index: proof_val["index"].as_u64().map(|i| i as u32),
            attestation,
            signature,
        };

        match verify_proof(&proof) {
            Ok(valid) => Nip46Response::ok(request_id, json!(valid)),
            Err(e) => Nip46Response::err(request_id, format!("heartwood_verify_proof: {e}")),
        }
    }

    /// Recover identities by scanning derived keys across the default purposes.
    ///
    /// Params: `[lookahead?: number]` — number of indices per purpose (default 20).
    ///
    /// Default purposes: `["messaging", "signing", "social", "commerce"]`.
    fn handle_recover(
        &mut self,
        request_id: &str,
        params: Vec<serde_json::Value>,
    ) -> Nip46Response {
        let scan_range = params.first().and_then(|v| v.as_u64()).map(|i| i as u32);

        let default_purposes: Vec<String> =
            vec!["messaging".into(), "signing".into(), "social".into(), "commerce".into()];

        let root = self.root.as_ref().expect("root checked");

        match recover(root, &default_purposes, scan_range) {
            Ok(results) => {
                // Build the output list whilst still borrowing results, then
                // consume results to push identities into the derived cache.
                let mut output = Vec::new();
                for identities in results.values() {
                    for identity in identities {
                        output.push(json!({
                            "npub": identity.npub,
                            "purpose": identity.purpose,
                            "index": identity.index,
                        }));
                    }
                }

                for (_purpose, identities) in results {
                    for identity in identities {
                        self.derived.push(DerivedEntry { identity, persona_name: None });
                    }
                }

                Nip46Response::ok(request_id, json!(output))
            }
            Err(e) => Nip46Response::err(request_id, format!("heartwood_recover: {e}")),
        }
    }

    // -------------------------------------------------------------------------
    // Test helpers
    // -------------------------------------------------------------------------

    /// Grant all privileged Heartwood methods to a client, creating a session
    /// if one does not already exist.
    ///
    /// This is a test helper that bypasses the normal opt-in flow so
    /// tests can exercise extension methods without permission scaffolding.
    /// It should not be called in production code.
    /// Restrict which event kinds a client may sign.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn restrict_signing_kinds(&mut self, client_pubkey: &str, kinds: std::collections::HashSet<u32>) {
        let mut sessions = self.lock_sessions();
        if let Some(session) = sessions.get_mut(client_pubkey) {
            session.permissions.allowed_kinds = Some(kinds);
        }
    }

    #[cfg(any(test, feature = "test-helpers"))]
    pub fn grant_all_permissions(&mut self, client_pubkey: &str) {
        let privileged: std::collections::HashSet<String> = [
            "heartwood_derive",
            "heartwood_derive_persona",
            "heartwood_switch",
            "heartwood_create_proof",
            "heartwood_recover",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        let mut sessions = self.lock_sessions();

        if let Some(session) = sessions.get_mut(client_pubkey) {
            session.permissions.allowed_methods = Some(privileged);
        } else {
            let mut session = ClientSession::new(client_pubkey)
                .expect("test client pubkey must be valid 64-char hex");
            session.permissions.allowed_methods = Some(privileged);
            sessions.add(session);
        }
    }
}

/// Extract the event `kind` from sign_event params, if present.
///
/// Handles both JSON string and inline object formats.
fn extract_event_kind(params: &[serde_json::Value]) -> Option<u32> {
    let raw = params.first()?;
    let template = if raw.is_string() {
        serde_json::from_str(raw.as_str()?).ok()?
    } else if raw.is_object() {
        raw.clone()
    } else {
        return None;
    };
    template["kind"].as_u64().map(|k| k as u32)
}

impl Default for HeartwoodServer {
    fn default() -> Self {
        Self::new()
    }
}
