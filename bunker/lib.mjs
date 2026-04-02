/**
 * Pure logic functions extracted from the Heartwood bunker for testability.
 * No I/O, no global state — all state is passed as parameters.
 */

/**
 * Parse --authorized-keys from CLI argv.
 * @param {string[]} argv - process.argv or equivalent
 * @returns {{ keys: Set<string>, warnings: string[] }}
 */
export function parseAuthorizedKeys(argv) {
  const keys = new Set()
  const warnings = []
  const idx = argv.indexOf('--authorized-keys')
  if (idx === -1 || !argv[idx + 1]) return { keys, warnings }

  for (const k of argv[idx + 1].split(',')) {
    const hex = k.trim()
    if (/^[0-9a-f]{64}$/.test(hex)) {
      keys.add(hex)
    } else if (hex.length > 0) {
      warnings.push(hex)
    }
  }
  return { keys, warnings }
}

/**
 * Check if a client pubkey is in the approved clients map.
 * @param {string} pubkey
 * @param {Record<string, object>} approvedClients
 * @returns {boolean}
 */
export function isApproved(pubkey, approvedClients) {
  return Object.prototype.hasOwnProperty.call(approvedClients, pubkey)
}

/**
 * Check if a signing kind is allowed for a given client.
 * Returns true if no restriction exists or the kind is in the allowlist.
 * @param {string} pubkey
 * @param {number} kind
 * @param {Record<string, object>} approvedClients
 * @returns {boolean}
 */
export function isKindAllowed(pubkey, kind, approvedClients) {
  const client = approvedClients[pubkey]
  if (!client || !client.allowedKinds) return true
  return client.allowedKinds.includes(kind)
}

/**
 * Record a pending client connection attempt.
 * Mutates pendingClients in place. Returns true if this is a new entry.
 * @param {string} pubkey
 * @param {Record<string, object>} pendingClients
 * @param {number} [maxPending=200]
 * @returns {boolean} true if new entry was created
 */
export function recordPending(pubkey, pendingClients, maxPending = 200) {
  const now = new Date().toISOString()
  if (pendingClients[pubkey]) {
    pendingClients[pubkey].lastSeen = now
    pendingClients[pubkey].attempts += 1
    return false
  }

  // Cap pending entries to prevent unbounded growth from rotating pubkeys
  const keys = Object.keys(pendingClients)
  if (keys.length >= maxPending) {
    // Evict oldest entry
    let oldestKey = keys[0]
    let oldestTime = pendingClients[oldestKey].firstSeen
    for (const k of keys) {
      if (pendingClients[k].firstSeen < oldestTime) {
        oldestTime = pendingClients[k].firstSeen
        oldestKey = k
      }
    }
    delete pendingClients[oldestKey]
  }

  pendingClients[pubkey] = { firstSeen: now, lastSeen: now, attempts: 1 }
  return true
}

/**
 * Try to auto-approve a client from the authorized keys list.
 * Mutates approvedClients in place if the client is authorized and not yet approved.
 * @param {string} clientPk
 * @param {Set<string>} authorizedKeys
 * @param {Record<string, object>} approvedClients
 * @returns {boolean} true if the client was newly auto-approved
 */
export function tryAutoApprove(clientPk, authorizedKeys, approvedClients) {
  if (!authorizedKeys.has(clientPk)) return false
  if (isApproved(clientPk, approvedClients)) return false
  approvedClients[clientPk] = { approvedAt: new Date().toISOString() }
  return true
}

/**
 * Check rate limit for a client (sliding window).
 * Mutates rateBuckets in place.
 * @param {string} pubkey
 * @param {Map<string, number[]>} rateBuckets
 * @param {Record<string, object>} approvedClients
 * @param {number} [defaultLimit=30]
 * @param {number} [windowMs=60000]
 * @param {number} [now=Date.now()] - injectable for testing
 * @returns {boolean} true if the request should be allowed
 */
export function checkRateLimit(pubkey, rateBuckets, approvedClients, defaultLimit = 30, windowMs = 60_000, now = Date.now()) {
  let timestamps = rateBuckets.get(pubkey)
  if (!timestamps) {
    timestamps = []
    rateBuckets.set(pubkey, timestamps)
  }

  // Prune entries older than the window
  const cutoff = now - windowMs
  while (timestamps.length > 0 && timestamps[0] < cutoff) {
    timestamps.shift()
  }

  // Per-client limit from clients.json, or default
  const client = approvedClients[pubkey]
  const limit = client?.rateLimit ?? defaultLimit

  if (timestamps.length >= limit) {
    return false
  }

  timestamps.push(now)
  return true
}
