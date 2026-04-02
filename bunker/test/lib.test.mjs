import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import {
  parseAuthorizedKeys,
  isApproved,
  isKindAllowed,
  recordPending,
  tryAutoApprove,
  checkRateLimit,
} from '../lib.mjs'

// Helpers — 64-char hex pubkeys
const PK_A = 'a'.repeat(64)
const PK_B = 'b'.repeat(64)
const PK_C = 'c'.repeat(64)

// ---------- parseAuthorizedKeys ----------

describe('parseAuthorizedKeys', () => {
  it('returns empty set when flag is absent', () => {
    const { keys, warnings } = parseAuthorizedKeys(['node', 'index.mjs'])
    assert.equal(keys.size, 0)
    assert.equal(warnings.length, 0)
  })

  it('returns empty set when flag has no value', () => {
    const { keys } = parseAuthorizedKeys(['node', 'index.mjs', '--authorized-keys'])
    assert.equal(keys.size, 0)
  })

  it('parses a single valid key', () => {
    const { keys, warnings } = parseAuthorizedKeys([
      'node', 'index.mjs', '--authorized-keys', PK_A,
    ])
    assert.equal(keys.size, 1)
    assert.ok(keys.has(PK_A))
    assert.equal(warnings.length, 0)
  })

  it('parses multiple comma-separated keys', () => {
    const { keys } = parseAuthorizedKeys([
      'node', 'index.mjs', '--authorized-keys', `${PK_A},${PK_B},${PK_C}`,
    ])
    assert.equal(keys.size, 3)
    assert.ok(keys.has(PK_A))
    assert.ok(keys.has(PK_B))
    assert.ok(keys.has(PK_C))
  })

  it('deduplicates identical keys', () => {
    const { keys } = parseAuthorizedKeys([
      'node', 'index.mjs', '--authorized-keys', `${PK_A},${PK_A}`,
    ])
    assert.equal(keys.size, 1)
  })

  it('trims whitespace around keys', () => {
    const { keys } = parseAuthorizedKeys([
      'node', 'index.mjs', '--authorized-keys', ` ${PK_A} , ${PK_B} `,
    ])
    assert.equal(keys.size, 2)
    assert.ok(keys.has(PK_A))
    assert.ok(keys.has(PK_B))
  })

  it('rejects uppercase hex', () => {
    const upper = 'A'.repeat(64)
    const { keys, warnings } = parseAuthorizedKeys([
      'node', 'index.mjs', '--authorized-keys', upper,
    ])
    assert.equal(keys.size, 0)
    assert.deepEqual(warnings, [upper])
  })

  it('rejects wrong-length hex', () => {
    const short = 'ab'.repeat(16) // 32 chars
    const { keys, warnings } = parseAuthorizedKeys([
      'node', 'index.mjs', '--authorized-keys', short,
    ])
    assert.equal(keys.size, 0)
    assert.deepEqual(warnings, [short])
  })

  it('rejects non-hex characters', () => {
    const bad = 'g'.repeat(64)
    const { keys, warnings } = parseAuthorizedKeys([
      'node', 'index.mjs', '--authorized-keys', bad,
    ])
    assert.equal(keys.size, 0)
    assert.deepEqual(warnings, [bad])
  })

  it('returns valid keys alongside warnings for invalid ones', () => {
    const bad = 'xyz'
    const { keys, warnings } = parseAuthorizedKeys([
      'node', 'index.mjs', '--authorized-keys', `${PK_A},${bad},${PK_B}`,
    ])
    assert.equal(keys.size, 2)
    assert.ok(keys.has(PK_A))
    assert.ok(keys.has(PK_B))
    assert.deepEqual(warnings, [bad])
  })

  it('ignores empty segments from trailing/double commas', () => {
    const { keys, warnings } = parseAuthorizedKeys([
      'node', 'index.mjs', '--authorized-keys', `${PK_A},,${PK_B},`,
    ])
    assert.equal(keys.size, 2)
    assert.equal(warnings.length, 0)
  })

  it('does not consume unrelated flags as the value', () => {
    const { keys } = parseAuthorizedKeys([
      'node', 'index.mjs', '--authorized-keys', '--other-flag',
    ])
    // '--other-flag' is not valid hex, so the set should be empty
    assert.equal(keys.size, 0)
  })
})

// ---------- isApproved ----------

describe('isApproved', () => {
  it('returns true for an approved client', () => {
    const clients = { [PK_A]: { approvedAt: '2024-01-01' } }
    assert.equal(isApproved(PK_A, clients), true)
  })

  it('returns false for an unknown client', () => {
    assert.equal(isApproved(PK_A, {}), false)
  })

  it('returns false for empty clients map', () => {
    assert.equal(isApproved(PK_A, {}), false)
  })

  it('does not match inherited prototype properties', () => {
    const clients = Object.create({ [PK_A]: true })
    assert.equal(isApproved(PK_A, clients), false)
  })

  it('handles client with falsy value', () => {
    // Even a null/0 value should count as approved (key exists)
    const clients = { [PK_A]: null }
    assert.equal(isApproved(PK_A, clients), true)
  })
})

// ---------- isKindAllowed ----------

describe('isKindAllowed', () => {
  it('allows any kind when client has no restriction', () => {
    const clients = { [PK_A]: { approvedAt: '2024-01-01' } }
    assert.equal(isKindAllowed(PK_A, 1, clients), true)
    assert.equal(isKindAllowed(PK_A, 30023, clients), true)
  })

  it('allows kind in the allowlist', () => {
    const clients = { [PK_A]: { allowedKinds: [1, 7, 30023] } }
    assert.equal(isKindAllowed(PK_A, 1, clients), true)
    assert.equal(isKindAllowed(PK_A, 7, clients), true)
    assert.equal(isKindAllowed(PK_A, 30023, clients), true)
  })

  it('blocks kind not in the allowlist', () => {
    const clients = { [PK_A]: { allowedKinds: [1, 7] } }
    assert.equal(isKindAllowed(PK_A, 30023, clients), false)
    assert.equal(isKindAllowed(PK_A, 4, clients), false)
  })

  it('allows any kind for unknown client', () => {
    assert.equal(isKindAllowed(PK_A, 1, {}), true)
  })

  it('allows any kind when allowedKinds is empty array', () => {
    const clients = { [PK_A]: { allowedKinds: [] } }
    assert.equal(isKindAllowed(PK_A, 1, clients), false)
  })
})

// ---------- recordPending ----------

describe('recordPending', () => {
  let pending

  beforeEach(() => {
    pending = {}
  })

  it('creates a new entry and returns true', () => {
    const isNew = recordPending(PK_A, pending)
    assert.equal(isNew, true)
    assert.ok(pending[PK_A])
    assert.equal(pending[PK_A].attempts, 1)
    assert.equal(pending[PK_A].firstSeen, pending[PK_A].lastSeen)
  })

  it('increments attempts for existing entry and returns false', () => {
    recordPending(PK_A, pending)
    const firstSeen = pending[PK_A].firstSeen

    const isNew = recordPending(PK_A, pending)
    assert.equal(isNew, false)
    assert.equal(pending[PK_A].attempts, 2)
    assert.equal(pending[PK_A].firstSeen, firstSeen) // unchanged
  })

  it('evicts oldest entry when at capacity', () => {
    // Fill to capacity (maxPending=3 for test)
    pending['oldest'] = { firstSeen: '2024-01-01T00:00:00.000Z', lastSeen: '2024-01-01', attempts: 1 }
    pending['middle'] = { firstSeen: '2024-06-01T00:00:00.000Z', lastSeen: '2024-06-01', attempts: 1 }
    pending['newest'] = { firstSeen: '2024-12-01T00:00:00.000Z', lastSeen: '2024-12-01', attempts: 1 }

    const isNew = recordPending(PK_A, pending, 3)
    assert.equal(isNew, true)
    assert.ok(!pending['oldest'], 'oldest entry should be evicted')
    assert.ok(pending['middle'], 'middle entry should survive')
    assert.ok(pending['newest'], 'newest entry should survive')
    assert.ok(pending[PK_A], 'new entry should be added')
  })

  it('correctly identifies oldest among multiple entries', () => {
    pending['z'] = { firstSeen: '2024-03-01T00:00:00.000Z', lastSeen: '2024-03-01', attempts: 1 }
    pending['a'] = { firstSeen: '2024-01-01T00:00:00.000Z', lastSeen: '2024-12-01', attempts: 99 }
    // 'a' has oldest firstSeen despite being seen recently and having many attempts
    recordPending(PK_A, pending, 2)
    assert.ok(!pending['a'], 'entry with oldest firstSeen should be evicted')
    assert.ok(pending['z'])
    assert.ok(pending[PK_A])
  })

  it('respects default maxPending of 200', () => {
    // Fill 200 entries
    for (let i = 0; i < 200; i++) {
      const pk = i.toString(16).padStart(64, '0')
      pending[pk] = { firstSeen: `2024-01-${String(i + 1).padStart(2, '0')}T00:00:00.000Z`, lastSeen: '2024-01-01', attempts: 1 }
    }
    assert.equal(Object.keys(pending).length, 200)

    recordPending(PK_A, pending)
    assert.equal(Object.keys(pending).length, 200) // evicted one, added one
    assert.ok(pending[PK_A])
  })
})

// ---------- tryAutoApprove ----------

describe('tryAutoApprove', () => {
  it('approves an authorized client that is not yet approved', () => {
    const authorized = new Set([PK_A])
    const approved = {}

    const result = tryAutoApprove(PK_A, authorized, approved)
    assert.equal(result, true)
    assert.ok(approved[PK_A])
    assert.ok(approved[PK_A].approvedAt)
  })

  it('returns false for already-approved authorized client', () => {
    const authorized = new Set([PK_A])
    const approved = { [PK_A]: { approvedAt: '2024-01-01' } }

    const result = tryAutoApprove(PK_A, authorized, approved)
    assert.equal(result, false)
    assert.equal(approved[PK_A].approvedAt, '2024-01-01') // unchanged
  })

  it('returns false for non-authorized client', () => {
    const authorized = new Set([PK_A])
    const approved = {}

    const result = tryAutoApprove(PK_B, authorized, approved)
    assert.equal(result, false)
    assert.ok(!approved[PK_B])
  })

  it('returns false when authorizedKeys is empty', () => {
    const result = tryAutoApprove(PK_A, new Set(), {})
    assert.equal(result, false)
  })

  it('does not modify approvedClients when not authorized', () => {
    const approved = { [PK_B]: { approvedAt: '2024-01-01' } }
    const approvedCopy = JSON.parse(JSON.stringify(approved))

    tryAutoApprove(PK_C, new Set([PK_A]), approved)
    assert.deepEqual(approved, approvedCopy)
  })

  it('sets a valid ISO timestamp on approval', () => {
    const authorized = new Set([PK_A])
    const approved = {}

    tryAutoApprove(PK_A, authorized, approved)
    const ts = new Date(approved[PK_A].approvedAt)
    assert.ok(!isNaN(ts.getTime()), 'approvedAt should be a valid date')
  })

  it('only adds the specific authorized client, not others', () => {
    const authorized = new Set([PK_A, PK_B])
    const approved = {}

    tryAutoApprove(PK_A, authorized, approved)
    assert.ok(approved[PK_A])
    assert.ok(!approved[PK_B], 'PK_B should not be auto-approved yet')
  })
})

// ---------- checkRateLimit ----------

describe('checkRateLimit', () => {
  let buckets, clients

  beforeEach(() => {
    buckets = new Map()
    clients = {}
  })

  it('allows first request', () => {
    assert.equal(checkRateLimit(PK_A, buckets, clients, 30, 60_000, 1000), true)
  })

  it('allows requests up to the limit', () => {
    const now = 10_000
    for (let i = 0; i < 29; i++) {
      checkRateLimit(PK_A, buckets, clients, 30, 60_000, now + i)
    }
    // 30th request (at the limit)
    assert.equal(checkRateLimit(PK_A, buckets, clients, 30, 60_000, now + 29), true)
  })

  it('blocks when limit is exceeded', () => {
    const now = 10_000
    for (let i = 0; i < 30; i++) {
      checkRateLimit(PK_A, buckets, clients, 30, 60_000, now + i)
    }
    // 31st request — should be blocked
    assert.equal(checkRateLimit(PK_A, buckets, clients, 30, 60_000, now + 30), false)
  })

  it('allows again after window expires', () => {
    const now = 10_000
    for (let i = 0; i < 30; i++) {
      checkRateLimit(PK_A, buckets, clients, 30, 60_000, now)
    }
    assert.equal(checkRateLimit(PK_A, buckets, clients, 30, 60_000, now + 1), false)

    // After window expires
    assert.equal(checkRateLimit(PK_A, buckets, clients, 30, 60_000, now + 60_001), true)
  })

  it('uses per-client rateLimit from approvedClients', () => {
    clients[PK_A] = { rateLimit: 2 }
    const now = 10_000

    assert.equal(checkRateLimit(PK_A, buckets, clients, 30, 60_000, now), true)
    assert.equal(checkRateLimit(PK_A, buckets, clients, 30, 60_000, now + 1), true)
    assert.equal(checkRateLimit(PK_A, buckets, clients, 30, 60_000, now + 2), false) // 3rd request, limit is 2
  })

  it('tracks clients independently', () => {
    const now = 10_000
    // Fill PK_A to limit
    for (let i = 0; i < 3; i++) {
      checkRateLimit(PK_A, buckets, clients, 3, 60_000, now + i)
    }
    assert.equal(checkRateLimit(PK_A, buckets, clients, 3, 60_000, now + 3), false)

    // PK_B should still be fine
    assert.equal(checkRateLimit(PK_B, buckets, clients, 3, 60_000, now + 3), true)
  })

  it('prunes expired entries from the window', () => {
    const now = 10_000
    // Add entries at time 10000
    for (let i = 0; i < 5; i++) {
      checkRateLimit(PK_A, buckets, clients, 5, 1_000, now)
    }
    assert.equal(checkRateLimit(PK_A, buckets, clients, 5, 1_000, now + 1), false)

    // At now + 1001, all old entries are expired
    assert.equal(checkRateLimit(PK_A, buckets, clients, 5, 1_000, now + 1_001), true)
    // Bucket should have been pruned — only the new entry remains
    assert.equal(buckets.get(PK_A).length, 1)
  })

  it('handles limit of 1', () => {
    clients[PK_A] = { rateLimit: 1 }
    const now = 10_000
    assert.equal(checkRateLimit(PK_A, buckets, clients, 30, 60_000, now), true)
    assert.equal(checkRateLimit(PK_A, buckets, clients, 30, 60_000, now + 1), false)
  })

  it('handles limit of 0 — blocks everything', () => {
    clients[PK_A] = { rateLimit: 0 }
    assert.equal(checkRateLimit(PK_A, buckets, clients, 30, 60_000, 10_000), false)
  })
})

// ---------- Integration-style: full connect flow ----------

describe('connect flow integration', () => {
  it('authorized client goes through full approval flow', () => {
    const authorized = new Set([PK_A])
    const approved = {}
    const pending = {}

    // Client connects — not yet approved
    assert.equal(isApproved(PK_A, approved), false)

    // Try auto-approve — should succeed
    assert.equal(tryAutoApprove(PK_A, authorized, approved), true)
    assert.equal(isApproved(PK_A, approved), true)

    // Subsequent connect — already approved, tryAutoApprove returns false (no-op)
    assert.equal(tryAutoApprove(PK_A, authorized, approved), false)
    assert.equal(isApproved(PK_A, approved), true)

    // Should pass rate limit
    const buckets = new Map()
    assert.equal(checkRateLimit(PK_A, buckets, approved), true)

    // No pending entries created
    assert.equal(Object.keys(pending).length, 0)
  })

  it('unauthorised client goes through pending flow', () => {
    const authorized = new Set([PK_A]) // PK_B is not authorized
    const approved = {}
    const pending = {}

    assert.equal(isApproved(PK_B, approved), false)
    assert.equal(tryAutoApprove(PK_B, authorized, approved), false)
    assert.equal(isApproved(PK_B, approved), false)

    // Falls through to pending
    const isNew = recordPending(PK_B, pending)
    assert.equal(isNew, true)
    assert.ok(pending[PK_B])
  })

  it('mixed clients: authorised auto-approved, others pending', () => {
    const authorized = new Set([PK_A])
    const approved = {}
    const pending = {}

    // PK_A connects — auto-approved
    tryAutoApprove(PK_A, authorized, approved)
    assert.equal(isApproved(PK_A, approved), true)

    // PK_B connects — not authorized, goes to pending
    assert.equal(tryAutoApprove(PK_B, authorized, approved), false)
    recordPending(PK_B, pending)
    assert.ok(pending[PK_B])
    assert.ok(!approved[PK_B])

    // PK_A can sign, PK_B cannot
    assert.equal(isApproved(PK_A, approved), true)
    assert.equal(isApproved(PK_B, approved), false)
  })

  it('auto-approved client respects kind restrictions after manual update', () => {
    const authorized = new Set([PK_A])
    const approved = {}

    // Auto-approve
    tryAutoApprove(PK_A, authorized, approved)

    // Admin later restricts kinds (simulates editing clients.json)
    approved[PK_A].allowedKinds = [1, 7]

    assert.equal(isKindAllowed(PK_A, 1, approved), true)
    assert.equal(isKindAllowed(PK_A, 7, approved), true)
    assert.equal(isKindAllowed(PK_A, 30023, approved), false)
  })

  it('auto-approved client respects rate limits', () => {
    const authorized = new Set([PK_A])
    const approved = {}
    const buckets = new Map()

    tryAutoApprove(PK_A, authorized, approved)
    approved[PK_A].rateLimit = 2

    const now = 10_000
    assert.equal(checkRateLimit(PK_A, buckets, approved, 30, 60_000, now), true)
    assert.equal(checkRateLimit(PK_A, buckets, approved, 30, 60_000, now + 1), true)
    assert.equal(checkRateLimit(PK_A, buckets, approved, 30, 60_000, now + 2), false)
  })
})
