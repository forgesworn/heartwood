/**
 * Heartwood NIP-46 Bunker — remote signing sidecar.
 *
 * Standalone daemon that holds the user's nsec and responds to signing
 * requests from NIP-46 clients (Amber, NostrHub, etc.) over Nostr relays.
 * Clients never see the nsec — only signatures and public keys leave the Pi.
 *
 * Reads secrets from /var/lib/heartwood/ (shared with heartwood-device).
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { writeFile } from 'node:fs/promises'
import { getConversationKey, encrypt, decrypt } from 'nostr-tools/nip44'
import { finalizeEvent, getPublicKey, generateSecretKey } from 'nostr-tools/pure'
import { decode as nip19decode } from 'nostr-tools/nip19'
import { SimplePool } from 'nostr-tools/pool'
import WebSocket from 'ws'
import { fromNsec } from 'nsec-tree/core'
import { fromMnemonic } from 'nsec-tree/mnemonic'
import { derivePersona } from 'nsec-tree/persona'
import { bytesToHex } from 'nostr-tools/utils'
import {
  parseAuthorizedKeys,
  parseAuthorizedKeysEnv,
  isApproved,
  isKindAllowed,
  isValidHexPubkey,
  recordPending,
  tryAutoApprove,
  checkRateLimit,
  resolveDataDir,
} from './lib.mjs'

globalThis.WebSocket = WebSocket

// --- 0. Parse CLI flags and env vars ---

const { keys: cliKeys, warnings: cliWarnings } = parseAuthorizedKeys(process.argv)
const { keys: envKeys, warnings: envWarnings } = parseAuthorizedKeysEnv(process.env)

// CLI keys take precedence: if --authorized-keys is provided, use only those.
// Otherwise fall back to HEARTWOOD_AUTHORIZED_KEYS env var.
const authorizedKeys = cliKeys.size > 0 ? cliKeys : envKeys
const akWarnings = cliKeys.size > 0 ? cliWarnings : envWarnings

for (const w of akWarnings) {
  console.warn(`WARN: ignoring invalid authorized key: ${w}`)
}
if (authorizedKeys.size > 0) {
  console.log(`Authorized keys: ${authorizedKeys.size} client(s) will be auto-approved`)
}

const DATA_DIR = resolveDataDir(process.env)
const DEFAULT_RELAYS = [
  'wss://relay.damus.io',
  'wss://nos.lol',
  'wss://relay.trotters.cc',
]

// --- 1. Read nsec from master.secret ---
//
// The master.secret file may be encrypted (AES-256-GCM, first byte 0x01).
// When encrypted, the Rust device writes the decrypted payload to a runtime
// path after PIN unlock. The bunker reads from the runtime path first, then
// falls back to the primary path (for legacy unencrypted installations).

const secretPath = `${DATA_DIR}/master.secret`
const runtimePayloadPath = `${DATA_DIR}/master.payload`

function readSecretPayload() {
  // Try runtime path first (written by heartwood-device after PIN unlock)
  if (existsSync(runtimePayloadPath)) {
    return readFileSync(runtimePayloadPath, 'utf-8').trim()
  }

  if (!existsSync(secretPath)) {
    console.error('FATAL: master.secret not found — is heartwood-device configured?')
    process.exit(1)
  }

  const raw = readFileSync(secretPath)
  // Encrypted files start with version byte 0x01 or 0x02 (not valid UTF-8 text prefix)
  if (raw[0] === 0x01 || raw[0] === 0x02) {
    console.error('FATAL: master.secret is encrypted but device is locked')
    console.error('       Unlock the device via the web UI, then restart the bunker.')
    process.exit(1)
  }

  return raw.toString('utf-8').trim()
}

const secretPayload = readSecretPayload()

// Parse the payload — supports bunker, tree-mnemonic, and tree-nsec modes
let userSk, userPk, treeRoot

if (secretPayload.startsWith('bunker:')) {
  const nsec = secretPayload.slice('bunker:'.length)
  const decoded = nip19decode(nsec)
  if (decoded.type !== 'nsec') {
    console.error('FATAL: invalid nsec in master.secret')
    process.exit(1)
  }
  userSk = decoded.data
  userPk = getPublicKey(userSk)
  treeRoot = fromNsec(new Uint8Array(userSk))
} else if (secretPayload.startsWith('tree-mnemonic:')) {
  // Format: "tree-mnemonic:{passphrase}:{mnemonic}" or "tree-mnemonic::{mnemonic}"
  const rest = secretPayload.slice('tree-mnemonic:'.length)
  const colonIdx = rest.indexOf(':')
  const passphrase = colonIdx > 0 ? rest.slice(0, colonIdx) : undefined
  const mnemonic = colonIdx >= 0 ? rest.slice(colonIdx + 1) : rest
  treeRoot = fromMnemonic(mnemonic, passphrase)
  // Derive master signing key via BIP-32 (same path as heartwood-core)
  const { mnemonicToSeedSync } = await import('@scure/bip39')
  const { HDKey } = await import('@scure/bip32')
  const seed = mnemonicToSeedSync(mnemonic, passphrase || '')
  const master = HDKey.fromMasterSeed(seed)
  const child = master.derive("m/44'/1237'/727'/0'/0'")
  userSk = child.privateKey
  userPk = getPublicKey(userSk)
} else if (secretPayload.startsWith('tree-nsec:')) {
  const nsec = secretPayload.slice('tree-nsec:'.length)
  const decoded = nip19decode(nsec)
  if (decoded.type !== 'nsec') {
    console.error('FATAL: invalid nsec in master.secret (tree-nsec mode)')
    process.exit(1)
  }
  treeRoot = fromNsec(new Uint8Array(decoded.data))
  // The tree-nsec master key is HMAC-SHA256(nsec_bytes, "nsec-tree-root")
  // fromNsec already computes this — masterPubkey is the pubkey of that derived key
  // We need the raw secret for signing, so derive it ourselves
  const { hmac } = await import('@noble/hashes/hmac')
  const { sha256 } = await import('@noble/hashes/sha256')
  userSk = hmac(sha256, new Uint8Array(decoded.data), new TextEncoder().encode('nsec-tree-root'))
  userPk = getPublicKey(userSk)
} else {
  console.error('FATAL: unrecognised master.secret format (expected bunker:, tree-mnemonic:, or tree-nsec:)')
  process.exit(1)
}
const personasPath = `${DATA_DIR}/personas.json`

/**
 * Persisted persona records. Array of { name, pubkey, purpose, index }.
 * The private keys are not stored — they're re-derived on demand from the
 * tree root.
 */
let personas = loadJson(personasPath, [])

/**
 * Active signing identity. Null means the master key (userSk/userPk).
 * When set, points to a persona entry whose key is used for signing.
 */
let activePersonaPubkey = null

// Restore active persona from config
const personaConfigPath = `${DATA_DIR}/active-persona.json`
const personaConfig = loadJson(personaConfigPath, {})
if (personaConfig.activePubkey) {
  activePersonaPubkey = personaConfig.activePubkey
}

/**
 * Get the currently active signing key and pubkey.
 * When a persona is active, the private key is re-derived on each call.
 * Call `releaseKey(result)` after use to zero derived key material.
 */
function getActiveSigningKey() {
  if (!activePersonaPubkey) {
    return { sk: userSk, pk: userPk, ephemeral: false }
  }
  const persona = personas.find((p) => p.pubkey === activePersonaPubkey)
  if (!persona) {
    // Persona was removed — fall back to master
    activePersonaPubkey = null
    return { sk: userSk, pk: userPk, ephemeral: false }
  }
  // Re-derive the private key from the tree root
  const derived = derivePersona(treeRoot, persona.name, persona.index)
  return {
    sk: derived.identity.privateKey,
    pk: bytesToHex(derived.identity.publicKey),
    ephemeral: true,
  }
}

/** Zero ephemeral key material after use. No-op for the persistent master key. */
function releaseKey(active) {
  if (active.ephemeral && active.sk instanceof Uint8Array) {
    active.sk.fill(0)
  }
}

// --- 2. Read relay list from config.json ---

const configPath = `${DATA_DIR}/config.json`

/** Read the current relay list from config.json, falling back to defaults. */
function loadRelays() {
  if (existsSync(configPath)) {
    try {
      const config = JSON.parse(readFileSync(configPath, 'utf-8'))
      if (Array.isArray(config.relays) && config.relays.length > 0) {
        return config.relays
      }
    } catch {
      console.warn('WARN: could not parse config.json, using default relays')
    }
  }
  return DEFAULT_RELAYS
}

let relays = loadRelays()

// --- 2b. Client allowlist ---

const clientsPath = `${DATA_DIR}/clients.json`
const pendingClientsPath = `${DATA_DIR}/pending-clients.json`

/** Load a JSON file or return a default value. */
function loadJson(path, fallback) {
  if (!existsSync(path)) return fallback
  try {
    return JSON.parse(readFileSync(path, 'utf-8'))
  } catch {
    return fallback
  }
}

/** Save a JSON object to a file with restrictive permissions. */
function saveJson(path, data) {
  writeFileSync(path, JSON.stringify(data, null, 2), { mode: 0o600 })
}

/**
 * Approved clients. Object keyed by hex pubkey, value is an object with
 * optional `allowedKinds` (array of numbers) and `approvedAt` (ISO string).
 * Example: { "ab12...": { "allowedKinds": [1, 7], "approvedAt": "..." } }
 */
let approvedClients = loadJson(clientsPath, {})

/**
 * Pending clients awaiting approval. Object keyed by hex pubkey, value is
 * { firstSeen: ISO string, lastSeen: ISO string, attempts: number }.
 */
let pendingClients = loadJson(pendingClientsPath, {})

/** Maximum number of pending client entries to prevent disk-write DoS. */
const MAX_PENDING_CLIENTS = 200

// --- Per-client rate limiting (sliding window) ---

const DEFAULT_RATE_LIMIT = 30 // requests per minute
const RATE_WINDOW_MS = 60_000

/** Map of client pubkey → array of request timestamps (epoch ms). */
const rateBuckets = new Map()

/** Maximum number of rate bucket entries to prevent unbounded memory growth. */
const MAX_RATE_BUCKETS = 500

/** Periodic cleanup: remove expired rate bucket entries every 2 minutes. */
setInterval(() => {
  const cutoff = Date.now() - RATE_WINDOW_MS
  for (const [key, timestamps] of rateBuckets) {
    // Remove entries where all timestamps have expired
    if (timestamps.length === 0 || timestamps[timestamps.length - 1] < cutoff) {
      rateBuckets.delete(key)
    }
  }
  // If still over capacity, evict oldest entries
  if (rateBuckets.size > MAX_RATE_BUCKETS) {
    const toRemove = rateBuckets.size - MAX_RATE_BUCKETS
    const keys = rateBuckets.keys()
    for (let i = 0; i < toRemove; i++) {
      rateBuckets.delete(keys.next().value)
    }
  }
}, 120_000)

// --- 3. Load or generate bunker keypair ---

const bunkerKeyPath = `${DATA_DIR}/bunker.key`
let bunkerSk

if (existsSync(bunkerKeyPath)) {
  const hex = readFileSync(bunkerKeyPath, 'utf-8').trim()
  bunkerSk = Uint8Array.from(Buffer.from(hex, 'hex'))
} else {
  bunkerSk = generateSecretKey()
  const hex = Buffer.from(bunkerSk).toString('hex')
  writeFileSync(bunkerKeyPath, hex, { mode: 0o600 })
  console.log('Generated new bunker keypair')
}

const bunkerPk = getPublicKey(bunkerSk)

// --- 4. Connect to relays and subscribe ---

const pool = new SimplePool()

/** Active subscription handle, tracked so we can close it on relay change. */
let activeSub = null

/** Build a bunker URI from the bunker pubkey and relay list. */
function buildBunkerUri(relayList) {
  const params = relayList.map((r) => `relay=${encodeURIComponent(r)}`).join('&')
  return `bunker://${bunkerPk}?${params}`
}

/** Write the bunker URI file and subscribe to the given relays. */
function connectRelays(relayList) {
  // Close any existing subscription before reconnecting
  if (activeSub) {
    activeSub.close()
    activeSub = null
  }

  activeSub = pool.subscribe(
    relayList,
    { kinds: [24133], '#p': [bunkerPk] },
    {
      onevent: async (event) => {
        try {
          await handleRequest(event)
        } catch (e) {
          console.error(`Error handling request: ${e.message}`)
        }
      },
    },
  )

  // Recompute and persist the bunker URI
  const bunkerUri = buildBunkerUri(relayList)
  writeFileSync(`${DATA_DIR}/bunker-uri.txt`, bunkerUri, { mode: 0o600 })

  return bunkerUri
}

// --- 5. Write bunker URI and start initial subscription ---

const bunkerUri = connectRelays(relays)

console.log(`Bunker started`)
console.log(`  URI:     ${bunkerUri}`)
console.log(`  Signing: ${userPk.slice(0, 12)}...`)
console.log(`  Relays:  ${relays.join(', ')}`)
if (authorizedKeys.size > 0) {
  console.log(`  Auto-approve: ${[...authorizedKeys].map((k) => k.slice(0, 12) + '...').join(', ')}`)
}

// --- 6. Request handler ---

async function handleRequest(event) {
  const clientPk = event.pubkey
  const conversationKey = getConversationKey(bunkerSk, clientPk)

  let request
  try {
    const plaintext = decrypt(event.content, conversationKey)
    request = JSON.parse(plaintext)
  } catch {
    console.error('Failed to decrypt request')
    return
  }

  console.log(`Request ${request.id}: ${request.method} from ${clientPk.slice(0, 12)}...`)

  let result = ''
  let error

  // --- Client allowlist enforcement ---
  // connect, ping, and get_public_key are always allowed; signing and other methods require approval.
  if (request.method !== 'connect' && request.method !== 'ping' && request.method !== 'get_public_key') {
    if (!isApproved(clientPk, approvedClients)) {
      if (tryAutoApprove(clientPk, authorizedKeys, approvedClients)) {
        saveJson(clientsPath, approvedClients)
        console.log(`Auto-approved authorized client ${clientPk.slice(0, 12)}...`)
      } else {
        const isNew = recordPending(clientPk, pendingClients, MAX_PENDING_CLIENTS)
        if (isNew) console.log(`New pending client: ${clientPk.slice(0, 12)}...`)
        saveJson(pendingClientsPath, pendingClients)
        error = 'client not approved — ask the device owner to approve your pubkey'
        console.log(`Blocked unapproved client ${clientPk.slice(0, 12)}... (${request.method})`)

        // Send error response and return early
        const response = JSON.stringify({ id: request.id, result: '', error })
        const encrypted = encrypt(response, conversationKey)
        const responseEvent = finalizeEvent(
          {
            kind: 24133,
            created_at: Math.floor(Date.now() / 1000),
            tags: [['p', clientPk]],
            content: encrypted,
          },
          bunkerSk,
        )
        await Promise.any(pool.publish(relays, responseEvent))
        return
      }
    }
  }

  // --- Rate limit enforcement ---
  // connect, ping, and get_public_key are exempt; all other methods are rate-limited.
  if (request.method !== 'connect' && request.method !== 'ping' && request.method !== 'get_public_key') {
    if (!checkRateLimit(clientPk, rateBuckets, approvedClients, DEFAULT_RATE_LIMIT, RATE_WINDOW_MS)) {
      error = 'rate limit exceeded — try again shortly'
      console.log(`Rate-limited ${clientPk.slice(0, 12)}... (${request.method})`)

      const response = JSON.stringify({ id: request.id, result: '', error })
      const encrypted = encrypt(response, conversationKey)
      const responseEvent = finalizeEvent(
        {
          kind: 24133,
          created_at: Math.floor(Date.now() / 1000),
          tags: [['p', clientPk]],
          content: encrypted,
        },
        bunkerSk,
      )
      await Promise.any(pool.publish(relays, responseEvent))
      return
    }
  }

  switch (request.method) {
    case 'connect':
      if (!isApproved(clientPk, approvedClients)) {
        if (tryAutoApprove(clientPk, authorizedKeys, approvedClients)) {
          saveJson(clientsPath, approvedClients)
          console.log(`Auto-approved authorized client ${clientPk.slice(0, 12)}...`)
        } else {
          const isNew = recordPending(clientPk, pendingClients, MAX_PENDING_CLIENTS)
          if (isNew) console.log(`New pending client: ${clientPk.slice(0, 12)}...`)
          saveJson(pendingClientsPath, pendingClients)
          console.log(`Connect from unapproved client ${clientPk.slice(0, 12)}... — recorded as pending`)
        }
      }
      result = 'ack'
      break

    case 'ping':
      result = 'pong'
      break

    case 'get_public_key': {
      const active = getActiveSigningKey()
      result = active.pk
      releaseKey(active)
      break
    }

    case 'sign_event': {
      if (!Array.isArray(request.params) || typeof request.params[0] !== 'string') {
        error = 'sign_event: missing event template'
        break
      }
      let template
      try {
        template = JSON.parse(request.params[0])
      } catch {
        error = 'sign_event: invalid event JSON'
        break
      }
      // Validate template is a non-null object with a numeric kind
      if (typeof template !== 'object' || template === null || Array.isArray(template)) {
        error = 'sign_event: template must be a JSON object'
        break
      }
      if (typeof template.kind !== 'number' || !Number.isInteger(template.kind) || template.kind < 0) {
        error = 'sign_event: template must include a non-negative integer kind'
        break
      }
      // Kind restriction check (always enforced — kind is guaranteed present)
      if (!isKindAllowed(clientPk, template.kind, approvedClients)) {
        error = `signing kind ${template.kind} not permitted for this client`
        break
      }
      const active = getActiveSigningKey()
      try {
        const signed = finalizeEvent(template, active.sk)
        result = JSON.stringify(signed)
      } finally {
        releaseKey(active)
      }
      break
    }

    case 'nip44_encrypt': {
      if (!Array.isArray(request.params) || request.params.length < 2) {
        error = 'nip44_encrypt: requires [peer_pubkey, plaintext]'
        break
      }
      if (!isValidHexPubkey(request.params[0])) {
        error = 'nip44_encrypt: peer_pubkey must be a 64-character hex string'
        break
      }
      const active = getActiveSigningKey()
      try {
        const ck = getConversationKey(active.sk, request.params[0])
        result = encrypt(request.params[1], ck)
      } finally {
        releaseKey(active)
      }
      break
    }

    case 'nip44_decrypt': {
      if (!Array.isArray(request.params) || request.params.length < 2) {
        error = 'nip44_decrypt: requires [peer_pubkey, ciphertext]'
        break
      }
      if (!isValidHexPubkey(request.params[0])) {
        error = 'nip44_decrypt: peer_pubkey must be a 64-character hex string'
        break
      }
      const active = getActiveSigningKey()
      try {
        const ck = getConversationKey(active.sk, request.params[0])
        result = decrypt(request.params[1], ck)
      } finally {
        releaseKey(active)
      }
      break
    }

    // --- Heartwood persona methods ---

    case 'heartwood_list_identities': {
      const identityList = [
        { name: 'master', pubkey: userPk, purpose: 'master', index: 0 },
        ...personas.map((p) => ({
          name: p.name,
          pubkey: p.pubkey,
          purpose: p.purpose,
          index: p.index,
        })),
      ]
      result = JSON.stringify(identityList)
      break
    }

    case 'heartwood_derive': {
      const name = request.params[0]
      if (typeof name !== 'string' || name.length === 0 || name.length > 64) {
        error = 'heartwood_derive: name must be a non-empty string (max 64 chars)'
        break
      }
      const rawIndex = parseInt(request.params[1] ?? '0', 10)
      if (!Number.isInteger(rawIndex) || rawIndex < 0 || rawIndex > 0xFFFFFFFF) {
        error = 'heartwood_derive: index must be a non-negative integer'
        break
      }
      const index = rawIndex

      // Check for duplicate
      const existing = personas.find((p) => p.name === name && p.index === index)
      if (existing) {
        result = JSON.stringify({ name, pubkey: existing.pubkey, purpose: existing.purpose, index })
        break
      }

      const derived = derivePersona(treeRoot, name, index)
      const pubkey = bytesToHex(derived.identity.publicKey)
      const record = { name, pubkey, purpose: derived.identity.purpose, index: derived.index }
      personas.push(record)
      saveJson(personasPath, personas)
      console.log(`Derived persona "${name}" → ${pubkey.slice(0, 12)}...`)
      result = JSON.stringify(record)
      break
    }

    case 'heartwood_switch': {
      const targetPubkey = request.params[0]
      if (typeof targetPubkey !== 'string' || targetPubkey.length === 0) {
        error = 'heartwood_switch: target must be a non-empty string'
        break
      }
      if (targetPubkey === userPk) {
        // Switch back to master
        activePersonaPubkey = null
        saveJson(personaConfigPath, { activePubkey: null })
        result = JSON.stringify({ switched: true, pubkey: userPk, name: 'master' })
        break
      }
      const target = personas.find((p) => p.pubkey === targetPubkey)
      if (!target) {
        error = `unknown persona: ${targetPubkey.slice(0, 12)}...`
        break
      }
      activePersonaPubkey = targetPubkey
      saveJson(personaConfigPath, { activePubkey: targetPubkey })
      console.log(`Switched to persona "${target.name}" (${targetPubkey.slice(0, 12)}...)`)
      result = JSON.stringify({ switched: true, pubkey: targetPubkey, name: target.name })
      break
    }

    default:
      error = `unsupported method: ${request.method}`
  }

  // Build and publish encrypted response
  const response = error
    ? JSON.stringify({ id: request.id, result: '', error })
    : JSON.stringify({ id: request.id, result })

  const encrypted = encrypt(response, conversationKey)
  const responseEvent = finalizeEvent(
    {
      kind: 24133,
      created_at: Math.floor(Date.now() / 1000),
      tags: [['p', clientPk]],
      content: encrypted,
    },
    bunkerSk,
  )

  await Promise.any(pool.publish(relays, responseEvent))
  console.log(`Response ${request.id}: ${error ?? 'ok'}`)
}

// --- 7. Reload config on file changes ---

import { watch } from 'node:fs'

// Watch clients.json so the bunker picks up approvals from the web UI
// without needing a restart.
try {
  watch(clientsPath, () => {
    approvedClients = loadJson(clientsPath, {})
    console.log(`Reloaded client allowlist (${Object.keys(approvedClients).length} approved)`)
  })
} catch {
  // File may not exist yet — that's fine, we'll pick up changes on next restart
}

// Watch pending-clients.json so clears from the web UI take effect immediately.
try {
  watch(pendingClientsPath, () => {
    pendingClients = loadJson(pendingClientsPath, {})
    console.log(`Reloaded pending clients (${Object.keys(pendingClients).length} pending)`)
  })
} catch {
  // File may not exist yet
}

// Watch config.json so the bunker picks up relay changes from the web UI.
// When relays change, recompute the bunker URI and reconnect subscriptions.
try {
  let configDebounce = null
  watch(configPath, () => {
    // Debounce rapid successive writes (editors and atomic saves can trigger multiple events)
    if (configDebounce) clearTimeout(configDebounce)
    configDebounce = setTimeout(() => {
      configDebounce = null
      const newRelays = loadRelays()
      // Only reconnect if the relay list actually changed
      const changed =
        newRelays.length !== relays.length || newRelays.some((r, i) => r !== relays[i])
      if (!changed) return

      const oldRelays = relays
      relays = newRelays
      const newUri = connectRelays(relays)
      console.log(`Relay list changed — reconnected`)
      console.log(`  Old: ${oldRelays.join(', ')}`)
      console.log(`  New: ${relays.join(', ')}`)
      console.log(`  URI: ${newUri}`)
    }, 250)
  })
} catch {
  // File may not exist yet — that's fine
}

// --- 8. Relay status reporting ---

const STATUS_PATH = `${DATA_DIR}/bunker-status.json`
let lastStatusJson = ''

async function writeRelayStatus() {
  const status = {}
  await Promise.all(
    relays.map(async (url) => {
      try {
        const relay = await Promise.race([
          pool.ensureRelay(url),
          new Promise((_, reject) => setTimeout(() => reject(), 5000)),
        ])
        status[url] = relay.connected
      } catch {
        status[url] = false
      }
    }),
  )
  const json = JSON.stringify({ relays: status, ts: new Date().toISOString() })
  if (json === lastStatusJson) return
  lastStatusJson = json
  // 0o644 intentionally (not 0o600 like secrets) — the Rust device reads this
  await writeFile(STATUS_PATH, json, { mode: 0o644 }).catch(() => {})
}

// Initial write after connections establish, then periodic
setTimeout(writeRelayStatus, 3000)
setInterval(writeRelayStatus, 15000)

// --- 9. Clean shutdown ---

function shutdown() {
  console.log('Shutting down...')
  pool.close(relays)
  treeRoot.destroy()
  bunkerSk.fill(0)
  userSk.fill(0)
  process.exit(0)
}

process.on('SIGINT', shutdown)
process.on('SIGTERM', shutdown)
