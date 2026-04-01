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
import { derivePersona } from 'nsec-tree/persona'
import { bytesToHex } from 'nostr-tools/utils'

globalThis.WebSocket = WebSocket

const DATA_DIR = '/var/lib/heartwood'
const DEFAULT_RELAYS = [
  'wss://relay.damus.io',
  'wss://relay.nostr.band',
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
const runtimePayloadPath = '/run/heartwood/master.payload'

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
  // Encrypted files start with version byte 0x01 (not valid UTF-8 text prefix)
  if (raw[0] === 0x01) {
    console.error('FATAL: master.secret is encrypted but device is locked')
    console.error('       Unlock the device via the web UI, then restart the bunker.')
    process.exit(1)
  }

  return raw.toString('utf-8').trim()
}

const secretPayload = readSecretPayload()
if (!secretPayload.startsWith('bunker:')) {
  console.error('FATAL: master.secret is not in bunker mode (expected "bunker:<nsec>")')
  process.exit(1)
}

const nsec = secretPayload.slice('bunker:'.length)
const { type, data: userSk } = nip19decode(nsec)
if (type !== 'nsec') {
  console.error('FATAL: invalid nsec in master.secret')
  process.exit(1)
}

const userPk = getPublicKey(userSk)

// --- 1b. nsec-tree persona derivation state ---

const treeRoot = fromNsec(new Uint8Array(userSk))
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

/** Get the currently active signing key and pubkey. */
function getActiveSigningKey() {
  if (!activePersonaPubkey) {
    return { sk: userSk, pk: userPk }
  }
  const persona = personas.find((p) => p.pubkey === activePersonaPubkey)
  if (!persona) {
    // Persona was removed — fall back to master
    activePersonaPubkey = null
    return { sk: userSk, pk: userPk }
  }
  // Re-derive the private key from the tree root
  const derived = derivePersona(treeRoot, persona.name, persona.index)
  return {
    sk: derived.identity.privateKey,
    pk: bytesToHex(derived.identity.publicKey),
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

/** Check if a client pubkey is approved. */
function isApproved(pubkey) {
  return Object.prototype.hasOwnProperty.call(approvedClients, pubkey)
}

/** Record a pending client connection attempt. */
function recordPending(pubkey) {
  const now = new Date().toISOString()
  if (pendingClients[pubkey]) {
    pendingClients[pubkey].lastSeen = now
    pendingClients[pubkey].attempts += 1
  } else {
    pendingClients[pubkey] = { firstSeen: now, lastSeen: now, attempts: 1 }
    console.log(`New pending client: ${pubkey.slice(0, 12)}...`)
  }
  saveJson(pendingClientsPath, pendingClients)
}

/** Check if a signing kind is allowed for a given client. */
function isKindAllowed(pubkey, kind) {
  const client = approvedClients[pubkey]
  if (!client || !client.allowedKinds) return true // no restriction
  return client.allowedKinds.includes(kind)
}

// --- Per-client rate limiting (sliding window) ---

const DEFAULT_RATE_LIMIT = 30 // requests per minute
const RATE_WINDOW_MS = 60_000

/** Map of client pubkey → array of request timestamps (epoch ms). */
const rateBuckets = new Map()

/**
 * Check if a client has exceeded their rate limit.
 * Returns true if the request should be allowed, false if rate-limited.
 */
function checkRateLimit(pubkey) {
  const now = Date.now()
  let timestamps = rateBuckets.get(pubkey)
  if (!timestamps) {
    timestamps = []
    rateBuckets.set(pubkey, timestamps)
  }

  // Prune entries older than the window
  const cutoff = now - RATE_WINDOW_MS
  while (timestamps.length > 0 && timestamps[0] < cutoff) {
    timestamps.shift()
  }

  // Per-client limit from clients.json, or default
  const client = approvedClients[pubkey]
  const limit = client?.rateLimit ?? DEFAULT_RATE_LIMIT

  if (timestamps.length >= limit) {
    return false
  }

  timestamps.push(now)
  return true
}

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
    if (!isApproved(clientPk)) {
      recordPending(clientPk)
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

  // --- Rate limit enforcement ---
  // connect, ping, and get_public_key are exempt; all other methods are rate-limited.
  if (request.method !== 'connect' && request.method !== 'ping' && request.method !== 'get_public_key') {
    if (!checkRateLimit(clientPk)) {
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
      if (!isApproved(clientPk)) {
        recordPending(clientPk)
        result = 'ack'
        console.log(`Connect from unapproved client ${clientPk.slice(0, 12)}... — recorded as pending`)
      } else {
        result = 'ack'
      }
      break

    case 'ping':
      result = 'pong'
      break

    case 'get_public_key': {
      const active = getActiveSigningKey()
      result = active.pk
      break
    }

    case 'sign_event': {
      const template = JSON.parse(request.params[0])
      // Kind restriction check
      if (template.kind !== undefined && !isKindAllowed(clientPk, template.kind)) {
        error = `signing kind ${template.kind} not permitted for this client`
        break
      }
      const active = getActiveSigningKey()
      const signed = finalizeEvent(template, active.sk)
      result = JSON.stringify(signed)
      break
    }

    case 'nip44_encrypt': {
      const active = getActiveSigningKey()
      const ck = getConversationKey(active.sk, request.params[0])
      result = encrypt(request.params[1], ck)
      break
    }

    case 'nip44_decrypt': {
      const active = getActiveSigningKey()
      const ck = getConversationKey(active.sk, request.params[0])
      result = decrypt(request.params[1], ck)
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
      const index = parseInt(request.params[1] ?? '0', 10)

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
