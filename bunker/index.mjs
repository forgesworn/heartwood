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
import { getConversationKey, encrypt, decrypt } from 'nostr-tools/nip44'
import { finalizeEvent, getPublicKey, generateSecretKey } from 'nostr-tools/pure'
import { decode as nip19decode } from 'nostr-tools/nip19'
import { SimplePool } from 'nostr-tools/pool'
import WebSocket from 'ws'

globalThis.WebSocket = WebSocket

const DATA_DIR = '/var/lib/heartwood'
const DEFAULT_RELAYS = [
  'wss://relay.damus.io',
  'wss://relay.nostr.band',
  'wss://nos.lol',
  'wss://relay.trotters.cc',
]

// --- 1. Read nsec from master.secret ---

const secretPath = `${DATA_DIR}/master.secret`
if (!existsSync(secretPath)) {
  console.error('FATAL: master.secret not found — is heartwood-device configured?')
  process.exit(1)
}

const secretPayload = readFileSync(secretPath, 'utf-8').trim()
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

// --- 2. Read relay list from config.json ---

let relays = DEFAULT_RELAYS
const configPath = `${DATA_DIR}/config.json`
if (existsSync(configPath)) {
  try {
    const config = JSON.parse(readFileSync(configPath, 'utf-8'))
    if (Array.isArray(config.relays) && config.relays.length > 0) {
      relays = config.relays
    }
  } catch {
    console.warn('WARN: could not parse config.json, using default relays')
  }
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

pool.subscribeMany(
  relays,
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

// --- 5. Write bunker URI ---

const relayParams = relays.map((r) => `relay=${encodeURIComponent(r)}`).join('&')
const bunkerUri = `bunker://${bunkerPk}?${relayParams}`

writeFileSync(`${DATA_DIR}/bunker-uri.txt`, bunkerUri)

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

  console.log(`Request ${request.id}: ${request.method}`)

  let result = ''
  let error

  switch (request.method) {
    case 'connect':
      result = 'ack'
      break

    case 'ping':
      result = 'pong'
      break

    case 'get_public_key':
      result = userPk
      break

    case 'sign_event': {
      const template = JSON.parse(request.params[0])
      const signed = finalizeEvent(template, userSk)
      result = JSON.stringify(signed)
      break
    }

    case 'nip44_encrypt': {
      const ck = getConversationKey(userSk, request.params[0])
      result = encrypt(request.params[1], ck)
      break
    }

    case 'nip44_decrypt': {
      const ck = getConversationKey(userSk, request.params[0])
      result = decrypt(request.params[1], ck)
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

// --- 7. Clean shutdown ---

function shutdown() {
  console.log('Shutting down...')
  pool.close(relays)
  bunkerSk.fill(0)
  userSk.fill(0)
  process.exit(0)
}

process.on('SIGINT', shutdown)
process.on('SIGTERM', shutdown)
