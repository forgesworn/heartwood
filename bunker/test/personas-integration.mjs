/**
 * Integration test for per-identity bunker routing (approach B).
 *
 * Not run by `npm test` (no `.test.mjs` suffix) because it spawns the real
 * sidecar and an in-process relay. Run directly:  node test/personas-integration.mjs
 *
 * It proves that each identity's bunker URI is an independent connection:
 * connecting to identity X's URI yields X's pubkey from `get_public_key` and
 * signs events as X — with no global "active" identity involved.
 */

import { spawn } from 'node:child_process'
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { setTimeout as sleep } from 'node:timers/promises'

import { WebSocketServer, WebSocket } from 'ws'
import { generateSecretKey, getPublicKey, finalizeEvent, verifyEvent } from 'nostr-tools/pure'
import { getConversationKey, encrypt, decrypt } from 'nostr-tools/nip44'
import { bytesToHex } from 'nostr-tools/utils'
import { fromMnemonic } from 'nsec-tree/mnemonic'
import { derivePersona } from 'nsec-tree/persona'

const BUNKER_DIR = dirname(dirname(fileURLToPath(import.meta.url)))
// Standard BIP-39 test vector (well-known; test-only).
const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
const NIP46_KIND = 24133
const nowSec = () => Math.floor(Date.now() / 1000)

let failures = 0
function check(cond, msg) {
  if (cond) {
    console.log(`  ✔ ${msg}`)
  } else {
    failures++
    console.log(`  x FAIL: ${msg}`)
  }
}

// ── Minimal in-process relay ────────────────────────────────────────────────
function matchFilter(f, ev) {
  if (f.kinds && !f.kinds.includes(ev.kind)) return false
  if (f.authors && !f.authors.includes(ev.pubkey)) return false
  if (f.ids && !f.ids.includes(ev.id)) return false
  if (f.since && ev.created_at < f.since) return false
  for (const k of Object.keys(f)) {
    if (k[0] !== '#') continue
    const want = f[k]
    const tag = k.slice(1)
    const have = ev.tags.filter((t) => t[0] === tag).map((t) => t[1])
    if (!have.some((v) => want.includes(v))) return false
  }
  return true
}

function startRelay() {
  const wss = new WebSocketServer({ port: 0 })
  const recent = []
  const subscribedPubkeys = new Set()
  wss.on('connection', (ws) => {
    ws._subs = new Map()
    ws.on('message', (data) => {
      let msg
      try {
        msg = JSON.parse(data)
      } catch {
        return
      }
      const [type, ...rest] = msg
      if (type === 'REQ') {
        const [subId, ...filters] = rest
        ws._subs.set(subId, filters)
        for (const f of filters) for (const p of f['#p'] ?? []) subscribedPubkeys.add(p)
        for (const ev of recent) {
          if (filters.some((f) => matchFilter(f, ev))) ws.send(JSON.stringify(['EVENT', subId, ev]))
        }
        ws.send(JSON.stringify(['EOSE', subId]))
      } else if (type === 'EVENT') {
        const ev = rest[0]
        recent.push(ev)
        if (recent.length > 300) recent.shift()
        ws.send(JSON.stringify(['OK', ev.id, true, '']))
        for (const client of wss.clients) {
          if (client.readyState !== WebSocket.OPEN) continue
          for (const [subId, filters] of client._subs ?? []) {
            if (filters.some((f) => matchFilter(f, ev))) {
              client.send(JSON.stringify(['EVENT', subId, ev]))
              break
            }
          }
        }
      } else if (type === 'CLOSE') {
        ws._subs.delete(rest[0])
      }
    })
  })
  const port = wss.address().port
  return { wss, port, url: `ws://127.0.0.1:${port}`, subscribedPubkeys }
}

// ── Minimal NIP-46 client (one ws per call) ─────────────────────────────────
function nip46Call(relayUrl, signerPk, clientSk, method, params, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    const clientPk = getPublicKey(clientSk)
    const convKey = getConversationKey(clientSk, signerPk)
    const id = 'req' + Math.floor(Math.random() * 1e9)
    const ws = new WebSocket(relayUrl)
    const timer = setTimeout(() => {
      ws.close()
      reject(new Error(`timeout waiting for ${method} response`))
    }, timeoutMs)
    ws.on('open', () => {
      ws.send(JSON.stringify(['REQ', 'r' + id, { kinds: [NIP46_KIND], '#p': [clientPk], authors: [signerPk] }]))
      const content = encrypt(JSON.stringify({ id, method, params }), convKey)
      const reqEvent = finalizeEvent(
        { kind: NIP46_KIND, created_at: nowSec(), tags: [['p', signerPk]], content },
        clientSk,
      )
      ws.send(JSON.stringify(['EVENT', reqEvent]))
    })
    ws.on('message', (data) => {
      let msg
      try {
        msg = JSON.parse(data)
      } catch {
        return
      }
      if (msg[0] !== 'EVENT') return
      const ev = msg[2]
      if (ev.kind !== NIP46_KIND || ev.pubkey !== signerPk) return
      let payload
      try {
        payload = JSON.parse(decrypt(ev.content, convKey))
      } catch {
        return
      }
      if (payload.id !== id) return
      clearTimeout(timer)
      ws.close()
      if (payload.error) reject(new Error(payload.error))
      else resolve(payload.result)
    })
    ws.on('error', (e) => {
      clearTimeout(timer)
      reject(e)
    })
  })
}

function parseBunkerUri(uri) {
  const rest = uri.slice('bunker://'.length)
  const [pubkey, query = ''] = rest.split('?')
  const params = new URLSearchParams(query)
  return { pubkey, relay: params.get('relay') }
}

// ── Harness ─────────────────────────────────────────────────────────────────
async function main() {
  const relay = startRelay()
  const dataDir = mkdtempSync(join(tmpdir(), 'heartwood-bunker-test-'))
  const clientSk = generateSecretKey()
  const clientPk = getPublicKey(clientSk)

  // Derive the two personas independently, so we can both pre-seed personas.json
  // and assert the sidecar returns the SAME pubkeys.
  const treeRoot = fromMnemonic(MNEMONIC)
  const persona = (name) => {
    const d = derivePersona(treeRoot, name, 0)
    return { name, pubkey: bytesToHex(d.identity.publicKey), purpose: d.identity.purpose, index: d.index }
  }
  const personas = [persona('work'), persona('fun')]

  writeFileSync(join(dataDir, 'master.payload'), `tree-mnemonic::${MNEMONIC}`)
  writeFileSync(join(dataDir, 'config.json'), JSON.stringify({ relays: [relay.url] }))
  writeFileSync(join(dataDir, 'personas.json'), JSON.stringify(personas))

  const child = spawn('node', ['index.mjs'], {
    cwd: BUNKER_DIR,
    env: { ...process.env, HEARTWOOD_DATA_DIR: dataDir, HEARTWOOD_AUTHORIZED_KEYS: clientPk },
  })
  const logs = []
  child.stdout.on('data', (d) => logs.push(`[sidecar] ${d}`.trimEnd()))
  child.stderr.on('data', (d) => logs.push(`[sidecar:err] ${d}`.trimEnd()))

  try {
    // Wait for the sidecar to mint URIs and subscribe for the master identity.
    const urisPath = join(dataDir, 'bunker-uris.json')
    for (let i = 0; i < 100 && !existsSync(urisPath); i++) await sleep(100)
    if (!existsSync(urisPath)) throw new Error('sidecar never wrote bunker-uris.json')
    const manifest = JSON.parse(readFileSync(urisPath, 'utf-8'))
    const masterPk = manifest.find((m) => m.label === 'master')?.pubkey
    for (let i = 0; i < 100 && !relay.subscribedPubkeys.has(masterPk); i++) await sleep(100)

    console.log(`\nManifest has ${manifest.length} identities: ${manifest.map((m) => m.label).join(', ')}`)
    check(manifest.length === 3, 'manifest lists master + 2 personas')
    for (const p of personas) {
      const entry = manifest.find((m) => m.label === p.name)
      check(entry?.pubkey === p.pubkey, `persona "${p.name}" pubkey matches independent derivation`)
      check(entry?.uri.startsWith(`bunker://${p.pubkey}?`), `persona "${p.name}" URI is addressed to its own pubkey`)
    }

    const seen = []
    for (const entry of manifest) {
      const { pubkey: signerPk, relay: relayUrl } = parseBunkerUri(entry.uri)
      const ack = await nip46Call(relayUrl, signerPk, clientSk, 'connect', [signerPk])
      check(ack === 'ack', `[${entry.label}] connect → ack`)

      const pk = await nip46Call(relayUrl, signerPk, clientSk, 'get_public_key', [])
      check(pk === entry.pubkey, `[${entry.label}] get_public_key returns the addressed identity`)

      const tmpl = JSON.stringify({ kind: 1, created_at: nowSec(), tags: [], content: `hi from ${entry.label}` })
      const signed = JSON.parse(await nip46Call(relayUrl, signerPk, clientSk, 'sign_event', [tmpl]))
      check(signed.pubkey === entry.pubkey, `[${entry.label}] sign_event signs AS the addressed identity`)
      check(verifyEvent(signed) === true, `[${entry.label}] signed event has a valid signature`)
      seen.push(signed.pubkey)
    }
    check(new Set(seen).size === 3, 'all three identities signed with distinct keys')

    // A request addressed to an unknown pubkey must be ignored (no response).
    const stranger = getPublicKey(generateSecretKey())
    let strayResolved = false
    await nip46Call(relay.url, stranger, clientSk, 'get_public_key', [], 2500)
      .then(() => (strayResolved = true))
      .catch(() => {})
    check(!strayResolved, 'request to an unknown identity is ignored (times out, no signer)')
  } catch (e) {
    failures++
    console.log(`\n✘ harness error: ${e.message}`)
    console.log(logs.join('\n'))
  } finally {
    child.kill('SIGKILL')
    relay.wss.close()
    rmSync(dataDir, { recursive: true, force: true })
  }

  console.log(`\n${failures === 0 ? '✔ ALL PASSED' : `✘ ${failures} FAILED`}`)
  process.exit(failures === 0 ? 0 : 1)
}

main()
