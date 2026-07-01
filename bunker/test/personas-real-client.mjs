/**
 * Real-client interop test for per-identity bunker routing (approach B).
 *
 * Where personas-integration.mjs uses a hand-rolled NIP-46 client on an
 * in-process relay, this drives the REAL `nostr-tools` BunkerSigner — the same
 * client library GUI apps (noStrudel, Coracle, Nostur, Amethyst) build on — over
 * a REAL public relay. It proves the per-identity URIs interoperate with an
 * off-the-shelf client, not just with our own transport code.
 *
 * Not run by `npm test` (hits the network). Run directly:
 *   node test/personas-real-client.mjs
 *
 * Override the relay with HEARTWOOD_TEST_RELAY=wss://... if trotters is down.
 */

import { spawn } from 'node:child_process'
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { setTimeout as sleep } from 'node:timers/promises'

import { generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools/pure'
import { BunkerSigner, parseBunkerInput } from 'nostr-tools/nip46'
import { SimplePool } from 'nostr-tools/pool'
import { bytesToHex } from 'nostr-tools/utils'
import { fromMnemonic } from 'nsec-tree/mnemonic'
import { derivePersona } from 'nsec-tree/persona'

const BUNKER_DIR = dirname(dirname(fileURLToPath(import.meta.url)))
// Standard BIP-39 test vector (well-known; test-only).
const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
const RELAY = process.env.HEARTWOOD_TEST_RELAY || 'wss://relay.trotters.cc'
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

async function main() {
  console.log(`Relay: ${RELAY}\n`)
  const dataDir = mkdtempSync(join(tmpdir(), 'heartwood-bunker-real-'))

  // Derive the personas independently so we can pre-seed personas.json AND
  // assert the sidecar + the real client both agree on the pubkeys.
  const treeRoot = fromMnemonic(MNEMONIC)
  const persona = (name) => {
    const d = derivePersona(treeRoot, name, 0)
    return { name, pubkey: bytesToHex(d.identity.publicKey), purpose: d.identity.purpose, index: d.index }
  }
  const personas = [persona('work'), persona('fun')]

  // A real GUI client uses a distinct local key per account. Mirror that: one
  // client key per persona, both pre-authorised so signing needs no operator tap.
  const clientKeys = personas.map(() => {
    const sk = generateSecretKey()
    return { sk, pk: getPublicKey(sk) }
  })

  writeFileSync(join(dataDir, 'master.payload'), `tree-mnemonic::${MNEMONIC}`)
  writeFileSync(join(dataDir, 'config.json'), JSON.stringify({ relays: [RELAY] }))
  writeFileSync(join(dataDir, 'personas.json'), JSON.stringify(personas))

  const child = spawn('node', ['index.mjs'], {
    cwd: BUNKER_DIR,
    env: {
      ...process.env,
      HEARTWOOD_DATA_DIR: dataDir,
      HEARTWOOD_AUTHORIZED_KEYS: clientKeys.map((c) => c.pk).join(','),
    },
  })
  const logs = []
  child.stdout.on('data', (d) => logs.push(`[sidecar] ${d}`.trimEnd()))
  child.stderr.on('data', (d) => logs.push(`[sidecar:err] ${d}`.trimEnd()))

  const pool = new SimplePool()
  const signers = []

  try {
    // Wait for the sidecar to mint the per-identity URIs.
    const urisPath = join(dataDir, 'bunker-uris.json')
    for (let i = 0; i < 100 && !existsSync(urisPath); i++) await sleep(100)
    if (!existsSync(urisPath)) throw new Error('sidecar never wrote bunker-uris.json')
    const manifest = JSON.parse(readFileSync(urisPath, 'utf-8'))

    console.log(`Manifest: ${manifest.map((m) => m.label).join(', ')}\n`)
    check(manifest.length === 3, 'manifest lists master + 2 personas')

    // Give the sidecar a moment to establish its relay subscription before the
    // real client starts firing requests at the public relay.
    await sleep(2500)

    const seen = []
    for (let i = 0; i < personas.length; i++) {
      const p = personas[i]
      const entry = manifest.find((m) => m.label === p.name)
      check(entry?.pubkey === p.pubkey, `[${p.name}] manifest pubkey matches independent derivation`)

      const pointer = await parseBunkerInput(entry.uri)
      check(pointer?.pubkey === p.pubkey, `[${p.name}] parseBunkerInput points at the persona pubkey`)

      const signer = BunkerSigner.fromBunker(clientKeys[i].sk, pointer, {
        pool,
        onauth: (url) => console.log(`    (auth challenge for ${p.name}: ${url})`),
      })
      signers.push(signer)

      await signer.connect()
      const pk = await signer.getPublicKey()
      check(pk === p.pubkey, `[${p.name}] BunkerSigner.getPublicKey() returns the persona identity`)

      const signed = await signer.signEvent({
        kind: 1,
        created_at: nowSec(),
        tags: [],
        content: `heartwood multi-identity proof: ${p.name}`,
      })
      check(signed.pubkey === p.pubkey, `[${p.name}] signed event is AUTHORED by the persona`)
      check(verifyEvent(signed) === true, `[${p.name}] signed event has a valid Schnorr signature`)
      console.log(`    ${p.name} → ${p.pubkey.slice(0, 16)}… sig ok`)
      seen.push(signed.pubkey)
    }

    check(new Set(seen).size === personas.length, 'each persona signed with a DISTINCT key')
    check(
      !seen.includes(manifest.find((m) => m.label === 'master').pubkey),
      'no persona connection leaked the master key',
    )
  } catch (e) {
    failures++
    console.log(`\n✘ harness error: ${e.message}`)
    console.log(logs.join('\n'))
  } finally {
    for (const s of signers) {
      try {
        s.close()
      } catch {}
    }
    pool.close([RELAY])
    child.kill('SIGKILL')
    rmSync(dataDir, { recursive: true, force: true })
  }

  console.log(`\n${failures === 0 ? '✔ ALL PASSED' : `✘ ${failures} FAILED`}`)
  process.exit(failures === 0 ? 0 : 1)
}

main()
