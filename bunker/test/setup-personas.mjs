/**
 * Dev helper: prepare a throwaway data dir with N personas + a connect-slot
 * secret (for auto-approval), and print one bunker URI per persona for manual
 * client testing (Coracle, noStrudel, ...). Pair with:
 *
 *   SERVE_DIR=/tmp/hw node test/setup-personas.mjs        # prepare + print URIs
 *   HEARTWOOD_DATA_DIR=/tmp/hw node index.mjs             # run the bunker
 *
 * Env: SERVE_DIR (required), RELAYS (comma-sep, default public), PERSONAS.
 */
import { mkdirSync, writeFileSync } from 'node:fs'
import { generateSecretKey } from 'nostr-tools/pure'
import { bytesToHex } from 'nostr-tools/utils'
import { fromMnemonic } from 'nsec-tree/mnemonic'
import { derivePersona } from 'nsec-tree/persona'

const dir = process.env.SERVE_DIR
if (!dir) {
  console.error('SERVE_DIR is required')
  process.exit(1)
}
const relays = (process.env.RELAYS || 'wss://relay.nsec.app,wss://relay.damus.io,wss://nos.lol').split(',')
const names = (process.env.PERSONAS || 'work,fun').split(',')

let mnemonic
try {
  const { generateMnemonic } = await import('@scure/bip39')
  const { wordlist } = await import('@scure/bip39/wordlists/english')
  mnemonic = generateMnemonic(wordlist, 128)
} catch {
  mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
}

const treeRoot = fromMnemonic(mnemonic)
const personas = names.map((name) => {
  const d = derivePersona(treeRoot, name.trim(), 0)
  return { name: name.trim(), pubkey: bytesToHex(d.identity.publicKey), purpose: d.identity.purpose, index: d.index }
})
const secret = bytesToHex(generateSecretKey())

mkdirSync(dir, { recursive: true })
writeFileSync(`${dir}/master.payload`, `tree-mnemonic::${mnemonic}`)
writeFileSync(`${dir}/config.json`, JSON.stringify({ relays }))
writeFileSync(`${dir}/personas.json`, JSON.stringify(personas))
writeFileSync(`${dir}/slots.json`, JSON.stringify({ [secret]: { label: 'manual-test' } }))

const relayParams = relays.map((r) => `relay=${encodeURIComponent(r)}`).join('&')
const lines = personas.map((p) => `${p.name}: bunker://${p.pubkey}?${relayParams}&secret=${secret}`)
writeFileSync(`${dir}/uris.txt`, lines.join('\n') + '\n')
console.log(lines.join('\n'))
