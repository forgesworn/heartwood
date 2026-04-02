#!/usr/bin/env node
/**
 * derive-client-key — extract a persistent NIP-46 client key from nsec-tree.
 *
 * Usage:
 *   node derive-client-key.mjs --nsec <nsec1...> --name <name>
 *   node derive-client-key.mjs --nsec <nsec1...> --name <name> --index <n>
 *
 * The derived private key is printed to stdout. Save it to a file for use
 * with Bray's --bunker-key-file flag. The corresponding pubkey goes into
 * the bunker's HEARTWOOD_AUTHORIZED_KEYS env var.
 *
 * This tool runs locally and never touches the network.
 */

import { decode as nip19decode } from 'nostr-tools/nip19'
import { bytesToHex } from 'nostr-tools/utils'
import { fromNsec } from 'nsec-tree/core'
import { derivePersona } from 'nsec-tree/persona'

function usage() {
  console.error('Usage: node derive-client-key.mjs --nsec <nsec1...> --name <name> [--index <n>]')
  console.error('')
  console.error('Options:')
  console.error('  --nsec <nsec1...>   Master nsec in bech32 format')
  console.error('  --name <name>       Persona name (e.g. client/bray, agent/dispatch)')
  console.error('  --index <n>         Derivation index (default: 0)')
  process.exit(1)
}

const args = process.argv.slice(2)

function getArg(flag) {
  const idx = args.indexOf(flag)
  if (idx === -1 || idx + 1 >= args.length) return undefined
  return args[idx + 1]
}

const nsec = getArg('--nsec')
const name = getArg('--name')
const index = parseInt(getArg('--index') ?? '0', 10)

if (!nsec || !name) usage()

// Decode nsec
let userSk
try {
  const decoded = nip19decode(nsec)
  if (decoded.type !== 'nsec') {
    console.error('ERROR: expected nsec, got ' + decoded.type)
    process.exit(1)
  }
  userSk = decoded.data
} catch (e) {
  console.error('ERROR: invalid nsec — ' + e.message)
  process.exit(1)
}

// Derive
const treeRoot = fromNsec(new Uint8Array(userSk))
let derived
try {
  derived = derivePersona(treeRoot, name, index)
} catch (e) {
  console.error('ERROR: derivation failed — ' + e.message)
  treeRoot.destroy()
  userSk.fill(0)
  process.exit(1)
}

const pubkey = bytesToHex(derived.identity.publicKey)
const secret = bytesToHex(derived.identity.privateKey)

console.log(`Name:    ${name}`)
console.log(`Index:   ${index}`)
console.log(`Purpose: ${derived.identity.purpose}`)
console.log(`Pubkey:  ${pubkey}`)
console.log(`Secret:  ${secret}`)

// Clean up
treeRoot.destroy()
userSk.fill(0)
derived.identity.privateKey.fill(0)
