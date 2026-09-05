#!/usr/bin/env node
/**
 * Client-side proving check: the preimage-ownership statement (D-025) proven
 * with noir_js (witness) + bb.js (UltraHonk, WASM) — the same libraries the
 * browser worker uses — and checked against the bb CLI's verification key, so
 * a browser proof is known to verify on the deployed PreimageHonkVerifier.
 *
 * Usage: node scripts/prove-preimage-node.mjs   (Node >= 22)
 */

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { Barretenberg, UltraHonkBackend } from '@aztec/bb.js'
import { Noir } from '@noir-lang/noir_js'
import { createHash } from 'node:crypto'
import { keccak256, toHex } from 'viem'

const here = (p) => fileURLToPath(new URL(p, import.meta.url))
const circuit = JSON.parse(readFileSync(here('../../noir/preimage-ownership/target/preimage_ownership.json'), 'utf8'))
const fx = JSON.parse(readFileSync(here('../../python/scripts/sphincs_c13_7913_demo.json'), 'utf8'))

const utf8 = (s) => new TextEncoder().encode(s)
const cat = (...parts) => {
  const n = parts.reduce((a, p) => a + p.length, 0)
  const out = new Uint8Array(n)
  let o = 0
  for (const p of parts) { out.set(p, o); o += p.length }
  return out
}
const hexBytes = (h) => Uint8Array.from(Buffer.from(h.slice(2), 'hex'))

// demo secret, opener and message exactly as generate_prover.py defaults them
const sk = new Uint8Array(createHash('sha256').update(cat(utf8('pq-stealth/preimage/keygen/v0'), new Uint8Array(32).fill(0x81))).digest())
const ss = hexBytes(fx.shared_secret_DEMO_ONLY)
const opener = new Uint8Array(createHash('sha256').update(cat(utf8('pq-stealth/preimage/open/v0'), ss)).digest())
const spendKey = hexBytes(keccak256(cat(utf8('pq-stealth/preimage/key/v0'), sk)))
const commitment = hexBytes(keccak256(cat(utf8('pq-stealth/preimage/commit/v0'), spendKey, opener)))
const message = hexBytes(fx.challenge)
const half = (b, i) => toHex(b.slice(16 * i, 16 * i + 16))

const inputs = {
  message_hi: half(message, 0), message_lo: half(message, 1),
  commitment_hi: half(commitment, 0), commitment_lo: half(commitment, 1),
  sk: Array.from(sk), opener: Array.from(opener),
}
console.log('commitment', toHex(commitment))

let t = Date.now()
const noir = new Noir(circuit)
const { witness } = await noir.execute(inputs)
console.log(`witness: ${witness.length} B in ${Date.now() - t} ms`)

t = Date.now()
const api = await Barretenberg.new({ threads: 8 })
const backend = new UltraHonkBackend(circuit.bytecode, api)
const proofData = await backend.generateProof(witness, { verifierTarget: 'evm' })
console.log(`proof: ${proofData.proof.length} B, ${proofData.publicInputs.length} public inputs, in ${Date.now() - t} ms`)

t = Date.now()
const ok = await backend.verifyProof(proofData, { verifierTarget: 'evm' })
console.log(`bb.js verify: ${ok} in ${Date.now() - t} ms`)

const vk = await backend.getVerificationKey({ verifierTarget: 'evm' })
const cliVk = readFileSync(here('../../noir/preimage-ownership/out/vk'))
console.log(`vk matches bb CLI (deployed verifier): ${Buffer.from(vk).equals(cliVk)}`)
console.log('public inputs', proofData.publicInputs)
await api.destroy()
