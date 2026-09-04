/**
 * Client-side prover for the preimage-ownership statement (D-025):
 * noir_js executes noir/preimage-ownership, bb.js (UltraHonk, WASM) proves it
 * for the EVM verifier. Pure TS — runs in a web worker and in Node alike.
 *
 *   spend_key  = keccak256("pq-stealth/preimage/key/v0" || sk)
 *   commitment = keccak256("pq-stealth/preimage/commit/v0" || spend_key || opener)
 *   public inputs: [message_hi, message_lo, commitment_hi, commitment_lo]
 */

import { Barretenberg, UltraHonkBackend } from '@aztec/bb.js'
import { Noir, type CompiledCircuit } from '@noir-lang/noir_js'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, type Hex } from 'viem'

export const PREIMAGE_KEYGEN_DOMAIN = 'pq-stealth/preimage/keygen/v0'

export interface PreimageProof {
  proof: Hex
  publicInputs: Hex[]
  timings: { witness: number; prove: number }
}

/** Demo secret derivation: sk = SHA-256(keygen domain || spend seed). */
export function secretFromSeed(spendSeed: Uint8Array): Uint8Array {
  const dom = new TextEncoder().encode(PREIMAGE_KEYGEN_DOMAIN)
  const buf = new Uint8Array(dom.length + spendSeed.length)
  buf.set(dom, 0)
  buf.set(spendSeed, dom.length)
  return sha256(buf)
}

const half = (b: Uint8Array, i: 0 | 1): Hex => bytesToHex(b.slice(16 * i, 16 * i + 16))

export class PreimageProver {
  private noir: Noir
  private api: Barretenberg | null = null
  private backend: UltraHonkBackend | null = null
  private circuit: CompiledCircuit
  private threads: number

  // no parameter properties: Node's type stripping (scripts/e2e-*.ts) does not support them
  constructor(circuit: CompiledCircuit, threads = 1) {
    this.circuit = circuit
    this.threads = threads
    this.noir = new Noir(circuit)
  }

  static async load(url: string, threads = 1): Promise<PreimageProver> {
    const r = await fetch(url)
    if (!r.ok) throw new Error(`cannot load circuit ${url}: ${r.status}`)
    return new PreimageProver((await r.json()) as CompiledCircuit, threads)
  }

  private async ready(): Promise<UltraHonkBackend> {
    if (!this.backend) {
      this.api = await Barretenberg.new({ threads: this.threads })
      this.backend = new UltraHonkBackend(this.circuit.bytecode, this.api)
    }
    return this.backend
  }

  /** Prove knowledge of (sk, opener) for `commitment`, bound to `message` (the frame tx sig_hash). */
  async prove(message: Uint8Array, commitment: Uint8Array, sk: Uint8Array, opener: Uint8Array): Promise<PreimageProof> {
    let t = Date.now()
    const { witness } = await this.noir.execute({
      message_hi: half(message, 0), message_lo: half(message, 1),
      commitment_hi: half(commitment, 0), commitment_lo: half(commitment, 1),
      sk: Array.from(sk), opener: Array.from(opener),
    })
    const tWitness = Date.now() - t
    t = Date.now()
    const backend = await this.ready()
    const { proof, publicInputs } = await backend.generateProof(witness, { verifierTarget: 'evm' })
    return { proof: bytesToHex(proof), publicInputs: publicInputs as Hex[], timings: { witness: tWitness, prove: Date.now() - t } }
  }

  async destroy(): Promise<void> {
    await this.api?.destroy()
    this.api = null
    this.backend = null
  }
}
