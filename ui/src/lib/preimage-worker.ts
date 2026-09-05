/**
 * Web worker: proves the preimage-ownership statement off the main thread.
 * Messages: { id, message, commitment, sk, opener } -> { id, proof, publicInputs, timings } | { id, error }.
 * The circuit is fetched once from /circuits/preimage_ownership.json.
 */

import { PreimageProver } from './preimage-prover.ts'

interface ProveRequest {
  id: number
  message: Uint8Array
  commitment: Uint8Array
  sk: Uint8Array
  opener: Uint8Array
}

let proverPromise: Promise<PreimageProver> | null = null
const prover = () => {
  if (!proverPromise) {
    // SharedArrayBuffer (COOP/COEP) => multi-threaded bb.js; otherwise one thread
    const threads = typeof SharedArrayBuffer !== 'undefined' ? Math.max(1, Math.min(8, navigator.hardwareConcurrency || 1)) : 1
    proverPromise = PreimageProver.load('/circuits/preimage_ownership.json', threads)
  }
  return proverPromise
}

self.onmessage = async (e: MessageEvent<ProveRequest>) => {
  const { id, message, commitment, sk, opener } = e.data
  try {
    const p = await prover()
    const t0 = Date.now()
    const r = await p.prove(message, commitment, sk, opener)
    self.postMessage({ id, ...r, total: Date.now() - t0 })
  } catch (err) {
    self.postMessage({ id, error: err instanceof Error ? err.message : String(err) })
  }
}
