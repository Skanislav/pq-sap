/**
 * Recipient key generation — mirrors python/pq_stealth/meta.py.
 *
 * Spending key follows FIPS 204 Algorithm 6 key expansion but keeps t at
 * FULL precision (the sender's Power2Round(A*s' + e' + t) needs the
 * unrounded value). Viewing key is a standard ML-KEM-768 keypair.
 *
 * Deterministic when seeds are supplied (test vectors); random otherwise.
 */

import { shake256 } from '@noble/hashes/sha3.js'
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js'

import {
  bitPack,
  expandA,
  expandS,
  invntt,
  K,
  L,
  N,
  ntt,
  type Poly,
  polyPointwiseAcc,
  Q,
  Q_BITS,
} from '../../../js-client/src/mldsa65.ts'
import { META_ADDRESS_BYTES, META_ADDRESS_VERSION } from '../../../js-client/src/scheme.ts'

export interface RecipientSeeds {
  zeta: Uint8Array // 32 B — ML-DSA key seed (xi)
  kemD: Uint8Array // 32 B — ML-KEM d
  kemZ: Uint8Array // 32 B — ML-KEM z
}

export interface RecipientKeys {
  seeds: RecipientSeeds
  metaAddress: Uint8Array // version || rho || pack23(t) || kem ek  (5,633 B)
  kemDk: Uint8Array // ML-KEM decapsulation key = the VIEWING key (2,400 B)
}

export function randomSeeds(): RecipientSeeds {
  const rand = (): Uint8Array => crypto.getRandomValues(new Uint8Array(32))
  return { zeta: rand(), kemD: rand(), kemZ: rand() }
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let off = 0
  for (const p of parts) {
    out.set(p, off)
    off += p.length
  }
  return out
}

/** seed = SHAKE256(zeta || k || l, 128); rho = seed[:32], rho' = seed[32:96]. */
export function deriveMetaAddress(seeds: RecipientSeeds): RecipientKeys {
  const seed = shake256(concat(seeds.zeta, Uint8Array.of(K, L)), { dkLen: 128 })
  const rho = seed.slice(0, 32)
  const rhoPrime = seed.slice(32, 96)

  const { s1, s2 } = expandS(rhoPrime)
  const A = expandA(rho) // NTT domain
  const s1Hat = s1.map((p) => ntt([...p]))

  // t = invntt(A @ ntt(s1)) + s2, full precision, coefficients in [0, Q)
  const tFlat: Poly = new Array<number>(K * N)
  for (let r = 0; r < K; r++) {
    const acc: Poly = new Array<number>(N).fill(0)
    for (let s = 0; s < L; s++) polyPointwiseAcc(acc, A[r]![s]!, s1Hat[s]!)
    const u = invntt(acc)
    for (let i = 0; i < N; i++) {
      tFlat[r * N + i] = (u[i]! + s2[r]![i]!) % Q
    }
  }

  const { publicKey: kemEk, secretKey: kemDk } = ml_kem768.keygen(concat(seeds.kemD, seeds.kemZ))

  const metaAddress = concat(Uint8Array.of(META_ADDRESS_VERSION), rho, bitPack(tFlat, Q_BITS), kemEk)
  if (metaAddress.length !== META_ADDRESS_BYTES)
    throw new Error(`meta-address is ${metaAddress.length} B, expected ${META_ADDRESS_BYTES}`)
  return { seeds, metaAddress, kemDk }
}
