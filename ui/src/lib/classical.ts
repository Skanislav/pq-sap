/**
 * Classical-spend hybrid — mirrors python/pq_stealth/classical.
 *
 * Discovery is post-quantum (ML-KEM-768 like the ML-DSA scheme); the
 * SPENDING key is secp256k1, additively blinded:
 *
 *     t = SHAKE256("pq-stealth/classical/tweak/v0" || ss, 48) mod (n-1) + 1
 *     P = K + t*G          (sender / scanner: public inputs only)
 *     p = (k + t) mod n    (recipient: controls the stealth EOA)
 *
 * The stealth address is a plain EOA, so spending is one ordinary ECDSA
 * transaction — ecrecover, ~21k gas, any wallet — no account contract and
 * no on-chain PQ verification. (Threat model D-001: harvest-now-decrypt-
 * later breaks unlinkability, not ECDSA ownership; spend-side PQ is the
 * separate 4337 route.)
 */

import { secp256k1 } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { keccak_256, shake256 } from '@noble/hashes/sha3.js'
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js'

import type { AnnouncementData, Payment } from '../../../js-client/src/scheme.ts'

export const CLASSICAL_META_VERSION = 0x01
export const CLASSICAL_META_BYTES = 1 + 33 + 1184 // version || spend_pub || kem ek
const TWEAK_DOMAIN = 'pq-stealth/classical/tweak/v0'
const TWEAK_SEED_BYTES = 48
const N = secp256k1.Point.Fn.ORDER

export interface ClassicalMeta {
  spendPub: Uint8Array // compressed secp256k1 point, 33 B
  kemEk: Uint8Array // ML-KEM-768 encapsulation key
}

export interface ClassicalSeeds {
  spendSeed: Uint8Array // 32 B — IS the spending secret key
  kemD: Uint8Array
  kemZ: Uint8Array
}

export interface ClassicalKeys {
  seeds: ClassicalSeeds
  metaAddress: Uint8Array
  kemDk: Uint8Array
}

export function randomClassicalSeeds(): ClassicalSeeds {
  // rejection-sample the spend seed into [1, n-1] (~2^-128 retry chance)
  let spendSeed: Uint8Array
  do {
    spendSeed = crypto.getRandomValues(new Uint8Array(32))
  } while (!secp256k1.utils.isValidSecretKey(spendSeed))
  return {
    spendSeed,
    kemD: crypto.getRandomValues(new Uint8Array(32)),
    kemZ: crypto.getRandomValues(new Uint8Array(32)),
  }
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((s, p) => s + p.length, 0))
  let off = 0
  for (const p of parts) {
    out.set(p, off)
    off += p.length
  }
  return out
}

const bytesToBigint = (b: Uint8Array): bigint =>
  BigInt('0x' + Array.from(b, (x) => x.toString(16).padStart(2, '0')).join(''))

const pointFromBytes = (b: Uint8Array) =>
  secp256k1.Point.fromHex(Array.from(b, (x) => x.toString(16).padStart(2, '0')).join(''))

export function deriveClassicalKeys(seeds: ClassicalSeeds): ClassicalKeys {
  const spendPub = secp256k1.getPublicKey(seeds.spendSeed, true)
  const { publicKey: kemEk, secretKey: kemDk } = ml_kem768.keygen(concat(seeds.kemD, seeds.kemZ))
  const metaAddress = concat(Uint8Array.of(CLASSICAL_META_VERSION), spendPub, kemEk)
  if (metaAddress.length !== CLASSICAL_META_BYTES) throw new Error(`classical meta-address is ${metaAddress.length} B`)
  return { seeds, metaAddress, kemDk }
}

export function decodeClassicalMeta(bytes: Uint8Array): ClassicalMeta {
  if (bytes.length !== CLASSICAL_META_BYTES)
    throw new Error(`classical meta-address must be ${CLASSICAL_META_BYTES} bytes, got ${bytes.length}`)
  if (bytes[0] !== CLASSICAL_META_VERSION)
    throw new Error(`unsupported classical meta-address version 0x${bytes[0]!.toString(16)}`)
  const spendPub = bytes.slice(1, 34)
  pointFromBytes(spendPub) // validate the point
  return { spendPub, kemEk: bytes.slice(34) }
}

/** t in [1, n-1] from the KEM shared secret. */
export function deriveTweak(ss: Uint8Array): bigint {
  const seed = shake256(concat(new TextEncoder().encode(TWEAK_DOMAIN), ss), { dkLen: TWEAK_SEED_BYTES })
  return (bytesToBigint(seed) % (N - 1n)) + 1n
}

/** P = K + t*G — sender side / scanner side, public inputs only. */
export function deriveStealthPubkey(spendPub: Uint8Array, ss: Uint8Array) {
  const t = deriveTweak(ss)
  return pointFromBytes(spendPub).add(secp256k1.Point.BASE.multiply(t))
}

/** Standard EOA rule: keccak256(uncompressed point minus 0x04)[12:]. */
export function ethAddressOfPoint(P: InstanceType<typeof secp256k1.Point>): Uint8Array {
  return keccak_256(P.toBytes(false).slice(1)).slice(12)
}

/** p = (k + t) mod n — the stealth EOA's private key. Recipient only. */
export function deriveStealthPrivkey(spendSeed: Uint8Array, ss: Uint8Array): Uint8Array {
  const p = (bytesToBigint(spendSeed) + deriveTweak(ss)) % N
  if (p === 0n) throw new Error('degenerate stealth key')
  const out = new Uint8Array(32)
  const hex = p.toString(16).padStart(64, '0')
  for (let i = 0; i < 32; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16)
  return out
}

// --- compact meta-address (the "ecrecover trick" format) -------------------
//
// 65 bytes: spend_pub(33, SEC1 compressed: version/parity prefix 0x02/0x03
// + 32-byte x) || registry_index(32). The spending key rides INLINE — a
// compromised registry can deny detection but never redirect funds — while
// the 1,184-byte ML-KEM viewing key is resolved from the on-chain
// StealthKeyRegistry by index. 32 bytes suffice for the pubkey because
// stealth outputs are ADDRESSES (ecrecover-compatible EOAs): the parity
// bit lives in the version byte and full point math stays client-side.

export const COMPACT_META_BYTES = 65

export interface CompactMeta {
  spendPub: Uint8Array // 33 B compressed
  index: bigint // StealthKeyRegistry index of the viewing key
}

export function encodeCompactMeta(spendPub: Uint8Array, index: bigint): Uint8Array {
  if (spendPub.length !== 33 || (spendPub[0] !== 0x02 && spendPub[0] !== 0x03))
    throw new Error('spend pubkey must be SEC1 compressed (33 bytes)')
  if (index < 0n || index >= 1n << 256n) throw new Error('index out of range')
  const out = new Uint8Array(COMPACT_META_BYTES)
  out.set(spendPub, 0)
  const hex = index.toString(16).padStart(64, '0')
  for (let i = 0; i < 32; i++) out[33 + i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16)
  return out
}

export function decodeCompactMeta(bytes: Uint8Array): CompactMeta {
  if (bytes.length !== COMPACT_META_BYTES)
    throw new Error(`compact meta-address must be ${COMPACT_META_BYTES} bytes, got ${bytes.length}`)
  if (bytes[0] !== 0x02 && bytes[0] !== 0x03)
    throw new Error(`unsupported compact meta version/parity byte 0x${bytes[0]!.toString(16)}`)
  const spendPub = bytes.slice(0, 33)
  pointFromBytes(spendPub) // validate the point
  return { spendPub, index: bytesToBigint(bytes.slice(33)) }
}

export function classicalViewTag(ss: Uint8Array): Uint8Array {
  return sha256(ss).slice(0, 1) // shared announcement rail with the ML-DSA scheme
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let d = 0
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!
  return d === 0
}

/** Scanner check for one announcement; null unless it pays this recipient. */
export function checkClassicalAnnouncement(
  meta: ClassicalMeta,
  kemDk: Uint8Array,
  ann: AnnouncementData,
): Payment | null {
  let ss: Uint8Array
  try {
    ss = ml_kem768.decapsulate(ann.ephemeralPubKey, kemDk)
  } catch {
    return null
  }
  if (!bytesEqual(classicalViewTag(ss), ann.viewTag)) return null
  const P = deriveStealthPubkey(meta.spendPub, ss)
  if (!bytesEqual(ethAddressOfPoint(P), ann.stealthAddress)) return null
  return { sharedSecret: ss, stealthPk: P.toBytes(true) }
}
