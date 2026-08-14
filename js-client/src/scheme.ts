/**
 * PQ stealth address scanning — client side.
 *
 * Mirrors python/pq_stealth: decode a meta-address, decapsulate the
 * announcement's ML-KEM ciphertext with the viewing key, check the view
 * tag, re-derive the blinded ML-DSA-65 stealth key, compare addresses.
 *
 * Scanning requires only the VIEWING key (the ML-KEM decapsulation key);
 * spending secrets never touch this code path.
 */

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256, shake256 } from '@noble/hashes/sha3.js';

import {
  Q, N, K, L, Q_BITS,
  ntt, invntt, polyPointwiseAcc,
  expandA, expandS, power2roundT1, bitUnpack, packPk,
  type Poly,
} from './mldsa65.ts';

export const META_ADDRESS_VERSION = 0x01;
export const META_ADDRESS_BYTES = 1 + 32 + (K * N * Q_BITS) / 8 + 1184; // 5633
export const EPHEMERAL_PUB_KEY_BYTES = 1088;
export const VIEW_TAG_BYTES = 1;

export interface MetaAddress {
  rho: Uint8Array;
  t: Poly[];          // full-precision t, K polynomials
  kemEk: Uint8Array;  // ML-KEM-768 encapsulation key
}

export interface AnnouncementData {
  stealthAddress: Uint8Array;   // 20 bytes
  ephemeralPubKey: Uint8Array;  // ML-KEM ciphertext R
  viewTag: Uint8Array;
}

export interface Payment {
  sharedSecret: Uint8Array;
  stealthPk: Uint8Array;
}

/** meta = version(1) || rho(32) || t(23-bit packed) || ML-KEM ek(1184) */
export function decodeMetaAddress(bytes: Uint8Array): MetaAddress {
  if (bytes.length !== META_ADDRESS_BYTES)
    throw new Error(`meta-address must be ${META_ADDRESS_BYTES} bytes, got ${bytes.length}`);
  if (bytes[0] !== META_ADDRESS_VERSION)
    throw new Error(`unsupported meta-address version 0x${bytes[0]!.toString(16)}`);
  const rho = bytes.slice(1, 33);
  const tBytes = bytes.slice(33, 33 + (K * N * Q_BITS) / 8);
  const coeffs = bitUnpack(tBytes, Q_BITS, K * N);
  const t: Poly[] = [];
  for (let r = 0; r < K; r++) t.push(coeffs.slice(r * N, (r + 1) * N));
  const kemEk = bytes.slice(33 + tBytes.length);
  return { rho, t, kemEk };
}

/** (s', e') = ExpandS(SHAKE256(ss, 64)); t' = A*s' + e' + t; pack rounded pk. */
export function deriveStealthPk(rho: Uint8Array, t: Poly[], ss: Uint8Array): Uint8Array {
  const seed = shake256(ss, { dkLen: 64 });
  const { s1: sP, s2: eP } = expandS(seed);
  const A = expandA(rho); // NTT domain

  const sHat = sP.map((p) => ntt([...p]));
  const t1: Poly[] = [];
  for (let r = 0; r < K; r++) {
    const acc: Poly = new Array<number>(N).fill(0);
    for (let s = 0; s < L; s++) polyPointwiseAcc(acc, A[r]![s]!, sHat[s]!);
    const u = invntt(acc);
    const row: Poly = new Array<number>(N);
    for (let i = 0; i < N; i++) {
      row[i] = power2roundT1((u[i]! + eP[r]![i]! + t[r]![i]!) % Q);
    }
    t1.push(row);
  }
  return packPk(rho, t1);
}

export function stealthAddressOf(stealthPk: Uint8Array): Uint8Array {
  return keccak_256(stealthPk).slice(12);
}

export function computeViewTag(ss: Uint8Array): Uint8Array {
  return sha256(ss).slice(0, VIEW_TAG_BYTES);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/**
 * Check one announcement. Returns the payment on a match, null otherwise.
 * Malformed ciphertexts yield null, never an exception.
 */
export function checkAnnouncement(
  meta: MetaAddress, kemDk: Uint8Array, ann: AnnouncementData,
): Payment | null {
  let ss: Uint8Array;
  try {
    ss = ml_kem768.decapsulate(ann.ephemeralPubKey, kemDk);
  } catch {
    return null;
  }
  if (!bytesEqual(computeViewTag(ss), ann.viewTag)) return null;
  const pk = deriveStealthPk(meta.rho, meta.t, ss);
  if (!bytesEqual(stealthAddressOf(pk), ann.stealthAddress)) return null;
  return { sharedSecret: ss, stealthPk: pk };
}

export function scan(
  meta: MetaAddress, kemDk: Uint8Array, announcements: AnnouncementData[],
): Array<Payment & { announcement: AnnouncementData }> {
  const hits: Array<Payment & { announcement: AnnouncementData }> = [];
  for (const ann of announcements) {
    const payment = checkAnnouncement(meta, kemDk, ann);
    if (payment) hits.push({ announcement: ann, ...payment });
  }
  return hits;
}
