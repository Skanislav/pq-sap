/**
 * Minimal ML-DSA-65 (FIPS 204) polynomial layer — just enough for the
 * stealth-address blinding derivation: ExpandA, ExpandS, NTT arithmetic,
 * Power2Round, and public-key packing. No signing, no secret handling.
 *
 * `@noble/post-quantum` keeps this machinery in module closures, so it is
 * ported here directly from FIPS 204 and validated against the Python
 * reference vectors (python/vectors/v0/vectors.json).
 *
 * All coefficient math uses plain numbers: products are < Q^2 < 2^47,
 * well inside the 2^53 safe-integer range.
 */

import { shake128, shake256 } from '@noble/hashes/sha3.js';

export const Q = 8380417; // 2^23 - 2^13 + 1
export const N = 256;
export const K = 6;       // rows (ML-DSA-65)
export const L = 5;       // cols
export const ETA = 4;
export const D = 13;
export const Q_BITS = 23;
export const T1_BITS = 10; // Q_BITS - D

/** One polynomial: N coefficients in [0, Q). */
export type Poly = number[];

const ROOT = 1753; // 512th root of unity mod Q

function modpow(b: number, e: number, m: number): number {
  let r = 1;
  b %= m;
  while (e > 0) {
    if (e & 1) r = (r * b) % m;
    b = (b * b) % m;
    e >>= 1;
  }
  return r;
}

function bitrev8(x: number): number {
  let r = 0;
  for (let i = 0; i < 8; i++) r = (r << 1) | ((x >> i) & 1);
  return r;
}

const ZETAS: number[] = [];
for (let i = 0; i < 256; i++) ZETAS.push(modpow(ROOT, bitrev8(i), Q));
const INV256 = modpow(256, Q - 2, Q);

// ---------------------------------------------------------------------------
// NTT (FIPS 204 Algorithms 41/42), in place over coeffs in [0, Q)
// ---------------------------------------------------------------------------
export function ntt(a: Poly): Poly {
  let k = 0;
  for (let len = 128; len > 0; len >>= 1) {
    for (let start = 0; start < N; start += 2 * len) {
      const zeta = ZETAS[++k]!;
      for (let j = start; j < start + len; j++) {
        const t = (zeta * a[j + len]!) % Q;
        a[j + len] = (a[j]! - t + Q) % Q;
        a[j] = (a[j]! + t) % Q;
      }
    }
  }
  return a;
}

export function invntt(a: Poly): Poly {
  let k = 256;
  for (let len = 1; len < N; len <<= 1) {
    for (let start = 0; start < N; start += 2 * len) {
      const zeta = ZETAS[--k]!;
      for (let j = start; j < start + len; j++) {
        const t = a[j]!;
        a[j] = (t + a[j + len]!) % Q;
        a[j + len] = (t - a[j + len]! + Q) % Q;
        a[j + len] = (a[j + len]! * (Q - zeta)) % Q;
      }
    }
  }
  for (let j = 0; j < N; j++) a[j] = (a[j]! * INV256) % Q;
  return a;
}

export function polyPointwiseAcc(acc: Poly, a: Poly, b: Poly): void {
  for (let i = 0; i < N; i++) acc[i] = (acc[i]! + a[i]! * b[i]!) % Q;
}

// ---------------------------------------------------------------------------
// Samplers
// ---------------------------------------------------------------------------
/** ExpandA (FIPS 204 Alg. 32 / RejNTTPoly): K x L matrix, NTT domain. */
export function expandA(rho: Uint8Array): Poly[][] {
  const A: Poly[][] = [];
  for (let r = 0; r < K; r++) {
    const row: Poly[] = [];
    for (let s = 0; s < L; s++) {
      const xof = shake128.create({}).update(rho).update(Uint8Array.of(s, r));
      const poly: Poly = new Array<number>(N);
      let filled = 0;
      while (filled < N) {
        const buf = xof.xof(3 * (N - filled));
        for (let i = 0; i + 2 < buf.length && filled < N; i += 3) {
          const z = buf[i]! | (buf[i + 1]! << 8) | ((buf[i + 2]! & 0x7f) << 16);
          if (z < Q) poly[filled++] = z;
        }
      }
      row.push(poly);
    }
    A.push(row);
  }
  return A;
}

/** ExpandS (FIPS 204 Alg. 33 / RejBoundedPoly, eta = 4):
 *  returns { s1: L polys, s2: K polys }, coefficients in [0, Q). */
export function expandS(seed: Uint8Array): { s1: Poly[]; s2: Poly[] } {
  const samplePoly = (nonce: number): Poly => {
    const xof = shake256.create({})
      .update(seed).update(Uint8Array.of(nonce & 0xff, nonce >> 8));
    const poly: Poly = new Array<number>(N);
    let filled = 0;
    while (filled < N) {
      const buf = xof.xof(N - filled);
      for (const byte of buf) {
        for (const z of [byte & 15, byte >> 4]) {
          if (z < 9 && filled < N) poly[filled++] = (ETA - z + Q) % Q;
        }
        if (filled === N) break;
      }
    }
    return poly;
  };
  const s1: Poly[] = [], s2: Poly[] = [];
  for (let j = 0; j < L; j++) s1.push(samplePoly(j));
  for (let j = 0; j < K; j++) s2.push(samplePoly(L + j));
  return { s1, s2 };
}

// ---------------------------------------------------------------------------
// Rounding and packing
// ---------------------------------------------------------------------------
/** Power2Round (FIPS 204 Alg. 35) on a coefficient in [0, Q); returns t1. */
export function power2roundT1(c: number): number {
  let r0 = c & 8191;            // c mod 2^13
  if (r0 > 4096) r0 -= 8192;
  return (c - r0) >> D;
}

function bitPack(values: Poly, bits: number): Uint8Array {
  const out = new Uint8Array(Math.ceil((values.length * bits) / 8));
  let acc = 0, accBits = 0, pos = 0;
  for (const v of values) {
    acc |= v << accBits;
    accBits += bits;
    while (accBits >= 8) {
      out[pos++] = acc & 0xff;
      acc >>>= 8;
      accBits -= 8;
    }
  }
  if (accBits > 0) out[pos] = acc & 0xff;
  return out;
}

/** Unpack fixed-width little-endian-bit values (bits <= 23 → safe in i32). */
export function bitUnpack(data: Uint8Array, bits: number, count: number): number[] {
  const out = new Array<number>(count);
  const mask = (1 << bits) - 1;
  let acc = 0, accBits = 0, pos = 0;
  for (let i = 0; i < count; i++) {
    while (accBits < bits) {
      acc |= data[pos++]! << accBits;
      accBits += 8;
    }
    out[i] = acc & mask;
    acc >>>= bits;
    accBits -= bits;
  }
  return out;
}

/** pkEncode (FIPS 204 Alg. 22): rho || t1 packed at 10 bits/coeff. */
export function packPk(rho: Uint8Array, t1Polys: Poly[]): Uint8Array {
  const pk = new Uint8Array(32 + (K * N * T1_BITS) / 8); // 1952
  pk.set(rho, 0);
  let off = 32;
  for (const poly of t1Polys) {
    pk.set(bitPack(poly, T1_BITS), off);
    off += (N * T1_BITS) / 8;
  }
  return pk;
}
