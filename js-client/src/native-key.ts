/**
 * EIP-8164 native-key stealth addresses (crafted-signature form).
 *
 * Mirror of `python/pq_stealth/native_key.py` — see that module and
 * `docs/research/prefix-deploy-native-keys.md` for the design. Given the
 * blinded ML-DSA-44 stealth pk (1,312 B) and a chain id, this derives the
 * deterministic "rootless" ECDSA authorization tuple from EIP-8164 and the
 * address it recovers to; that address is the native-key stealth address, and
 * the tuple is what the sender's payment transaction carries so the account
 * is PQ-governed from its first block.
 *
 * Encoding choices the draft leaves open (kept identical to the Python side):
 * chain_id in r_seed is a 32-byte big-endian integer; y_parity = 0; s = 1;
 * r must also be < n so the upward search skips [n, p).
 */

import { keccak_256 } from '@noble/hashes/sha3.js';
import { recoverAddress, toRlp, type Address, type Hex } from 'viem';

export const NATIVE_KEY_MAGIC = 0x07;
export const ML_DSA_44_DESIGNATION = new Uint8Array([0xef, 0x01, 0x01]);
export const ML_DSA_44_PK_BYTES = 1312;
const NKD_SEED_DOMAIN = new TextEncoder().encode('nkd-v1');

// secp256k1 field and group order
export const SECP_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
export const SECP_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

export interface NativeKeyAuthorization {
  chainId: bigint;
  pubkey: Uint8Array;
  nonce: bigint;
  yParity: 0 | 1;
  r: bigint;
  s: bigint;
  msgHash: Hex;
  address: Address;
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return result;
}

/** True iff x is the x-coordinate of a point on secp256k1 (x^3 + 7 is a QR). */
export function isValidX(x: bigint): boolean {
  if (x < 0n || x >= SECP_P) return false;
  const rhs = (modPow(x, 3n, SECP_P) + 7n) % SECP_P;
  if (rhs === 0n) return true;
  return modPow(rhs, (SECP_P - 1n) / 2n, SECP_P) === 1n;
}

function be32(v: bigint): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}

function bytesToBigInt(b: Uint8Array): bigint {
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  return v;
}

function toHex(b: Uint8Array): Hex {
  return `0x${Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')}`;
}

function intToMinimalHex(v: bigint): Hex {
  if (v === 0n) return '0x';
  let h = v.toString(16);
  if (h.length % 2) h = `0${h}`;
  return `0x${h}`;
}

/** keccak256(NATIVE_KEY_MAGIC || rlp([chain_id, pubkey, nonce])) */
export function authorizationMsgHash(chainId: bigint, pubkey: Uint8Array, nonce: bigint): Hex {
  const rlp = toRlp([intToMinimalHex(chainId), toHex(pubkey), intToMinimalHex(nonce)], 'bytes');
  const buf = new Uint8Array(1 + rlp.length);
  buf[0] = NATIVE_KEY_MAGIC;
  buf.set(rlp, 1);
  return toHex(keccak_256(buf));
}

/** r_seed = keccak256("nkd-v1" || chain_id || pk); r = smallest valid x >= r_seed mod p, < n. */
export function craftedR(chainId: bigint, pubkey: Uint8Array): { rSeed: Uint8Array; r: bigint } {
  const pre = new Uint8Array(NKD_SEED_DOMAIN.length + 32 + pubkey.length);
  pre.set(NKD_SEED_DOMAIN, 0);
  pre.set(be32(chainId), NKD_SEED_DOMAIN.length);
  pre.set(pubkey, NKD_SEED_DOMAIN.length + 32);
  const rSeed = keccak_256(pre);
  let x = bytesToBigInt(rSeed) % SECP_P;
  while (!(x < SECP_N && isValidX(x))) x += 1n;
  return { rSeed, r: x };
}

export async function craftAuthorization(
  pubkey: Uint8Array, chainId: bigint, nonce = 0n,
): Promise<NativeKeyAuthorization> {
  if (pubkey.length !== ML_DSA_44_PK_BYTES) {
    throw new Error('EIP-8164 0xef0101 expects a 1,312-byte ML-DSA-44 pk');
  }
  const { r } = craftedR(chainId, pubkey);
  const s = 1n;
  const yParity = 0 as const;
  const msgHash = authorizationMsgHash(chainId, pubkey, nonce);
  const address = await recoverAddress({ hash: msgHash, signature: { r: toHex(be32(r)), s: toHex(be32(s)), yParity } });
  return { chainId, pubkey, nonce, yParity, r, s, msgHash, address };
}

/** Address form for a native-key (EIP-8164) stealth account. */
export async function nativeKeyStealthAddress(stealthPk: Uint8Array, chainId: bigint): Promise<Address> {
  return (await craftAuthorization(stealthPk, chainId)).address;
}

/** The code EIP-8164 installs: 0xef0101 || pk (1,315 B). */
export function nativeKeyCode(pubkey: Uint8Array): Uint8Array {
  const out = new Uint8Array(3 + pubkey.length);
  out.set(ML_DSA_44_DESIGNATION, 0);
  out.set(pubkey, 3);
  return out;
}
