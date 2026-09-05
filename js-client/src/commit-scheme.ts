/**
 * Commitment meta-address (format 0x02) — the key-exchange-only scheme.
 * Mirror of `python/pq_stealth/commit.py`; see D-024.
 *
 *   meta-address = 0x02 || spendKey(32) || ML-KEM-768 ek(1184)      (1,217 B)
 *   opener       = SHA-256(openDomain || ss)
 *   commitment   = keccak256(commitDomain || spendKey || opener)
 *   address      = CREATE2(factory, salt 0, initcode(commitment, verifier, frameCtx))
 *
 * The spend key never appears at receive time and the meta-address carries no
 * lattice material; spending is whatever the account bound to the commitment
 * accepts (revealed C13 signature, ZK proof, or a protocol-native dependency).
 */

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatHex, getContractAddress, hexToBytes, keccak256, pad, type Address, type Hex } from 'viem';

import { sphincsC13Commitment, sphincsC13Opener } from './sphincs.ts';

export const COMMIT_META_ADDRESS_VERSION = 0x02;
export const SPEND_KEY_BYTES = 32;
export const ML_KEM_768_EK_BYTES = 1184;
export const ML_KEM_768_CT_BYTES = 1088;
export const COMMIT_META_ADDRESS_BYTES = 1 + SPEND_KEY_BYTES + ML_KEM_768_EK_BYTES; // 1217
export const VIEW_TAG_BYTES = 1;

export interface CommitMetaAddress {
  spendKey: Hex;      // 32-byte commitment to / encoding of the spending public key
  kemEk: Uint8Array;  // ML-KEM-768 encapsulation key
}

/** Chain binding of a commitment to a payable address (Stealth8141ZkFactory shape). */
export interface Deployment {
  factory: Address;
  creationCode: Hex;   // account creation code without constructor args
  verifier: Address;
  frameCtx: Address;
  salt?: Hex;          // default 0
}

export interface CommitAnnouncementData {
  stealthAddress: Address;
  ephemeralPubKey: Uint8Array;  // ML-KEM ciphertext
  viewTag: Uint8Array;
}

export interface CommitPayment {
  sharedSecret: Uint8Array;
  opener: Hex;
  commitment: Hex;
}

const toHex = (b: Uint8Array): Hex => `0x${Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')}`;

export function encodeCommitMetaAddress(spendKey: Hex, kemEk: Uint8Array): Uint8Array {
  const key = hexToBytes(spendKey);
  if (key.length !== SPEND_KEY_BYTES) throw new Error('spend key commitment must be 32 bytes');
  if (kemEk.length !== ML_KEM_768_EK_BYTES) throw new Error(`ML-KEM-768 ek must be ${ML_KEM_768_EK_BYTES} bytes`);
  const out = new Uint8Array(COMMIT_META_ADDRESS_BYTES);
  out[0] = COMMIT_META_ADDRESS_VERSION;
  out.set(key, 1);
  out.set(kemEk, 33);
  return out;
}

export function decodeCommitMetaAddress(bytes: Uint8Array): CommitMetaAddress {
  if (bytes.length !== COMMIT_META_ADDRESS_BYTES)
    throw new Error(`commit meta-address must be ${COMMIT_META_ADDRESS_BYTES} bytes, got ${bytes.length}`);
  if (bytes[0] !== COMMIT_META_ADDRESS_VERSION)
    throw new Error(`unsupported meta-address version 0x${bytes[0]!.toString(16)}`);
  return { spendKey: toHex(bytes.slice(1, 33)), kemEk: bytes.slice(33) };
}

/** Domain separation of the opener/commitment derivation; one set per spend scheme. */
export interface CommitDomains {
  open: string;
  commit: string;
}
/** The deployed SPHINCS- C13 commit signer / C13 ZK circuit (D-018, D-023). */
export const SPHINCS_C13_DOMAINS: CommitDomains = { open: 'pq-stealth/sphincs-c13/open/v0', commit: 'pq-stealth/sphincs-c13/commit/v0' };
/** Preimage-ownership spend (D-025, noir/preimage-ownership): spend_key = keccak(KEY || sk). */
export const PREIMAGE_DOMAINS: CommitDomains = { open: 'pq-stealth/preimage/open/v0', commit: 'pq-stealth/preimage/commit/v0' };
export const PREIMAGE_KEY_DOMAIN = 'pq-stealth/preimage/key/v0';

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function deriveOpener(ss: Uint8Array, domains: CommitDomains = SPHINCS_C13_DOMAINS): Hex {
  if (domains === SPHINCS_C13_DOMAINS) return sphincsC13Opener(ss);
  const dom = utf8(domains.open);
  const buf = new Uint8Array(dom.length + ss.length);
  buf.set(dom, 0);
  buf.set(ss, dom.length);
  return toHex(sha256(buf));
}

export function deriveCommitment(spendKey: Hex, opener: Hex, domains: CommitDomains = SPHINCS_C13_DOMAINS): Hex {
  if (domains === SPHINCS_C13_DOMAINS) return sphincsC13Commitment(spendKey, opener);
  return keccak256(concatHex([toHex(utf8(domains.commit)), spendKey, opener]));
}

/** spend_key = keccak256(KEY_DOMAIN || sk): the 32-byte value the meta-address carries. */
export function spendKeyFromSecret(sk: Uint8Array): Hex {
  if (sk.length !== 32) throw new Error('spending secret must be 32 bytes');
  const dom = utf8(PREIMAGE_KEY_DOMAIN);
  const buf = new Uint8Array(dom.length + 32);
  buf.set(dom, 0);
  buf.set(sk, dom.length);
  return keccak256(buf);
}

export function computeViewTag(ss: Uint8Array): Uint8Array {
  return sha256(ss).slice(0, VIEW_TAG_BYTES);
}

/** CREATE2(factory, salt, keccak256(creationCode || abi.encode(commitment, verifier, frameCtx))). */
export function accountAddress(commitment: Hex, dep: Deployment): Address {
  const initCode = concatHex([dep.creationCode, commitment, pad(dep.verifier, { size: 32 }), pad(dep.frameCtx, { size: 32 })]);
  return getContractAddress({
    opcode: 'CREATE2', from: dep.factory, salt: dep.salt ?? `0x${'00'.repeat(32)}`, bytecodeHash: keccak256(initCode),
  });
}

/** Sender: encapsulate (or reuse given randomness via `encapsulate`), derive the account. */
export function sendCommit(
  meta: CommitMetaAddress, dep: Deployment, encaps?: { cipherText: Uint8Array; sharedSecret: Uint8Array },
  domains: CommitDomains = SPHINCS_C13_DOMAINS,
): { announcement: CommitAnnouncementData; commitment: Hex; sharedSecret: Uint8Array } {
  const { cipherText, sharedSecret } = encaps ?? ml_kem768.encapsulate(meta.kemEk);
  const commitment = deriveCommitment(meta.spendKey, deriveOpener(sharedSecret, domains), domains);
  return {
    announcement: { stealthAddress: accountAddress(commitment, dep), ephemeralPubKey: cipherText, viewTag: computeViewTag(sharedSecret) },
    commitment, sharedSecret,
  };
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/** Viewing-key scan of one announcement: view tag fast path, then re-derive the account. */
export function checkCommitAnnouncement(
  meta: CommitMetaAddress, kemDk: Uint8Array, ann: CommitAnnouncementData, dep: Deployment,
  domains: CommitDomains = SPHINCS_C13_DOMAINS,
): CommitPayment | null {
  let ss: Uint8Array;
  try {
    ss = ml_kem768.decapsulate(ann.ephemeralPubKey, kemDk);
  } catch {
    return null;
  }
  if (!bytesEqual(computeViewTag(ss), ann.viewTag)) return null;
  const opener = deriveOpener(ss, domains);
  const commitment = deriveCommitment(meta.spendKey, opener, domains);
  if (accountAddress(commitment, dep).toLowerCase() !== ann.stealthAddress.toLowerCase()) return null;
  return { sharedSecret: ss, opener, commitment };
}

export function scanCommit(
  meta: CommitMetaAddress, kemDk: Uint8Array, announcements: CommitAnnouncementData[], dep: Deployment,
  domains: CommitDomains = SPHINCS_C13_DOMAINS,
): Array<CommitPayment & { announcement: CommitAnnouncementData }> {
  const hits: Array<CommitPayment & { announcement: CommitAnnouncementData }> = [];
  for (const ann of announcements) {
    const p = checkCommitAnnouncement(meta, kemDk, ann, dep, domains);
    if (p) hits.push({ announcement: ann, ...p });
  }
  return hits;
}
