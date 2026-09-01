/**
 * EIP-8141 frame transaction (type 0x06) serialization.
 *
 * Wire format is transcribed from the DEPLOYED chain, not the spec draft: the
 * authoritative source is ethrex `crates/common/types/transaction.rs` at commit
 * 2e1352b (the commit the public frames testnet, chain 81410, actually runs).
 * Two facts the older `docs/eip-8141.md` gets wrong:
 *   - each frame carries TWO gas budgets, `limits = [execution, state]`
 *     (EIP-8037), encoded as a nested 2-list — not a flat `gas_limit`;
 *   - the three fee fields are encoded as a single nested 3-tuple, so the
 *     envelope body has 7 elements, not 9.
 *
 * Canonical (broadcast) form:
 *   0x06 || rlp([ chain_id, nonce, sender, frames, signatures,
 *                 [max_priority_fee, max_fee, max_fee_per_blob],
 *                 blob_versioned_hashes ])
 * where
 *   frame     = [mode, flags, target, [execution, state], value, data]
 *   signature = [scheme, signer, msg, signature]
 *
 * The sig-hash a signer with empty `msg` signs is
 *   keccak256(0x06 || rlp(body with empty-msg signatures' `signature` elided)).
 */

import type { Address, Hex } from 'viem';
import { keccak256, toRlp } from 'viem';

// --- constants (ethrex transaction.rs) ---------------------------------------

export const FRAME_TX_TYPE = 0x06;

export const FRAME_MODE = { DEFAULT: 0, VERIFY: 1, SENDER: 2 } as const;

/** APPROVE scope bits (flags bits 0-1) and the atomic-batch bit (bit 2). */
export const APPROVE_SCOPE = { NONE: 0, PAYMENT: 1, EXECUTION: 2, BOTH: 3 } as const;
export const FLAG_ATOMIC_BATCH = 0x04;

export const SIG_SCHEME = { ARBITRARY: 0, SECP256K1: 1, P256: 2 } as const;

/** Intrinsic gas accounting (EIP-8141), for the offline estimator. */
export const FRAME_TX_INTRINSIC_COST = 12000n;
export const FRAME_TX_PER_FRAME_COST = 475n;
export const TX_VALUE_COST = 6000n; // EIP-2780, charged once per value-moving frame
export const SIG_VERIFY_COST = { 0: 100n, 1: 2800n, 2: 6700n } as const; // by scheme

// --- types -------------------------------------------------------------------

export interface Frame {
  mode: number;
  flags: number;
  /** 20-byte address, or null to resolve to `tx.sender`. */
  target: Address | null;
  /** limits.execution — the execution-gas budget. */
  executionGas: bigint;
  /** limits.state — the EIP-8037 state-gas budget (independent of execution). */
  stateGas: bigint;
  /** wei; must be 0 unless the frame is SENDER. */
  value: bigint;
  data: Hex;
}

export interface FrameSignature {
  scheme: number;
  /** 20-byte address, or null (required null for ARBITRARY). */
  signer: Address | null;
  /** empty (`0x`) = signs compute_sig_hash(tx); else an explicit 32-byte digest. */
  msg: Hex;
  signature: Hex;
}

export interface FrameTx {
  chainId: bigint;
  nonce: bigint;
  sender: Address;
  frames: Frame[];
  signatures: FrameSignature[];
  maxPriorityFeePerGas: bigint;
  maxFeePerGas: bigint;
  maxFeePerBlobGas: bigint;
  blobVersionedHashes: Hex[];
}

// --- RLP helpers -------------------------------------------------------------

// viem's toRlp takes a recursive tree of Hex leaves. Integers RLP-encode as
// minimal big-endian byte strings; zero encodes as the empty string (0x80).
type RlpTree = Hex | RlpTree[];

const EMPTY: Hex = '0x';

/** Minimal big-endian hex for a non-negative integer; 0 -> '0x' (empty). */
function int(v: bigint | number): Hex {
  let n = typeof v === 'bigint' ? v : BigInt(v);
  if (n < 0n) throw new Error('frame-tx: negative integer field');
  if (n === 0n) return EMPTY;
  let s = n.toString(16);
  if (s.length % 2) s = '0' + s;
  return `0x${s}`;
}

/** Address as a 20-byte string, or RLP-null (empty) for `null`. */
function addr(a: Address | null): Hex {
  return a === null ? EMPTY : (a.toLowerCase() as Hex);
}

function frameTree(f: Frame): RlpTree {
  if (f.mode !== FRAME_MODE.SENDER && f.value !== 0n) {
    throw new Error('frame-tx: only SENDER frames may carry a non-zero value');
  }
  return [
    int(f.mode),
    int(f.flags),
    addr(f.target),
    [int(f.executionGas), int(f.stateGas)],
    int(f.value),
    f.data === '0x' ? EMPTY : f.data,
  ];
}

function sigTree(s: FrameSignature): RlpTree {
  if (s.scheme === SIG_SCHEME.ARBITRARY && s.signer !== null) {
    throw new Error('frame-tx: ARBITRARY signature must have a null signer');
  }
  return [int(s.scheme), addr(s.signer), s.msg === '0x' ? EMPTY : s.msg,
    s.signature === '0x' ? EMPTY : s.signature];
}

/** RLP body shared by the canonical form and the sig-hash preimage. */
function bodyTree(tx: FrameTx, signatures: FrameSignature[]): RlpTree {
  return [
    int(tx.chainId),
    int(tx.nonce),
    addr(tx.sender),
    tx.frames.map(frameTree),
    signatures.map(sigTree),
    [int(tx.maxPriorityFeePerGas), int(tx.maxFeePerGas), int(tx.maxFeePerBlobGas)],
    tx.blobVersionedHashes,
  ];
}

// --- public API --------------------------------------------------------------

/** The `0x06 || rlp(body)` bytes ready for `eth_sendRawTransaction`. */
export function serializeFrameTx(tx: FrameTx): Hex {
  const body = toRlp(bodyTree(tx, tx.signatures));
  return `0x06${body.slice(2)}`;
}

/**
 * The digest a signature with empty `msg` signs: keccak256 over the canonical
 * bytes with every empty-`msg` signature's `signature` field elided to empty
 * (frames, and explicit-`msg` signatures, committed verbatim).
 */
export function frameTxSigHash(tx: FrameTx): Hex {
  const elided = tx.signatures.map((s) =>
    s.msg === '0x' ? { ...s, signature: EMPTY as Hex } : s);
  const body = toRlp(bodyTree(tx, elided));
  return keccak256(`0x06${body.slice(2)}`);
}

/** Intrinsic (pre-execution) gas: mandatory costs only, excludes Σ frame gas. */
export function intrinsicGas(tx: FrameTx): bigint {
  let g = FRAME_TX_INTRINSIC_COST + FRAME_TX_PER_FRAME_COST * BigInt(tx.frames.length);
  for (const f of tx.frames) if (f.value !== 0n) g += TX_VALUE_COST;
  for (const s of tx.signatures) {
    g += SIG_VERIFY_COST[s.scheme as keyof typeof SIG_VERIFY_COST] ?? 0n;
  }
  return g;
}
