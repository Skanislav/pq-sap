/**
 * EIP-8141 frame builders, secp256k1 outer-signature signing, and the EOA
 * transfer pattern that `rex` uses (verified byte-identical against its
 * `frame send --dry-run` output on chain 81410).
 *
 * An EOA has no code to call APPROVE, so a plain frame-tx transfer is authorized
 * by the protocol-validated secp256k1 signature: a VERIFY frame targeting the
 * sender with scope BOTH (flags 0x3) records execution+payment approval, then a
 * SENDER frame does the actual transfer.
 */

import type { Address, Hex } from 'viem';
import { sign } from 'viem/accounts';

import {
  FRAME_MODE, APPROVE_SCOPE, SIG_SCHEME,
  serializeFrameTx, frameTxSigHash,
  type Frame, type FrameSignature, type FrameTx,
} from './serialize.ts';

// --- frame builders ----------------------------------------------------------

export function defaultFrame(p: Partial<Frame> & Pick<Frame, 'target'>): Frame {
  return { mode: FRAME_MODE.DEFAULT, flags: 0, target: p.target,
    executionGas: p.executionGas ?? 0n, stateGas: p.stateGas ?? 0n,
    value: p.value ?? 0n, data: p.data ?? '0x' };
}

export function verifyFrame(p: Partial<Frame> & Pick<Frame, 'target'>): Frame {
  return { mode: FRAME_MODE.VERIFY, flags: p.flags ?? APPROVE_SCOPE.BOTH, target: p.target,
    executionGas: p.executionGas ?? 0n, stateGas: p.stateGas ?? 0n,
    value: 0n, data: p.data ?? '0x' };
}

export function senderFrame(p: Partial<Frame> & Pick<Frame, 'target'>): Frame {
  return { mode: FRAME_MODE.SENDER, flags: p.flags ?? 0, target: p.target,
    executionGas: p.executionGas ?? 0n, stateGas: p.stateGas ?? 0n,
    value: p.value ?? 0n, data: p.data ?? '0x' };
}

/** An ARBITRARY-scheme signature carrying raw bytes (e.g. a PQ signature). */
export function arbitrarySignature(signature: Hex): FrameSignature {
  return { scheme: SIG_SCHEME.ARBITRARY, signer: null, msg: '0x', signature };
}

/** A placeholder secp256k1 entry (empty bytes) so sig_hash sees final structure. */
export function secp256k1Placeholder(signer: Address): FrameSignature {
  return { scheme: SIG_SCHEME.SECP256K1, signer, msg: '0x', signature: '0x' };
}

// --- secp256k1 outer signature ----------------------------------------------

/**
 * Sign a frame-tx sig_hash and encode it the way ethrex expects:
 * `v(1) || r(32) || s(32)` with v a BARE recovery id (0/1, not 27/28) and
 * low-s. viem's `sign` already produces canonical low-s and a 0/1 yParity.
 */
export async function secp256k1FrameSignature(
  sigHash: Hex, signer: Address, privateKey: Hex,
): Promise<FrameSignature> {
  const { r, s, yParity } = await sign({ hash: sigHash, privateKey });
  const v = yParity === 0 ? '00' : '01';
  const rr = r.slice(2).padStart(64, '0');
  const ss = s.slice(2).padStart(64, '0');
  return { scheme: SIG_SCHEME.SECP256K1, signer, msg: '0x', signature: `0x${v}${rr}${ss}` };
}

// --- EOA transfer (the rex-compatible pattern) -------------------------------

export interface EoaTransferParams {
  chainId: bigint;
  nonce: bigint;
  sender: Address;
  to: Address;
  value: bigint;
  data?: Hex;
  privateKey: Hex;
  frameGas?: bigint; // limits.execution per frame (rex default 100000)
  frameStateGas?: bigint; // limits.state per frame (rex default 250000)
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
}

/**
 * Build and secp256k1-sign a `[VERIFY(sender, BOTH), SENDER(to, value)]`
 * transfer, returning the signed FrameTx and its `0x06` raw bytes ready for
 * `eth_sendRawTransaction`.
 */
export async function buildEoaTransfer(p: EoaTransferParams): Promise<{ tx: FrameTx; raw: Hex; sigHash: Hex }> {
  const frameGas = p.frameGas ?? 100_000n;
  const frameStateGas = p.frameStateGas ?? 250_000n;
  const frames: Frame[] = [
    verifyFrame({ target: p.sender, flags: APPROVE_SCOPE.BOTH, executionGas: frameGas, stateGas: frameStateGas }),
    senderFrame({ target: p.to, executionGas: frameGas, stateGas: frameStateGas, value: p.value, data: p.data ?? '0x' }),
  ];
  const unsigned: FrameTx = {
    chainId: p.chainId, nonce: p.nonce, sender: p.sender, frames,
    signatures: [secp256k1Placeholder(p.sender)],
    maxPriorityFeePerGas: p.maxPriorityFeePerGas, maxFeePerGas: p.maxFeePerGas,
    maxFeePerBlobGas: 0n, blobVersionedHashes: [],
  };
  const sigHash = frameTxSigHash(unsigned);
  const sig = await secp256k1FrameSignature(sigHash, p.sender, p.privateKey);
  const tx: FrameTx = { ...unsigned, signatures: [sig] };
  return { tx, raw: serializeFrameTx(tx), sigHash };
}

// --- submission --------------------------------------------------------------

/** POST a JSON-RPC method to an EIP-8141 node. */
export async function rpc<T = unknown>(rpcUrl: string, method: string, params: unknown[]): Promise<T> {
  const res = await fetch(rpcUrl, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const j = await res.json() as { result?: T; error?: { code: number; message: string } };
  if (j.error) throw new Error(`${method}: ${j.error.code} ${j.error.message}`);
  return j.result as T;
}

/** Send a raw `0x06` frame tx; returns the tx hash. */
export function sendRawFrameTx(rpcUrl: string, raw: Hex): Promise<Hex> {
  return rpc<Hex>(rpcUrl, 'eth_sendRawTransaction', [raw]);
}
