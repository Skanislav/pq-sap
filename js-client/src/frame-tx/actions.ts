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

// --- generic single-signer frame tx -----------------------------------------

export interface FramesTxParams {
  chainId: bigint;
  nonce: bigint;
  sender: Address;
  frames: Frame[];
  /** the secp256k1 key that signs as `sender` (one outer signature). */
  privateKey: Hex;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
}

/**
 * Assemble arbitrary frames, sign a single secp256k1 outer signature as
 * `sender`, and return the signed FrameTx + its `0x06` raw bytes. The caller's
 * frame list should begin with a `VERIFY(sender, BOTH)` frame so the EOA sender
 * is approved for execution and payment.
 */
export async function buildFramesTx(p: FramesTxParams): Promise<{ tx: FrameTx; raw: Hex; sigHash: Hex }> {
  const unsigned: FrameTx = {
    chainId: p.chainId, nonce: p.nonce, sender: p.sender, frames: p.frames,
    signatures: [secp256k1Placeholder(p.sender)],
    maxPriorityFeePerGas: p.maxPriorityFeePerGas, maxFeePerGas: p.maxFeePerGas,
    maxFeePerBlobGas: 0n, blobVersionedHashes: [],
  };
  const sigHash = frameTxSigHash(unsigned);
  const sig = await secp256k1FrameSignature(sigHash, p.sender, p.privateKey);
  const tx: FrameTx = { ...unsigned, signatures: [sig] };
  return { tx, raw: serializeFrameTx(tx), sigHash };
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
export function buildEoaTransfer(p: EoaTransferParams): Promise<{ tx: FrameTx; raw: Hex; sigHash: Hex }> {
  const frameGas = p.frameGas ?? 100_000n;
  const frameStateGas = p.frameStateGas ?? 250_000n;
  return buildFramesTx({
    chainId: p.chainId, nonce: p.nonce, sender: p.sender, privateKey: p.privateKey,
    maxFeePerGas: p.maxFeePerGas, maxPriorityFeePerGas: p.maxPriorityFeePerGas,
    frames: [
      verifyFrame({ target: p.sender, flags: APPROVE_SCOPE.BOTH, executionGas: frameGas, stateGas: frameStateGas }),
      senderFrame({ target: p.to, executionGas: frameGas, stateGas: frameStateGas, value: p.value, data: p.data ?? '0x' }),
    ],
  });
}

export interface AnnounceTransferParams {
  chainId: bigint;
  nonce: bigint;
  sender: Address;
  /** the derived stealth address to pay. */
  stealthAddress: Address;
  value: bigint;
  /** the ERC-5564 announcer, and the pre-encoded `announce(...)` calldata. */
  announcer: Address;
  announceData: Hex;
  privateKey: Hex;
  frameGas?: bigint;
  frameStateGas?: bigint;
  /** the DEFAULT frame that runs `announce` may need more execution gas. */
  announceGas?: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
}

/**
 * One atomic frame tx that pays a stealth address AND emits its ERC-5564
 * announcement: `[VERIFY(sender, BOTH), SENDER(stealth, value), DEFAULT(announcer, announce…)]`.
 * The DEFAULT frame runs as ENTRY_POINT and calls the announcer.
 */
export function buildAnnounceTransfer(p: AnnounceTransferParams): Promise<{ tx: FrameTx; raw: Hex; sigHash: Hex }> {
  const frameGas = p.frameGas ?? 100_000n;
  const frameStateGas = p.frameStateGas ?? 250_000n;
  return buildFramesTx({
    chainId: p.chainId, nonce: p.nonce, sender: p.sender, privateKey: p.privateKey,
    maxFeePerGas: p.maxFeePerGas, maxPriorityFeePerGas: p.maxPriorityFeePerGas,
    frames: [
      verifyFrame({ target: p.sender, flags: APPROVE_SCOPE.BOTH, executionGas: frameGas, stateGas: frameStateGas }),
      senderFrame({ target: p.stealthAddress, executionGas: frameGas, stateGas: frameStateGas, value: p.value }),
      defaultFrame({ target: p.announcer, executionGas: p.announceGas ?? 200_000n, stateGas: frameStateGas, data: p.announceData }),
    ],
  });
}

// --- sponsored PQ-authorized tx (Stealth8141Account) --------------------------

/** Index of the PQ (ARBITRARY) signature in a sponsored tx: 0 is the sponsor's. */
export const SPONSORED_PQ_SIG_INDEX = 1n;

export interface SponsoredPqTxParams {
  chainId: bigint;
  nonce: bigint;
  /** the EOA that is `tx.sender` and payer (APPROVE BOTH via its secp256k1 sig). */
  sponsor: Address;
  sponsorPrivateKey: Hex;
  /**
   * The execution frames that follow the sponsor's VERIFY frame — e.g. a
   * DEFAULT frame calling `Stealth8141Account.executeFrame(1, to, value, data)`,
   * optionally preceded by a DEFAULT frame that deploys the account.
   */
  frames: Frame[];
  /**
   * Produces the post-quantum signature over the tx's sig_hash (the digest the
   * account reads back with TXPARAM 0x08). Called once, after the tx shape is
   * final; the returned bytes become the ARBITRARY signature at index 1.
   */
  pqSign: (sigHash: Hex) => Promise<Hex>;
  frameGas?: bigint;
  frameStateGas?: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
}

/**
 * Sponsored, PQ-authorized frame tx:
 *   frames     = [VERIFY(sponsor, BOTH), ...p.frames]
 *   signatures = [SECP256K1(sponsor), ARBITRARY(pq)]
 * The validation prefix is just the sponsor's protocol-checked signature, so
 * the (multi-million-gas) PQ verification in the execution frames is outside
 * the public mempool's MAX_VERIFY_GAS bound. Both signatures have an empty
 * `msg`, so both sign the same sig_hash, which elides their bytes — the PQ
 * signature can be produced from the placeholder shape and filled in.
 */
export async function buildSponsoredPqTx(p: SponsoredPqTxParams): Promise<{ tx: FrameTx; raw: Hex; sigHash: Hex }> {
  const frameGas = p.frameGas ?? 100_000n;
  const frameStateGas = p.frameStateGas ?? 250_000n;
  const unsigned: FrameTx = {
    chainId: p.chainId, nonce: p.nonce, sender: p.sponsor,
    frames: [
      verifyFrame({ target: p.sponsor, flags: APPROVE_SCOPE.BOTH, executionGas: frameGas, stateGas: frameStateGas }),
      ...p.frames,
    ],
    signatures: [secp256k1Placeholder(p.sponsor), arbitrarySignature('0x')],
    maxPriorityFeePerGas: p.maxPriorityFeePerGas, maxFeePerGas: p.maxFeePerGas,
    maxFeePerBlobGas: 0n, blobVersionedHashes: [],
  };
  const sigHash = frameTxSigHash(unsigned);
  const [sponsorSig, pqSig] = await Promise.all([
    secp256k1FrameSignature(sigHash, p.sponsor, p.sponsorPrivateKey),
    p.pqSign(sigHash),
  ]);
  const tx: FrameTx = { ...unsigned, signatures: [sponsorSig, arbitrarySignature(pqSig)] };
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
