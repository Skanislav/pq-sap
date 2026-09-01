/**
 * Byte-conformance for the EIP-8141 serializer against golden vectors produced
 * by `rex` (the reference builder the public frames testnet points at). rex
 * uses ethrex's own `FrameTransaction` types, so matching its `--print` output
 * byte-for-byte is the strongest offline guarantee our wire format is the one
 * the chain accepts.
 *
 * Regenerate vectors with `devnet/gen-vectors.sh` (needs `rex` on PATH); the
 * test self-skips when the file is absent so CI without rex still passes.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  serializeFrameTx, frameTxSigHash,
  type FrameTx,
} from '../src/frame-tx/serialize.ts';

const VECTORS_PATH = fileURLToPath(
  new URL('./state/frame-tx-vectors.json', import.meta.url));

// A vector fixes the raw 0x06 bytes and sig_hash rex computed for one input.
interface Vector {
  name: string;
  // FrameTx with bigints serialized as decimal strings (JSON has no bigint).
  tx: SerializedFrameTx;
  raw: string; // expected 0x06... hex
  sigHash: string; // expected 0x... 32-byte hex
}
type SerializedFrameTx = {
  [K in keyof FrameTx]: FrameTx[K] extends bigint ? string : FrameTx[K] extends bigint[] ? string[] : FrameTx[K];
} & {
  frames: Array<Record<string, unknown>>;
};

function reviveTx(s: SerializedFrameTx): FrameTx {
  return {
    chainId: BigInt(s.chainId as unknown as string),
    nonce: BigInt(s.nonce as unknown as string),
    sender: s.sender,
    frames: (s.frames as unknown[]).map((f) => {
      const g = f as Record<string, string | null>;
      return {
        mode: Number(g.mode),
        flags: Number(g.flags),
        target: (g.target ?? null) as FrameTx['frames'][number]['target'],
        executionGas: BigInt(g.executionGas as string),
        stateGas: BigInt(g.stateGas as string),
        value: BigInt(g.value as string),
        data: (g.data ?? '0x') as `0x${string}`,
      };
    }),
    signatures: (s.signatures as unknown[]).map((x) => {
      const g = x as Record<string, string | null>;
      return {
        scheme: Number(g.scheme),
        signer: (g.signer ?? null) as FrameTx['signatures'][number]['signer'],
        msg: (g.msg ?? '0x') as `0x${string}`,
        signature: (g.signature ?? '0x') as `0x${string}`,
      };
    }),
    maxPriorityFeePerGas: BigInt(s.maxPriorityFeePerGas as unknown as string),
    maxFeePerGas: BigInt(s.maxFeePerGas as unknown as string),
    maxFeePerBlobGas: BigInt(s.maxFeePerBlobGas as unknown as string),
    blobVersionedHashes: (s.blobVersionedHashes ?? []) as `0x${string}`[],
  };
}

test('frame-tx serializer matches rex golden vectors', { skip: !existsSync(VECTORS_PATH) && 'run devnet/gen-vectors.sh (needs rex)' }, () => {
  const vectors: Vector[] = JSON.parse(readFileSync(VECTORS_PATH, 'utf8'));
  assert.ok(vectors.length > 0, 'no vectors');
  for (const v of vectors) {
    const tx = reviveTx(v.tx);
    assert.equal(serializeFrameTx(tx).toLowerCase(), v.raw.toLowerCase(), `raw mismatch: ${v.name}`);
    assert.equal(frameTxSigHash(tx).toLowerCase(), v.sigHash.toLowerCase(), `sigHash mismatch: ${v.name}`);
  }
});
