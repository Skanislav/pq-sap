/**
 * Live end-to-end: build + sign + submit a real EIP-8141 frame transaction (an
 * EOA transfer) on the public frames testnet with our own client, and assert it
 * mines as a type-0x06 tx. Env-gated: set FRAMES_LIVE=1 to run (the chain may be
 * reset without notice, and CI is offline), otherwise it skips cleanly.
 *
 *   FRAMES_LIVE=1 npm run e2e:frames:public
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { Hex } from 'viem';

import { buildEoaTransfer, sendRawFrameTx, rpc } from '../src/frame-tx/actions.ts';
import { FRAMES_PUBLIC, DEV_KEY } from '../src/frame-tx/chains.ts';

const LIVE = process.env.FRAMES_LIVE === '1';

test('frame tx (0x06) transfer mines on the public testnet', { skip: !LIVE && 'set FRAMES_LIVE=1' }, async () => {
  const net = FRAMES_PUBLIC;
  const sender = DEV_KEY.address;

  // Sanity: the RPC is up and speaks the expected chain.
  const chainId = BigInt(await rpc<Hex>(net.rpcUrl, 'eth_chainId', []));
  assert.equal(chainId, net.chainId, 'unexpected chain id (reset?)');

  const nonce = BigInt(await rpc<Hex>(net.rpcUrl, 'eth_getTransactionCount', [sender, 'latest']));
  const { raw, tx } = await buildEoaTransfer({
    chainId: net.chainId, nonce, sender, to: '0x000000000000000000000000000000000000dEaD',
    value: 1_000_000_000_000_000n, privateKey: DEV_KEY.privateKey,
    maxFeePerGas: 3_000_000_000n, maxPriorityFeePerGas: 1_000_000_000n,
  });
  assert.equal(tx.frames.length, 2, 'expected VERIFY + SENDER frames');

  const hash = await sendRawFrameTx(net.rpcUrl, raw);
  assert.match(hash, /^0x[0-9a-f]{64}$/i);

  let receipt: { status: Hex; type: Hex; blockNumber: Hex } | null = null;
  for (let i = 0; i < 30 && !receipt; i++) {
    receipt = await rpc(net.rpcUrl, 'eth_getTransactionReceipt', [hash]);
    if (!receipt) await new Promise((r) => setTimeout(r, 2000));
  }
  assert.ok(receipt, 'no receipt within timeout');
  assert.equal(receipt.type, '0x6', 'not a frame transaction');
  assert.equal(receipt.status, '0x1', 'frame tx reverted');
});
