#!/usr/bin/env node
/**
 * Send a real EIP-8141 frame transaction (an EOA transfer) on the public frames
 * testnet with our own serializer + signing. Proves the client end-to-end
 * against a live type-0x06 chain.
 *
 *   npm run frames:live                       # 0.001 ETH to 0x…dead, dev key
 *   npm run frames:live -- --to 0x… --value 0.002ether
 *
 * The signer key comes from FRAMES_PRIVATE_KEY (falls back to the well-known
 * ethereum-package dev key, funded on this testnet). NEVER put a real key here.
 */
import { parseEther, type Address, type Hex } from 'viem';
import { buildEoaTransfer, sendRawFrameTx, rpc } from '../src/frame-tx/actions.ts';
import { FRAMES_PUBLIC, DEV_KEY } from '../src/frame-tx/chains.ts';

function arg(name: string, def?: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : def;
}

const net = FRAMES_PUBLIC;
const privateKey = (process.env.FRAMES_PRIVATE_KEY ?? DEV_KEY.privateKey) as Hex;
const to = (arg('to') ?? '0x000000000000000000000000000000000000dEaD') as Address;
const valueStr = arg('value', '0.001ether')!;
const value = valueStr.endsWith('ether') ? parseEther(valueStr.replace('ether', '')) : BigInt(valueStr);

// Derive the sender from the key so a custom FRAMES_PRIVATE_KEY works too.
const { privateKeyToAccount } = await import('viem/accounts');
const sender = privateKeyToAccount(privateKey).address;

const nonce = BigInt(await rpc<Hex>(net.rpcUrl, 'eth_getTransactionCount', [sender, 'latest']));
const gasPrice = BigInt(await rpc<Hex>(net.rpcUrl, 'eth_gasPrice', []));
const maxFeePerGas = gasPrice * 2n + 1_000_000_000n;

console.log(`[frames-live] ${net.name} (chain ${net.chainId}) sender ${sender} nonce ${nonce}`);
console.log(`[frames-live] transfer ${value} wei -> ${to}`);

const { raw, sigHash } = await buildEoaTransfer({
  chainId: net.chainId, nonce, sender, to, value, privateKey,
  maxFeePerGas, maxPriorityFeePerGas: 1_000_000_000n,
});
console.log(`[frames-live] sig_hash ${sigHash}`);

const hash = await sendRawFrameTx(net.rpcUrl, raw);
console.log(`[frames-live] sent ${hash}`);
if (net.explorerTx) console.log(`[frames-live] ${net.explorerTx(hash)}`);

let receipt: { status: Hex; blockNumber: Hex; gasUsed: Hex; type: Hex } | null = null;
for (let i = 0; i < 30 && !receipt; i++) {
  receipt = await rpc(net.rpcUrl, 'eth_getTransactionReceipt', [hash]);
  if (!receipt) await new Promise((r) => setTimeout(r, 2000));
}
if (!receipt) { console.error('[frames-live] receipt timeout'); process.exit(1); }
console.log(`[frames-live] mined block ${BigInt(receipt.blockNumber)} status ${receipt.status} type ${receipt.type} gasUsed ${BigInt(receipt.gasUsed)}`);
process.exit(receipt.status === '0x1' ? 0 : 1);
