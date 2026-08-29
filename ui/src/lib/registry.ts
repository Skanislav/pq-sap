/**
 * StealthKeyRegistry client: register the ML-KEM viewing key once, then
 * share only the 65-byte compact meta-address (spend_pub || index).
 */

import {
  parseAbi, parseEventLogs,
  type Address, type PublicClient, type WalletClient, type Hex,
} from 'viem';

import {
  decodeCompactMeta, type ClassicalMeta, type CompactMeta,
} from './classical.ts';
import { fromHex, toHex } from './hex.ts';
import type { ChainConfig } from './chain.ts';

export const REGISTRY_ABI = parseAbi([
  'event ViewingKeyRegistered(uint256 indexed index, address indexed registrant, uint256 length)',
  'function register(bytes viewingKey) returns (uint256 index)',
  'function viewingKeyOf(uint256 index) view returns (bytes)',
  'function count() view returns (uint256)',
]);

/** Resolve a 65-byte compact meta-address to full key material. */
export async function resolveCompactMeta(
  publicClient: PublicClient, registry: Address, compact: CompactMeta,
): Promise<ClassicalMeta> {
  const ek = await publicClient.readContract({
    address: registry, abi: REGISTRY_ABI,
    functionName: 'viewingKeyOf', args: [compact.index],
  });
  const kemEk = fromHex(ek);
  if (kemEk.length !== 1184)
    throw new Error(`registry index ${compact.index} holds a ${kemEk.length}-byte key, expected 1,184 (ML-KEM-768 ek)`);
  return { spendPub: compact.spendPub, kemEk };
}

/** Decode + resolve in one step (what a sender does with a pasted compact meta). */
export async function resolveCompactMetaBytes(
  publicClient: PublicClient, registry: Address, bytes: Uint8Array,
): Promise<{ meta: ClassicalMeta; compact: CompactMeta }> {
  const compact = decodeCompactMeta(bytes);
  return { meta: await resolveCompactMeta(publicClient, registry, compact), compact };
}

/** Register a viewing key; returns its permanent index. */
export async function registerViewingKey(
  publicClient: PublicClient, walletClient: WalletClient, cfg: ChainConfig,
  registry: Address, viewingKey: Uint8Array,
): Promise<{ index: bigint; txHash: Hex }> {
  if (!walletClient.account) throw new Error('wallet not ready');
  const txHash = await walletClient.writeContract({
    account: walletClient.account, chain: cfg.chain,
    address: registry, abi: REGISTRY_ABI,
    functionName: 'register', args: [toHex(viewingKey)],
  });
  const rcpt = await publicClient.waitForTransactionReceipt({ hash: txHash });
  const [ev] = parseEventLogs({
    abi: REGISTRY_ABI, eventName: 'ViewingKeyRegistered', logs: rcpt.logs });
  if (!ev) throw new Error('registration event missing');
  return { index: ev.args.index, txHash };
}
