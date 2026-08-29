/**
 * Chain registry for the demo UI: local anvil (dev-chain script) and
 * Sepolia (canonical ERC-5564 singleton announcer).
 */

import { createPublicClient, http, type Address, type PublicClient } from 'viem';
import { foundry, sepolia } from 'viem/chains';

import { SEPOLIA } from '../../../js-client/src/sepolia.ts';

export { SCHEME_ID } from '../../../js-client/src/sepolia.ts';

export interface ChainConfig {
  key: 'anvil' | 'sepolia';
  label: string;
  chain: typeof foundry | typeof sepolia;
  rpcUrl: string;
  announcer: Address;
  explorer: string | null;
  /** first block worth scanning (announcer deploy height) */
  scanFromBlock: bigint;
  /** max getLogs span per request on this RPC */
  logChunk: bigint | null;
}

/** Deterministic CREATE address: anvil account 0, nonce 0 (dev-chain.mjs deploys first). */
export const ANVIL_ANNOUNCER: Address = '0x5FbDB2315678afecb367f032d93F642f64180aa3';

/** anvil's first default funded account — dev signer for the local demo. */
export const ANVIL_DEV_KEY =
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' as const;

export const CHAINS: Record<'anvil' | 'sepolia', ChainConfig> = {
  anvil: {
    key: 'anvil',
    label: 'Local anvil',
    chain: foundry,
    rpcUrl: 'http://127.0.0.1:8545',
    announcer: ANVIL_ANNOUNCER,
    explorer: null,
    scanFromBlock: 0n,
    logChunk: null,
  },
  sepolia: {
    key: 'sepolia',
    label: 'Sepolia',
    chain: sepolia,
    rpcUrl: 'https://ethereum-sepolia-rpc.publicnode.com',
    announcer: SEPOLIA.erc5564Announcer,
    explorer: 'https://sepolia.etherscan.io',
    // canonical announcer deployed early 2024; default to a recent window
    scanFromBlock: -50_000n, // negative = relative to latest
    logChunk: 10_000n,
  },
};

export function publicClientFor(cfg: ChainConfig): PublicClient {
  return createPublicClient({ chain: cfg.chain, transport: http(cfg.rpcUrl) });
}
