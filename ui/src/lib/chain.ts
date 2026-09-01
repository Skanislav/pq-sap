/**
 * Chain registry for the demo UI: local anvil (dev-chain script) and
 * Sepolia (canonical ERC-5564 singleton announcer).
 */

import { type Address, createPublicClient, defineChain, http, type PublicClient } from 'viem'
import { foundry, sepolia } from 'viem/chains'

import { SEPOLIA } from '../../../js-client/src/sepolia.ts'

export { SCHEME_ID } from '../../../js-client/src/sepolia.ts'

export type ChainKey = 'anvil' | 'sepolia' | 'frames'

/** Public EIP-8141 frames testnet (chain 81410) — the only network with type 0x06. */
export const framesTestnet = defineChain({
  id: 81410,
  name: 'Frames Testnet',
  nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
  rpcUrls: { default: { http: ['https://rpc1.frames.ethrex.xyz'] } },
  blockExplorers: { default: { name: 'dora', url: 'https://dora.frames.ethrex.xyz' } },
})

export interface ChainConfig {
  key: ChainKey
  label: string
  chain: typeof foundry | typeof sepolia | typeof framesTestnet
  rpcUrl: string
  announcer: Address
  explorer: string | null
  /** does this network support EIP-8141 frame transactions (type 0x06)? */
  frames?: boolean
  /** first block worth scanning (announcer deploy height) */
  scanFromBlock: bigint
  /** max getLogs span per request on this RPC */
  logChunk: bigint | null
}

/** Deterministic CREATE address: anvil account 0, nonce 0 (dev-chain.mjs deploys first). */
export const ANVIL_ANNOUNCER: Address = '0x5FbDB2315678afecb367f032d93F642f64180aa3'

/** anvil's first default funded account — dev signer for the local demo. */
export const ANVIL_DEV_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' as const

/**
 * Well-known ethereum-package genesis account, funded on the frames testnet.
 * A public throwaway key — safe to ship in a testnet demo (like the anvil key).
 */
export const FRAMES_DEV_KEY = {
  address: '0x8943545177806ED17B9F23F0a21ee5948eCaa776' as Address,
  privateKey: '0xbcdf20249abf0ed6d944c0288fad489e33f66b3960d9e6229c1cd214ed3bbe31' as `0x${string}`,
} as const

export const CHAINS: Record<ChainKey, ChainConfig> = {
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
  frames: {
    key: 'frames',
    label: 'Frames testnet (EIP-8141)',
    chain: framesTestnet,
    rpcUrl: 'https://rpc1.frames.ethrex.xyz',
    // minimal ERC-5564 announcer we deployed on this testnet (canonical
    // singleton isn't present); redeploy + update if the chain is reset.
    announcer: '0x9fcf7d13d10dedf17d0f24c62f0cf4ed462f65b7',
    explorer: 'https://dora.frames.ethrex.xyz',
    frames: true,
    scanFromBlock: 58_891n, // announcer deploy block
    logChunk: 10_000n,
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
}

export function publicClientFor(cfg: ChainConfig): PublicClient {
  return createPublicClient({ chain: cfg.chain, transport: http(cfg.rpcUrl) })
}
