/**
 * Deployed ZKNOX pq-account addresses (ethereum/kohaku, examples/pq-account
 * + packages/pq-account/deployments/deployments.json), verified on-chain.
 *
 * The Sepolia PQ spend route REUSES these — the MLDSA verifier and the
 * mldsa_k1 HYBRID factory (ECDSA secp256k1 pre-quantum + ML-DSA-44/level-2
 * post-quantum) are already live, so nothing PQ-specific needs deploying.
 * This is the same infrastructure js-client/src/spend.ts targets and the
 * fork-replay test (e2e-sepolia-fork-spend) spends against.
 */

import type { Address } from 'viem'

export const KOHAKU_SEPOLIA = {
  chainId: 11155111,
  // ERC-4337 v0.7 canonical EntryPoint (the deployed accounts use v0.7)
  entryPoint: '0x0000000071727De22E5E9d8BAf0edAc6f37da032' as Address,
  // ZKNOX_MLDSA_VERIFIER_V0_0_10 (level-2 Dilithium2 / ML-DSA-44)
  mldsaVerifier: '0x092c5d82069de997E34Ce2505CA7D5042f3721ef' as Address,
  // ZKNOX_MLDSA_K1_FACTORY_V0_0_10 — hybrid (ecdsa_k1 + mldsa) account factory
  mldsaK1Factory: '0xF45104FCfBB9233cEa6D516d71ba57F6961B8C2e' as Address,
} as const

/** Same hybrid factory address is deployed on these chains too (see kohaku). */
export const KOHAKU_FACTORY_BY_CHAIN: Record<number, Address> = {
  11155111: KOHAKU_SEPOLIA.mldsaK1Factory, // Sepolia
  421614: '0xF45104FCfBB9233cEa6D516d71ba57F6961B8C2e', // Arbitrum Sepolia
  84532: '0xF45104FCfBB9233cEa6D516d71ba57F6961B8C2e', // Base Sepolia
}
