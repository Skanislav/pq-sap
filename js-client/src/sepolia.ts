/**
 * Sepolia deployment constants + minimal ABIs for the PQ stealth flow.
 *
 * Canonical ERC-5564/6538 singletons (same address on all chains) and the
 * ZKNOX contracts from kohaku packages/pq-account/deployments (verified
 * on-chain 2026-07-25).
 */

import type { Address } from 'viem';
import { parseAbi } from 'viem';

export const SEPOLIA = {
  chainId: 11155111,
  erc5564Announcer: '0x55649E01B5Df198D18D95b5cc5051630cfD45564' as Address,
  erc6538Registry: '0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538' as Address,
  zknoxMldsaVerifier: '0x092c5d82069de997E34Ce2505CA7D5042f3721ef' as Address,
  zknoxMldsaK1Factory: '0xF45104FCfBB9233cEa6D516d71ba57F6961B8C2e' as Address,
} as const;

// placeholder pending ERC-5564 scheme-ID registration
export const SCHEME_ID = 2n;

export const ANNOUNCER_ABI = parseAbi([
  'event Announcement(uint256 indexed schemeId, address indexed stealthAddress, address indexed caller, bytes ephemeralPubKey, bytes metadata)',
  'function announce(uint256 schemeId, address stealthAddress, bytes ephemeralPubKey, bytes metadata)',
]);

export const REGISTRY_ABI = parseAbi([
  'function registerKeys(uint256 schemeId, bytes stealthMetaAddress)',
  'function stealthMetaAddressOf(address registrant, uint256 schemeId) view returns (bytes)',
]);

export const ZKNOX_VERIFIER_ABI = parseAbi([
  'function setKey(bytes pubkey) returns (bytes)',
  'function verify(bytes pk, bytes m, bytes signature, bytes ctx) view returns (bool)',
]);

export const FACTORY_ABI = parseAbi([
  'function getAddress(bytes preQuantumPubKey, bytes postQuantumPubKey) view returns (address)',
  'function createAccount(bytes preQuantumPubKey, bytes postQuantumPubKey) returns (address)',
]);
