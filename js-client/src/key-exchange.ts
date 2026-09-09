/**
 * StealthKeyExchange client — the on-chain half of the key exchange
 * (contracts/src/StealthKeyExchange.sol): register an encapsulation key once
 * and announce through the shape-validating wrapper instead of calling the
 * ERC-5564 announcer directly.
 *
 * The parameter table below is the same table as the contract's constants and
 * the Lean model's `Params.lean`; contracts/lean/scripts/check_constants.py
 * fails CI if the three drift.
 */

import { type Address, type Hex, type PublicClient, parseAbi, parseEventLogs, type WalletClient, type Chain } from 'viem';

export const KEY_EXCHANGE_ABI = parseAbi([
  'function announce(address stealthAddress, bytes ciphertext, bytes metadata) returns (uint8 kem)',
  'function registerViewingKey(bytes encapsulationKey) returns (uint256 index)',
  'function viewingKeyOf(uint256 index) view returns (uint8 kem, bytes encapsulationKey)',
  'function viewingKeyCount() view returns (uint256)',
  'function isValidAnnouncement(bytes ciphertext, bytes metadata) pure returns (bool)',
  'function kemOfCiphertextLength(uint256 length) pure returns (uint8)',
  'function kemOfEncapsulationKeyLength(uint256 length) pure returns (uint8)',
  'function kemOfMetaAddress(bytes metaAddress) pure returns (uint8)',
  'function metaAddressBytes(uint8 kem) pure returns (uint256)',
  'function SCHEME_ID() view returns (uint256)',
  'function ANNOUNCER() view returns (address)',
  'event ViewingKeyRegistered(uint256 indexed index, address indexed registrant, uint8 kem)',
  'error UnsupportedCiphertextLength(uint256 length)',
  'error UnsupportedEncapsulationKeyLength(uint256 length)',
  'error UnsupportedMetaAddress(uint256 length, uint8 version)',
  'error MissingViewTag()',
  'error NoSuchViewingKey(uint256 index)',
]);

export const SCHEME_ID = 2n;
export const VIEW_TAG_BYTES = 1;

/** `enum Kem` of the contract, in ABI order (the index is the on-chain value). */
export const KEM_SIZES = {
  MLKEM512: { ek: 800, ct: 768 },
  MLKEM768: { ek: 1184, ct: 1088 },
  MLKEM1024: { ek: 1568, ct: 1568 },
  XWING: { ek: 1216, ct: 1120 },
} as const;

export type Kem = keyof typeof KEM_SIZES;
export const KEM_ORDER = Object.keys(KEM_SIZES) as Kem[];

export function kemOfCiphertextLength(length: number): Kem | null {
  return KEM_ORDER.find((k) => KEM_SIZES[k].ct === length) ?? null;
}

export function kemOfEncapsulationKeyLength(length: number): Kem | null {
  return KEM_ORDER.find((k) => KEM_SIZES[k].ek === length) ?? null;
}

/** The predicate under which the contract's `announce` succeeds. */
export function isValidAnnouncement(ciphertext: Uint8Array, metadata: Uint8Array): boolean {
  return kemOfCiphertextLength(ciphertext.length) !== null && metadata.length >= VIEW_TAG_BYTES;
}

const toHex = (b: Uint8Array): Hex => `0x${Buffer.from(b).toString('hex')}`;

/** Announce through the wrapper; the singleton emits the ERC-5564 event with `caller = keyExchange`. */
export async function announceViaKeyExchange(
  publicClient: PublicClient, walletClient: WalletClient, chain: Chain, keyExchange: Address,
  ann: { stealthAddress: Address; ephemeralPubKey: Uint8Array; viewTag: Uint8Array },
): Promise<Hex> {
  if (!walletClient.account) throw new Error('wallet not ready');
  const hash = await walletClient.writeContract({
    account: walletClient.account, chain, address: keyExchange, abi: KEY_EXCHANGE_ABI,
    functionName: 'announce',
    args: [ann.stealthAddress, toHex(ann.ephemeralPubKey), toHex(ann.viewTag)],
  });
  await publicClient.waitForTransactionReceipt({ hash });
  return hash;
}

/** Register an encapsulation key; returns its permanent index. */
export async function registerViewingKey(
  publicClient: PublicClient, walletClient: WalletClient, chain: Chain, keyExchange: Address,
  encapsulationKey: Uint8Array,
): Promise<{ index: bigint; kem: Kem; txHash: Hex }> {
  if (!walletClient.account) throw new Error('wallet not ready');
  const txHash = await walletClient.writeContract({
    account: walletClient.account, chain, address: keyExchange, abi: KEY_EXCHANGE_ABI,
    functionName: 'registerViewingKey', args: [toHex(encapsulationKey)],
  });
  const rcpt = await publicClient.waitForTransactionReceipt({ hash: txHash });
  const [ev] = parseEventLogs({ abi: KEY_EXCHANGE_ABI, eventName: 'ViewingKeyRegistered', logs: rcpt.logs });
  if (!ev) throw new Error('registration event missing');
  return { index: ev.args.index, kem: KEM_ORDER[ev.args.kem]!, txHash };
}
