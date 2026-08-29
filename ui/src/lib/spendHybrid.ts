/**
 * Sepolia PQ spend — reuses the DEPLOYED ZKNOX hybrid account (kohaku).
 *
 * The stealth account is the counterfactual address of a ZKNOX mldsa_k1
 * account = ECDSA secp256k1 (pre-quantum) AND ML-DSA-44 (post-quantum,
 * the blinded stealth key). Signing is hybrid: the ECDSA half is a
 * deterministic PUBLIC demo key (testnet only), the ML-DSA half is the
 * blinded signature from the local signer service (old ZKNOX v0.0.10
 * format). This mirrors js-client/src/spend.ts, which the Sepolia fork
 * test spends with.
 *
 * Browser-safe: none of js-client/src/spend.ts's Node imports are pulled
 * in; the small hybrid pieces are reproduced here.
 */

import {
  type Address,
  concatHex,
  encodeAbiParameters,
  encodeFunctionData,
  type Hex,
  keccak256,
  type PublicClient,
  parseAbi,
  stringToHex,
  toHex as viemToHex,
} from 'viem'
import { privateKeyToAccount, sign } from 'viem/accounts'

export const ENTRYPOINT_ABI = parseAbi([
  'struct PackedUserOperation { address sender; uint256 nonce; bytes initCode; bytes callData; bytes32 accountGasLimits; uint256 preVerificationGas; bytes32 gasFees; bytes paymasterAndData; bytes signature; }',
  'function getUserOpHash(PackedUserOperation userOp) view returns (bytes32)',
  'function getNonce(address sender, uint192 key) view returns (uint256)',
  'function handleOps(PackedUserOperation[] ops, address beneficiary)',
])

export const ACCOUNT_ABI = parseAbi(['function execute(address target, uint256 value, bytes data)'])

export const ZKNOX_FACTORY_ABI = parseAbi([
  'function getAddress(bytes preQuantumPubKey, bytes postQuantumPubKey) view returns (address)',
  'function createAccount(bytes preQuantumPubKey, bytes postQuantumPubKey) returns (address)',
])

/** Deterministic, PUBLIC throwaway key for the pre-quantum half (testnet only). */
export function preQuantumDemoKey() {
  const priv = keccak256(stringToHex('pq-stealth spend demo prequantum key v0'))
  return { priv, address: privateKeyToAccount(priv).address }
}

const packPair = (hi: bigint, lo: bigint): Hex => viemToHex((hi << 128n) | lo, { size: 32 })

export interface UserOp {
  sender: Address
  nonce: bigint
  initCode: Hex
  callData: Hex
  accountGasLimits: Hex
  preVerificationGas: bigint
  gasFees: Hex
  paymasterAndData: Hex
  signature: Hex
}

export function requiredPrefund(op: UserOp): bigint {
  const maxFee = BigInt(op.gasFees) & ((1n << 128n) - 1n)
  const verification = BigInt(op.accountGasLimits) >> 128n
  const call = BigInt(op.accountGasLimits) & ((1n << 128n) - 1n)
  return maxFee * (verification + call + op.preVerificationGas)
}

export async function buildSpendUserOp(
  publicClient: PublicClient,
  entryPoint: Address,
  account: Address,
  dest: Address,
  value: bigint,
): Promise<UserOp> {
  const nonce = await publicClient.readContract({
    address: entryPoint,
    abi: ENTRYPOINT_ABI,
    functionName: 'getNonce',
    args: [account, 0n],
  })
  const gasPrice = await publicClient.getGasPrice()
  const maxFee = gasPrice * 2n < 1_500_000_000n ? 1_500_000_000n : gasPrice * 2n
  return {
    sender: account,
    nonce,
    initCode: '0x',
    callData: encodeFunctionData({
      abi: ACCOUNT_ABI,
      functionName: 'execute',
      args: [dest, value, '0x'],
    }),
    // one ML-DSA verify at the v0.0.10 profile is ~8M gas
    accountGasLimits: packPair(12_000_000n, 200_000n),
    preVerificationGas: 150_000n,
    gasFees: packPair(1_000_000_000n, maxFee),
    paymasterAndData: '0x',
    signature: '0x',
  }
}

/** Hybrid signature: abi.encode(bytes ecdsaSig, bytes blindedMldsaSig). */
export async function packHybridSignature(userOpHash: Hex, blindedSig: Hex): Promise<Hex> {
  const { priv } = preQuantumDemoKey()
  const ecdsa = await sign({ hash: userOpHash, privateKey: priv })
  const preSig = concatHex([
    ecdsa.r,
    ecdsa.s,
    viemToHex(Number(ecdsa.v ?? BigInt((ecdsa.yParity ?? 0) + 27)), { size: 1 }),
  ])
  return encodeAbiParameters([{ type: 'bytes' }, { type: 'bytes' }], [preSig, blindedSig])
}

// ML-DSA-44 (level-2) signature length, for the estimation dummy.
const MLDSA44_SIG_BYTES = 2420

/** Correctly-shaped dummy hybrid signature for paymaster estimation: a real
 *  (format-valid) ECDSA half so the classical check never reverts, and a
 *  zero-filled ML-DSA half of the right length so the account decodes it. */
export async function dummyHybridSignature(): Promise<Hex> {
  const { priv } = preQuantumDemoKey()
  const ecdsa = await sign({ hash: viemToHex(0n, { size: 32 }), privateKey: priv })
  const preSig = concatHex([
    ecdsa.r,
    ecdsa.s,
    viemToHex(Number(ecdsa.v ?? BigInt((ecdsa.yParity ?? 0) + 27)), { size: 1 }),
  ])
  const zeroMldsa = viemToHex(0n, { size: MLDSA44_SIG_BYTES })
  return encodeAbiParameters([{ type: 'bytes' }, { type: 'bytes' }], [preSig, zeroMldsa])
}
