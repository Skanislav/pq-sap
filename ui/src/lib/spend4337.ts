/**
 * PQ spend route (D-014) client — ERC-4337 + ERC-7913 on the local dev
 * chain, at the ZKNOX level-2 profile (the on-chain ML-DSA verifier's
 * parameter set).
 *
 * The stealth address is the CREATE2 counterfactual address of a
 * Stealth7913Account4337 bound to the blinded key (Stealth7913Factory),
 * so discovery, funding, and spending all agree on one address. Blinded
 * key material lives in the local Python signer service (dev-chain.mjs);
 * the browser only handles public data and chain mechanics.
 */

import { sha256 } from '@noble/hashes/sha2.js'
import {
  type Address,
  decodeAbiParameters,
  encodeFunctionData,
  type Hex,
  type PublicClient,
  parseAbi,
  toHex as viemToHex,
} from 'viem'

export const ENTRYPOINT_ABI = parseAbi([
  'struct PackedUserOperation { address sender; uint256 nonce; bytes initCode; bytes callData; bytes32 accountGasLimits; uint256 preVerificationGas; bytes32 gasFees; bytes paymasterAndData; bytes signature; }',
  'function getUserOpHash(PackedUserOperation userOp) view returns (bytes32)',
  'function getNonce(address sender, uint192 key) view returns (uint256)',
  'function handleOps(PackedUserOperation[] ops, address beneficiary)',
])

export const ACCOUNT_ABI = parseAbi(['function execute(address target, uint256 value, bytes data)'])

export const FACTORY_ABI = parseAbi([
  'function getAccountAddress(uint256[][][] aHat, bytes tr, uint256[][] t1) view returns (address)',
  'function createAccount(uint256[][][] aHat, bytes tr, uint256[][] t1) returns (address)',
])

/** `Stealth8141Account` (frame-tx PQ route): the spend entry point a DEFAULT
 *  frame calls; `sigIndex` names the ARBITRARY (ML-DSA) signature in tx.signatures. */
export const ACCOUNT_8141_ABI = parseAbi([
  'function executeFrame(uint256 sigIndex, address to, uint256 value, bytes data)',
  'function signer() view returns (bytes)',
])

/** Written by ui/scripts/dev-chain.mjs (anvil), deploy-sepolia.mjs, or
 *  deploy-frames.mjs; served from ui/public as {dev,sepolia,frames}-deployment.json,
 *  resolved relative to the app's base URL (works under an IPFS gateway path). */
export interface DevDeployment {
  /** which account model the PQ route uses on this chain:
   *  stealth7913 = ERC-4337 + ERC-7913 (local), zknox-hybrid = kohaku (Sepolia),
   *  stealth8141 = EIP-8141 frame tx, sponsored + ML-DSA-authorized (frames testnet) */
  mode: 'stealth7913' | 'zknox-hybrid' | 'stealth8141'
  chainId: number
  announcer: Address
  /** null for stealth8141 — there is no EntryPoint contract, the protocol is the entry point */
  entryPoint: Address | null
  verifier: Address
  factory: Address
  /** stealth8141 only: the Yul TXPARAM/SIGPARAM helper the account reads the frame tx through */
  frameCtx?: Address
  registry: Address | null
  signerService: string
  demo?: { zeta: Hex; kemD: Hex; kemZ: Hex }
}

export async function fetchDeployment(chainKey: 'anvil' | 'sepolia' | 'frames'): Promise<DevDeployment | null> {
  const name =
    chainKey === 'anvil' ? 'dev-deployment.json' : chainKey === 'frames' ? 'frames-deployment.json' : 'sepolia-deployment.json'
  const file = new URL(`${import.meta.env.BASE_URL}${name}`, document.baseURI).href
  try {
    const r = await fetch(file, { cache: 'no-store' })
    if (!r.ok) return null
    const dep = (await r.json()) as DevDeployment
    // VITE_SIGNER_URL (build-time) overrides the signer baked into the JSON —
    // e.g. http://127.0.0.1:8546 to use `npm run signer` instead of the hosted one.
    const override = import.meta.env.VITE_SIGNER_URL as string | undefined
    if (override) dep.signerService = override.replace(/\/$/, '')
    return dep
  } catch {
    return null
  }
}

export interface DerivedSpendable {
  view_tag: Hex
  stealth_pk: Hex
  public_key_data: Hex
}

async function callService<T>(service: string, path: string, body: unknown): Promise<T> {
  const r = await fetch(`${service}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!r.ok) throw new Error(`signer service ${path}: ${await r.text()}`)
  return (await r.json()) as T
}

/** Blinded-key derivation for one payment's shared secret (public outputs). */
export const deriveSpendable = (service: string, ss: Hex) => callService<DerivedSpendable>(service, '/derive', { ss })

/** Blinded ML-DSA signature over a 32-byte hash (the userOpHash). */
export const signSpendable = (service: string, ss: Hex, challenge: Hex) =>
  callService<{ sig: Hex }>(service, '/sign', { ss, challenge })

/** PKContract constructor args from the abi(bytes,bytes,bytes) blob. */
export function decodePublicKeyData(
  publicKeyData: Hex,
): readonly [readonly (readonly (readonly bigint[])[])[], Hex, readonly (readonly bigint[])[]] {
  const [aHatEnc, tr, t1Enc] = decodeAbiParameters(
    [{ type: 'bytes' }, { type: 'bytes' }, { type: 'bytes' }],
    publicKeyData,
  )
  const [aHat] = decodeAbiParameters([{ type: 'uint256[][][]' }], aHatEnc)
  const [t1] = decodeAbiParameters([{ type: 'uint256[][]' }], t1Enc)
  return [aHat, tr, t1] as const
}

export function spendableViewTag(ss: Uint8Array): Uint8Array {
  return sha256(ss).slice(0, 1) // same announcement rail as the other schemes
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

/** maxFeePerGas × total gas limits — the EntryPoint's AA21 prefund bound. */
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
    // one df999ed ML-DSA verify (t1 plain, NTT recomputed) is ~15M gas
    accountGasLimits: packPair(20_000_000n, 200_000n), // verification | call
    preVerificationGas: 150_000n,
    gasFees: packPair(1_000_000_000n, maxFee), // priority | max
    paymasterAndData: '0x',
    signature: '0x',
  }
}
