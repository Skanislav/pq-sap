/**
 * Pimlico bundler + verifying paymaster for the Sepolia PQ spend route.
 *
 * With a paymaster the stealth account needs NO ETH for gas — the paymaster
 * sponsors the userOp (fixes the AA21 funding friction) and, for a stealth
 * scheme, removes the privacy leak of funding the account's gas from a
 * linkable EOA. Pimlico also bundles the op, so we no longer self-bundle
 * handleOps.
 *
 * ERC-4337 v0.7 (EntryPoint 0x…da032). The bundler/paymaster RPCs speak the
 * UNPACKED userOp format; the account/EntryPoint hash uses the PACKED form.
 * We keep both and convert. Mirrors ethereum/kohaku's userOperation.ts.
 */

import { type Address, concatHex, encodeAbiParameters, type Hex, keccak256, numberToHex, toHex } from 'viem'

export const ENTRYPOINT_V07: Address = '0x0000000071727De22E5E9d8BAf0edAc6f37da032'

export function pimlicoUrl(chainId: number, apiKey: string): string {
  return `https://api.pimlico.io/v2/${chainId}/rpc?apikey=${encodeURIComponent(apiKey)}`
}

/** Unpacked userOp as the bundler/paymaster JSON-RPC expects it. */
export interface UnpackedUserOp {
  sender: Address
  nonce: bigint
  callData: Hex
  callGasLimit: bigint
  verificationGasLimit: bigint
  preVerificationGas: bigint
  maxFeePerGas: bigint
  maxPriorityFeePerGas: bigint
  paymaster?: Address | undefined
  paymasterVerificationGasLimit?: bigint | undefined
  paymasterPostOpGasLimit?: bigint | undefined
  paymasterData?: Hex | undefined
  signature: Hex
}

const hx = (v: bigint): Hex => numberToHex(v)

function toRpc(op: UnpackedUserOp): Record<string, unknown> {
  const r: Record<string, unknown> = {
    sender: op.sender,
    nonce: hx(op.nonce),
    callData: op.callData,
    callGasLimit: hx(op.callGasLimit),
    verificationGasLimit: hx(op.verificationGasLimit),
    preVerificationGas: hx(op.preVerificationGas),
    maxFeePerGas: hx(op.maxFeePerGas),
    maxPriorityFeePerGas: hx(op.maxPriorityFeePerGas),
    signature: op.signature,
  }
  if (op.paymaster) {
    r.paymaster = op.paymaster
    r.paymasterVerificationGasLimit = hx(op.paymasterVerificationGasLimit ?? 0n)
    r.paymasterPostOpGasLimit = hx(op.paymasterPostOpGasLimit ?? 0n)
    r.paymasterData = op.paymasterData ?? '0x'
  }
  return r
}

async function rpc<T>(url: string, method: string, params: unknown[]): Promise<T> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  })
  const json = (await res.json()) as { result?: T; error?: { message?: string } }
  if (json.error) throw new Error(`${method}: ${json.error.message ?? 'RPC error'}`)
  if (json.result === undefined) throw new Error(`${method}: empty result`)
  return json.result
}

const packUint128Pair = (hi: bigint, lo: bigint): Hex => toHex((hi << 128n) | lo, { size: 32 })

/** paymaster(20) ‖ pmVerificationGasLimit(16) ‖ pmPostOpGasLimit(16) ‖ data */
export function packPaymasterAndData(op: UnpackedUserOp): Hex {
  if (!op.paymaster) return '0x'
  return concatHex([
    op.paymaster,
    toHex(op.paymasterVerificationGasLimit ?? 0n, { size: 16 }),
    toHex(op.paymasterPostOpGasLimit ?? 0n, { size: 16 }),
    op.paymasterData ?? '0x',
  ])
}

/** EntryPoint v0.7 userOpHash (same formula as ethereum/kohaku). */
export function computeUserOpHash(op: UnpackedUserOp, chainId: number): Hex {
  const accountGasLimits = packUint128Pair(op.verificationGasLimit, op.callGasLimit)
  const gasFees = packUint128Pair(op.maxPriorityFeePerGas, op.maxFeePerGas)
  const packed = keccak256(
    encodeAbiParameters(
      [
        { type: 'address' },
        { type: 'uint256' },
        { type: 'bytes32' },
        { type: 'bytes32' },
        { type: 'bytes32' },
        { type: 'uint256' },
        { type: 'bytes32' },
        { type: 'bytes32' },
      ],
      [
        op.sender,
        op.nonce,
        keccak256('0x'),
        keccak256(op.callData),
        accountGasLimits,
        op.preVerificationGas,
        gasFees,
        keccak256(packPaymasterAndData(op)),
      ],
    ),
  )
  return keccak256(
    encodeAbiParameters(
      [{ type: 'bytes32' }, { type: 'address' }, { type: 'uint256' }],
      [packed, ENTRYPOINT_V07, BigInt(chainId)],
    ),
  )
}

export async function getUserOpGasPrice(url: string): Promise<{ maxFeePerGas: bigint; maxPriorityFeePerGas: bigint }> {
  const r = await rpc<{ standard: { maxFeePerGas: Hex; maxPriorityFeePerGas: Hex } }>(
    url,
    'pimlico_getUserOperationGasPrice',
    [],
  )
  return {
    maxFeePerGas: BigInt(r.standard.maxFeePerGas),
    maxPriorityFeePerGas: BigInt(r.standard.maxPriorityFeePerGas),
  }
}

interface SponsorResult {
  paymaster: Address
  paymasterData: Hex
  paymasterVerificationGasLimit?: Hex
  paymasterPostOpGasLimit?: Hex
  callGasLimit?: Hex
  verificationGasLimit?: Hex
  preVerificationGas?: Hex
}

/** Ask the paymaster to sponsor the op (estimation + sponsorship). Returns
 *  a copy of the op with paymaster fields + refined gas limits attached. */
export async function sponsorUserOp(
  url: string,
  op: UnpackedUserOp,
  context?: Record<string, unknown>,
): Promise<UnpackedUserOp> {
  const params: unknown[] = [toRpc(op), ENTRYPOINT_V07]
  if (context) params.push(context)
  const r = await rpc<SponsorResult>(url, 'pm_sponsorUserOperation', params)
  return {
    ...op,
    paymaster: r.paymaster,
    paymasterData: r.paymasterData,
    paymasterVerificationGasLimit: r.paymasterVerificationGasLimit
      ? BigInt(r.paymasterVerificationGasLimit)
      : op.paymasterVerificationGasLimit,
    paymasterPostOpGasLimit: r.paymasterPostOpGasLimit ? BigInt(r.paymasterPostOpGasLimit) : op.paymasterPostOpGasLimit,
    callGasLimit: r.callGasLimit ? BigInt(r.callGasLimit) : op.callGasLimit,
    verificationGasLimit: r.verificationGasLimit ? BigInt(r.verificationGasLimit) : op.verificationGasLimit,
    preVerificationGas: r.preVerificationGas ? BigInt(r.preVerificationGas) : op.preVerificationGas,
  }
}

export async function sendUserOp(url: string, op: UnpackedUserOp): Promise<Hex> {
  return rpc<Hex>(url, 'eth_sendUserOperation', [toRpc(op), ENTRYPOINT_V07])
}

/**
 * End-to-end sponsored spend: fetch gas price, sponsor (paymaster +
 * estimation), sign the final hash, submit, and wait for the receipt.
 * `sign` receives the final userOpHash and returns the account signature —
 * for the ZKNOX hybrid account that's the ECDSA + blinded ML-DSA pack.
 */
export async function submitSponsoredUserOp(args: {
  url: string
  chainId: number
  sender: Address
  nonce: bigint
  callData: Hex
  dummySignature: Hex
  sign: (userOpHash: Hex) => Promise<Hex>
  onStep?: (msg: string) => void
  context?: Record<string, unknown>
}): Promise<{ userOpHash: Hex; txHash: Hex; gasUsed: bigint; success: boolean }> {
  const { url, chainId, sender, nonce, callData, dummySignature, sign, onStep, context } = args
  onStep?.('Fetching gas price…')
  const gp = await getUserOpGasPrice(url)
  let op: UnpackedUserOp = {
    sender,
    nonce,
    callData,
    callGasLimit: 500_000n,
    verificationGasLimit: 10_000_000n, // ZKNOX ML-DSA verify (~8.35M) + headroom
    preVerificationGas: 1_000_000n,
    maxFeePerGas: gp.maxFeePerGas,
    maxPriorityFeePerGas: gp.maxPriorityFeePerGas,
    signature: dummySignature,
  }
  onStep?.('Requesting paymaster sponsorship…')
  op = await sponsorUserOp(url, op, context)
  const userOpHash = computeUserOpHash(op, chainId)
  onStep?.('Signing (ECDSA + blinded ML-DSA)…')
  op = { ...op, signature: await sign(userOpHash) }
  onStep?.('Submitting through the Pimlico bundler…')
  const sent = await sendUserOp(url, op)
  onStep?.('Waiting for the userOp receipt…')
  const receipt = await waitForUserOpReceipt(url, sent)
  return {
    userOpHash: sent,
    txHash: receipt.receipt.transactionHash,
    gasUsed: receipt.actualGasUsed,
    success: receipt.success,
  }
}

export interface UserOpReceipt {
  success: boolean
  actualGasUsed: bigint
  receipt: { transactionHash: Hex }
}

/** Poll for the userOp receipt (bundler includes it in a block). */
export async function waitForUserOpReceipt(
  url: string,
  userOpHash: Hex,
  opts: { tries?: number; delayMs?: number } = {},
): Promise<UserOpReceipt> {
  const tries = opts.tries ?? 60
  const delayMs = opts.delayMs ?? 2000
  for (let i = 0; i < tries; i++) {
    // A `null` result means "not mined yet" (normal); a thrown error is a real
    // RPC failure — surface the first one so a bad key/endpoint isn't hidden as
    // a silent timeout.
    type RawReceipt = { success: boolean; actualGasUsed: Hex; receipt: { transactionHash: Hex } }
    let r: RawReceipt | null = null
    try {
      r = await rpc<RawReceipt | null>(url, 'eth_getUserOperationReceipt', [userOpHash])
    } catch (e) {
      if (i === 0) console.error(`  receipt poll error: ${(e as Error).message}`)
    }
    if (r)
      return {
        success: r.success,
        actualGasUsed: BigInt(r.actualGasUsed),
        receipt: r.receipt,
      }
    await new Promise((res) => setTimeout(res, delayMs))
  }
  throw new Error('timed out waiting for the userOp receipt')
}
