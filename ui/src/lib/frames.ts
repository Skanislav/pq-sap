/**
 * Frame-transaction (EIP-8141) plumbing shared by the UI's frames paths:
 * broadcast + receipt (with per-frame results), a fee policy for the public
 * frames testnet, a balance poll for the throwaway sponsor wallet, and the
 * builder's per-transaction execution-gas cap.
 */

import { useEffect, useState } from 'react'
import type { Address, Hex } from 'viem'

import { rpc as frameRpc, sendRawFrameTx } from '../../../js-client/src/frame-tx/actions.ts'

/**
 * EIP-7825 per-transaction cap (`TX_MAX_GAS_LIMIT_AMSTERDAM` = 2^24 in ethrex),
 * measured against a frame tx's TOTAL execution gas (Σ limits.execution). The
 * block builder drops an over-cap frame tx *silently* — the ingress accepts it
 * and returns a hash, then it never mines — so every frame list has to be
 * budgeted under this up front.
 */
export const TX_EXEC_GAS_CAP = 16_777_216n

export interface FrameResult {
  status: 'success' | 'reverted'
  gasUsed: bigint
}

export interface FrameReceipt {
  hash: Hex
  status: 'success' | 'reverted'
  gasUsed: bigint
  blockNumber: bigint
  /** ethrex reports one entry per frame (`frameReceipts`), in order. */
  frames: FrameResult[]
}

interface RawReceipt {
  status: Hex
  gasUsed: Hex
  blockNumber: Hex
  frameReceipts?: { status: Hex; gasUsed: Hex }[]
}

/** Broadcast a raw `0x06` frame tx and wait for its receipt. */
export async function broadcastFrameTx(rpcUrl: string, raw: Hex): Promise<FrameReceipt> {
  let hash: Hex | null = null
  for (let attempt = 1; !hash; attempt++) {
    try {
      hash = await sendRawFrameTx(rpcUrl, raw)
    } catch (e) {
      // the public RPC occasionally drops the connection on large bodies
      const net = e instanceof TypeError || /fetch failed|ECONNRESET|socket/i.test(String(e))
      if (!net || attempt >= 3) throw e
      await new Promise((x) => setTimeout(x, 2500))
    }
  }
  let r: RawReceipt | null = null
  for (let i = 0; i < 60 && !r; i++) {
    r = await frameRpc<RawReceipt | null>(rpcUrl, 'eth_getTransactionReceipt', [hash])
    if (!r) await new Promise((x) => setTimeout(x, 1500))
  }
  if (!r)
    throw new Error(
      `Frame tx ${hash.slice(0, 10)}… was accepted but never mined. The builder silently drops frame txs whose ` +
        `total execution gas exceeds ${TX_EXEC_GAS_CAP.toLocaleString()} (EIP-7825 cap), or whose payer cannot front max_cost.`,
    )
  const st = (s: Hex): 'success' | 'reverted' => (s === '0x1' ? 'success' : 'reverted')
  return {
    hash,
    status: st(r.status),
    gasUsed: BigInt(r.gasUsed),
    blockNumber: BigInt(r.blockNumber),
    frames: (r.frameReceipts ?? []).map((f) => ({ status: st(f.status), gasUsed: BigInt(f.gasUsed) })),
  }
}

/**
 * Fee policy for the frames testnet: its base fee is a few wei and the
 * proposer accepts ~100-wei tips, so a 0.1 gwei tip over 2× the quoted price
 * is generous. Kept low on purpose — the payer fronts `max_gas × maxFeePerGas`
 * at APPROVE time, and a sponsored PQ spend reserves ~17M gas.
 */
export async function frameFees(rpcUrl: string): Promise<{ maxFeePerGas: bigint; maxPriorityFeePerGas: bigint }> {
  const gp = BigInt(await frameRpc<Hex>(rpcUrl, 'eth_gasPrice', []))
  const tip = 100_000_000n // 0.1 gwei
  return { maxFeePerGas: gp * 2n + tip, maxPriorityFeePerGas: tip }
}

/** `pending` nonce — rapid back-to-back frame txs collide on `latest`. */
export async function pendingNonce(rpcUrl: string, address: Address): Promise<bigint> {
  return BigInt(await frameRpc<Hex>(rpcUrl, 'eth_getTransactionCount', [address, 'pending']))
}

/** Poll an address's native balance every 4 s (null while unknown / no address). */
export function useNativeBalance(rpcUrl: string, address: Address | null): bigint | null {
  const [balance, setBalance] = useState<bigint | null>(null)
  useEffect(() => {
    if (!address) {
      setBalance(null)
      return
    }
    let live = true
    const tick = async () => {
      try {
        const b = await frameRpc<Hex>(rpcUrl, 'eth_getBalance', [address, 'latest'])
        if (live) setBalance(BigInt(b))
      } catch {
        /* keep the last value */
      }
    }
    tick()
    const id = setInterval(tick, 4000)
    return () => {
      live = false
      clearInterval(id)
    }
  }, [rpcUrl, address])
  return balance
}
