/**
 * EIP-8141 frame-transaction demo against the public frames testnet (chain
 * 81410). Builds, signs, and broadcasts a real type-0x06 transaction with the
 * js-client frame-tx code — the same bytes verified against `rex` — and shows
 * the two-frame [VERIFY(sender), SENDER(to)] structure the EOA path uses.
 *
 * Injected wallets can't sign type 0x06, so this uses an in-page testnet key
 * (the funded ethereum-package dev account), exactly like the anvil dev signer.
 */

import { useEffect, useState } from 'react'
import { formatEther, type Hex, isAddress, parseEther } from 'viem'

import { buildEoaTransfer, rpc, sendRawFrameTx } from '../../../js-client/src/frame-tx/actions.ts'
import { type ChainConfig, FRAMES_DEV_KEY as DEV_KEY } from '../lib/chain.ts'
import { AddressChip, HexBlob, Note } from './bits.tsx'

interface Result {
  sigHash: Hex
  raw: Hex
  hash: Hex
  status?: string
  blockNumber?: bigint
  gasUsed?: bigint
  txType?: string
}

export function FramesTab({ cfg }: { cfg: ChainConfig }) {
  const rpcUrl = cfg.rpcUrl
  const explorerTx = (h: string) => `${cfg.explorer}/tx/${h}`

  const [to, setTo] = useState('0x000000000000000000000000000000000000dEaD')
  const [amount, setAmount] = useState('0.001')
  const [balance, setBalance] = useState<bigint | null>(null)
  const [block, setBlock] = useState<bigint | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<Result | null>(null)

  // Poll network status (block height + our sender balance).
  useEffect(() => {
    let live = true
    const tick = async () => {
      try {
        const [bn, bal] = await Promise.all([
          rpc<Hex>(rpcUrl, 'eth_blockNumber', []),
          rpc<Hex>(rpcUrl, 'eth_getBalance', [DEV_KEY.address, 'latest']),
        ])
        if (!live) return
        setBlock(BigInt(bn))
        setBalance(BigInt(bal))
      } catch {
        /* RPC down / chain reset — leave last values */
      }
    }
    tick()
    const id = setInterval(tick, 4000)
    return () => {
      live = false
      clearInterval(id)
    }
  }, [rpcUrl])

  const send = async () => {
    setError(null)
    setResult(null)
    if (!isAddress(to)) {
      setError('Recipient is not a valid address')
      return
    }
    setBusy(true)
    try {
      const [nonceHex, gasPriceHex] = await Promise.all([
        rpc<Hex>(rpcUrl, 'eth_getTransactionCount', [DEV_KEY.address, 'latest']),
        rpc<Hex>(rpcUrl, 'eth_gasPrice', []),
      ])
      const gasPrice = BigInt(gasPriceHex)
      const { raw, sigHash } = await buildEoaTransfer({
        chainId: BigInt(cfg.chain.id),
        nonce: BigInt(nonceHex),
        sender: DEV_KEY.address,
        to: to as Hex,
        value: parseEther(amount),
        privateKey: DEV_KEY.privateKey,
        maxFeePerGas: gasPrice * 2n + 1_000_000_000n,
        maxPriorityFeePerGas: 1_000_000_000n,
      })
      const hash = await sendRawFrameTx(rpcUrl, raw)
      setResult({ sigHash, raw, hash })

      // Poll for the receipt.
      let rcpt: { status: Hex; blockNumber: Hex; gasUsed: Hex; type: Hex } | null = null
      for (let i = 0; i < 30 && !rcpt; i++) {
        rcpt = await rpc(rpcUrl, 'eth_getTransactionReceipt', [hash])
        if (!rcpt) await new Promise((r) => setTimeout(r, 2000))
      }
      if (rcpt) {
        setResult({
          sigHash,
          raw,
          hash,
          status: rcpt.status === '0x1' ? 'success' : 'reverted',
          blockNumber: BigInt(rcpt.blockNumber),
          gasUsed: BigInt(rcpt.gasUsed),
          txType: rcpt.type,
        })
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="tabpanel">
      <h2>Frame transaction (EIP-8141, type 0x06)</h2>
      <p className="fine">
        A native account-abstraction transaction: instead of one ECDSA signature, an ordered list of{' '}
        <strong>frames</strong>. The EOA transfer below is two frames — a <code>VERIFY</code> frame that approves
        execution and payment for the sender, then a <code>SENDER</code> frame that moves the value — authorized by a
        secp256k1 signature in the transaction's own signature list.
      </p>

      <div className="statusrow">
        <span>
          Network: <strong>{cfg.label}</strong> (chain {cfg.chain.id})
        </span>
        <span>Block: {block === null ? '…' : block.toString()}</span>
      </div>
      <div className="statusrow">
        <span>
          Sender <AddressChip address={DEV_KEY.address} explorer={cfg.explorer} />
        </span>
        <span>Balance: {balance === null ? '…' : `${formatEther(balance)} ETH`}</span>
      </div>

      <div className="form">
        <label>
          Recipient
          <input value={to} onChange={(e) => setTo(e.target.value.trim())} spellCheck={false} />
        </label>
        <label>
          Amount (ETH)
          <input value={amount} onChange={(e) => setAmount(e.target.value.trim())} inputMode="decimal" />
        </label>
        <button type="button" onClick={() => void send()} disabled={busy}>
          {busy ? 'Sending frame tx…' : 'Send frame transaction'}
        </button>
      </div>

      {error && <Note kind="error">{error}</Note>}

      {result && (
        <div className="result">
          <Note kind={result.status === 'success' ? 'ok' : result.status ? 'error' : 'info'}>
            {result.status
              ? `Mined in block ${result.blockNumber} — type ${result.txType}, ${result.status}, gasUsed ${result.gasUsed}`
              : 'Broadcast — waiting for the receipt…'}
          </Note>
          <div className="statusrow">
            <span>Transaction</span>
            <a href={explorerTx(result.hash)} target="_blank" rel="noreferrer">
              {result.hash.slice(0, 18)}… ↗
            </a>
          </div>
          <HexBlob label="sig_hash (what the secp256k1 signature signs)" value={result.sigHash} />
          <HexBlob label="raw 0x06 transaction" value={result.raw} />
        </div>
      )}
    </section>
  )
}
