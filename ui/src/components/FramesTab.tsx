/**
 * EIP-8141 frame-transaction playground on the public frames testnet (chain
 * 81410): build/sign/broadcast a real type-0x06 transfer with the js-client
 * frame-tx code — the same bytes verified against `rex`. Signed by the in-page
 * frames wallet managed in the header (no browser wallet can sign 0x06 yet).
 */

import { useCallback, useEffect, useState } from 'react'
import { type Hex, isAddress, parseEther } from 'viem'

import { buildEoaTransfer, rpc, sendRawFrameTx } from '../../../js-client/src/frame-tx/actions.ts'
import type { ChainConfig } from '../lib/chain.ts'
import type { Wallet } from '../lib/useWallet.ts'
import { HexBlob, Note } from './bits.tsx'

interface Result {
  sigHash: Hex
  raw: Hex
  hash: Hex
  status?: string
  blockNumber?: bigint
  gasUsed?: bigint
  txType?: string
}

export function FramesTab({ cfg, wallet }: { cfg: ChainConfig; wallet: Wallet }) {
  const rpcUrl = cfg.rpcUrl
  const explorerTx = (h: string) => `${cfg.explorer}/tx/${h}`
  const tw = wallet.throwaway

  const [to, setTo] = useState('0x000000000000000000000000000000000000dEaD')
  const [amount, setAmount] = useState('0.001')
  const [block, setBlock] = useState<bigint | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<Result | null>(null)

  const refresh = useCallback(async () => {
    try {
      const bn = await rpc<Hex>(rpcUrl, 'eth_blockNumber', [])
      setBlock(BigInt(bn))
    } catch {
      /* RPC down / chain reset — keep last value */
    }
  }, [rpcUrl])

  useEffect(() => {
    refresh()
    const id = setInterval(refresh, 4000)
    return () => clearInterval(id)
  }, [refresh])

  const send = async () => {
    setError(null)
    setResult(null)
    if (!tw.privateKey || !tw.address) {
      setError('Generate the in-page wallet first (header).')
      return
    }
    if (!isAddress(to)) {
      setError('Recipient is not a valid address')
      return
    }
    setBusy(true)
    try {
      const [nonceHex, gasPriceHex] = await Promise.all([
        // 'pending' so rapid successive sends don't reuse an in-flight nonce.
        rpc<Hex>(rpcUrl, 'eth_getTransactionCount', [tw.address, 'pending']),
        rpc<Hex>(rpcUrl, 'eth_gasPrice', []),
      ])
      const gasPrice = BigInt(gasPriceHex)
      const { raw, sigHash } = await buildEoaTransfer({
        chainId: BigInt(cfg.chain.id),
        nonce: BigInt(nonceHex),
        sender: tw.address,
        to: to as Hex,
        value: parseEther(amount),
        privateKey: tw.privateKey,
        maxFeePerGas: gasPrice * 2n + 1_000_000_000n,
        maxPriorityFeePerGas: 1_000_000_000n,
      })
      const hash = await sendRawFrameTx(rpcUrl, raw)
      setResult({ sigHash, raw, hash })

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

  const funded = wallet.mode === 'throwaway' && wallet.balance !== null && wallet.balance > 0n

  return (
    <section>
      <h2>Frame transaction</h2>
      <p className="lede">
        EIP-8141 (type <code>0x06</code>) native account abstraction: instead of one ECDSA signature, an ordered list of{' '}
        <strong>frames</strong>. The transfer here is two — a <code>VERIFY</code> frame that approves execution and
        payment for the sender, then a <code>SENDER</code> frame that moves the value.
      </p>

      <div className="metastrip">
        <span>
          <strong>{cfg.label}</strong> · chain {cfg.chain.id}
        </span>
        <span>block {block === null ? '…' : block.toString()}</span>
      </div>

      <h3>Send</h3>
      <label className="field">
        <span>Recipient</span>
        <input value={to} onChange={(e) => setTo(e.target.value.trim())} spellCheck={false} placeholder="0x…" />
      </label>
      <label className="field narrow">
        <span>Amount (ETH)</span>
        <input value={amount} onChange={(e) => setAmount(e.target.value.trim())} inputMode="decimal" />
      </label>
      <div className="row">
        <button type="button" onClick={() => void send()} disabled={busy || !funded}>
          {busy ? 'Sending frame tx…' : 'Send frame transaction'}
        </button>
        {!funded && <span className="fine">generate and fund the in-page wallet (header) to enable sending</span>}
      </div>

      {error && <Note kind="error">{error}</Note>}

      {result && (
        <div className="panel">
          <Note kind={result.status === 'success' ? 'ok' : result.status ? 'error' : 'info'}>
            {result.status
              ? `Mined in block ${result.blockNumber} — type ${result.txType}, ${result.status}, gasUsed ${result.gasUsed}`
              : 'Broadcast — waiting for the receipt…'}
          </Note>
          <div className="kv">
            <span className="fine">transaction</span>
            <a href={explorerTx(result.hash)} target="_blank" rel="noreferrer">
              {result.hash.slice(0, 20)}… ↗
            </a>
          </div>
          <HexBlob label="sig_hash" value={result.sigHash} />
          <HexBlob label="raw 0x06 tx" value={result.raw} />
        </div>
      )}
    </section>
  )
}
