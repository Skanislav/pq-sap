/**
 * EIP-8141 frame-transaction playground on the public frames testnet (chain
 * 81410). The user generates a throwaway wallet, funds it from the faucet, then
 * builds/signs/broadcasts a real type-0x06 transaction with the js-client
 * frame-tx code — the same bytes verified against `rex`.
 *
 * A throwaway in-page key is required because no browser wallet (and no viem tx
 * layer) can sign type 0x06 yet; the key only ever holds faucet funds.
 */

import { useCallback, useEffect, useState } from 'react'
import { formatEther, type Hex, isAddress, parseEther } from 'viem'

import { buildEoaTransfer, rpc, sendRawFrameTx } from '../../../js-client/src/frame-tx/actions.ts'
import type { ChainConfig } from '../lib/chain.ts'
import { useThrowawayWallet } from '../lib/throwaway.ts'
import { AddressChip, CopyButton, HexBlob, Note } from './bits.tsx'

interface Result {
  sigHash: Hex
  raw: Hex
  hash: Hex
  status?: string
  blockNumber?: bigint
  gasUsed?: bigint
  txType?: string
}

const FAUCET_URL = 'https://faucet.frames.ethrex.xyz/'

export function FramesTab({ cfg }: { cfg: ChainConfig }) {
  const rpcUrl = cfg.rpcUrl
  const explorerTx = (h: string) => `${cfg.explorer}/tx/${h}`
  const wallet = useThrowawayWallet()

  const [to, setTo] = useState('0x000000000000000000000000000000000000dEaD')
  const [amount, setAmount] = useState('0.001')
  const [balance, setBalance] = useState<bigint | null>(null)
  const [block, setBlock] = useState<bigint | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<Result | null>(null)

  const refresh = useCallback(async () => {
    try {
      const bn = await rpc<Hex>(rpcUrl, 'eth_blockNumber', [])
      setBlock(BigInt(bn))
      if (wallet.address) {
        const bal = await rpc<Hex>(rpcUrl, 'eth_getBalance', [wallet.address, 'latest'])
        setBalance(BigInt(bal))
      } else {
        setBalance(null)
      }
    } catch {
      /* RPC down / chain reset — keep last values */
    }
  }, [rpcUrl, wallet.address])

  useEffect(() => {
    refresh()
    const id = setInterval(refresh, 4000)
    return () => clearInterval(id)
  }, [refresh])

  const send = async () => {
    setError(null)
    setResult(null)
    if (!wallet.privateKey || !wallet.address) {
      setError('Generate a wallet first')
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
        rpc<Hex>(rpcUrl, 'eth_getTransactionCount', [wallet.address, 'pending']),
        rpc<Hex>(rpcUrl, 'eth_gasPrice', []),
      ])
      const gasPrice = BigInt(gasPriceHex)
      const { raw, sigHash } = await buildEoaTransfer({
        chainId: BigInt(cfg.chain.id),
        nonce: BigInt(nonceHex),
        sender: wallet.address,
        to: to as Hex,
        value: parseEther(amount),
        privateKey: wallet.privateKey,
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
        refresh()
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  const funded = balance !== null && balance > 0n

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

      <h3>Throwaway wallet</h3>
      {!wallet.address ? (
        <div className="panel">
          <p className="fine" style={{ margin: 0 }}>
            A random testnet wallet, kept only in this browser — it holds nothing but faucet funds. Browser wallets
            can't sign type <code>0x06</code>, so the demo signs with this key.
          </p>
          <div className="row">
            <button type="button" onClick={wallet.generate}>
              Generate wallet
            </button>
          </div>
        </div>
      ) : (
        <div className="panel">
          <div className="kv">
            <span className="addr">
              <AddressChip address={wallet.address} explorer={cfg.explorer} /> <CopyButton text={wallet.address} />
            </span>
            <span className={funded ? 'val' : 'val dim'}>{balance === null ? '…' : `${formatEther(balance)} ETH`}</span>
          </div>
          {funded ? (
            <Note kind="ok">Funded — send a frame transaction below.</Note>
          ) : (
            <Note kind="warn">
              Fund this wallet first: copy the address, open the{' '}
              <a href={FAUCET_URL} target="_blank" rel="noreferrer">
                frames faucet ↗
              </a>
              , paste it and request test ETH. The balance updates here automatically.
            </Note>
          )}
          <div className="row">
            <button type="button" className="secondary" onClick={wallet.generate}>
              New wallet
            </button>
            <button type="button" className="ghost" onClick={wallet.clear}>
              Forget
            </button>
          </div>
        </div>
      )}

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
        {!funded && wallet.address && <span className="fine">fund the wallet to enable sending</span>}
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
