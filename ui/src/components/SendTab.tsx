/**
 * Sender flow: paste a recipient meta-address, encapsulate a fresh
 * ML-KEM shared secret, derive the one-time stealth address, then
 * (1) pay it and (2) announce on the ERC-5564 announcer.
 */

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js'
import { useMemo, useState } from 'react'
import { formatEther, getAddress, type Hex, parseEther } from 'viem'

import {
  computeViewTag,
  decodeMetaAddress,
  deriveStealthPk,
  META_ADDRESS_BYTES,
  stealthAddressOf,
} from '../../../js-client/src/scheme.ts'
import { ANNOUNCER_ABI } from '../../../js-client/src/sepolia.ts'
import { type ChainConfig, publicClientFor, SCHEME_ID } from '../lib/chain.ts'
import { parseTxError } from '../lib/errors.ts'
import { fromHex, toHex } from '../lib/hex.ts'
import { usd } from '../lib/useEthUsd.ts'
import type { Wallet } from '../lib/useWallet.ts'
import { AddressChip, Note } from './bits.tsx'

type Step = 'idle' | 'derive' | 'pay' | 'announce'

interface SentReceipt {
  stealthAddress: string
  viewTag: string
  amountEth: string
  payTx: string
  announceTx: string
}

// Recovery bundle kept between the (mined) pay and the announce: the ML-KEM
// encapsulation is randomized, so a fresh send targets a *different* address —
// re-sending after an announce failure would strand the already-paid funds.
// Holding these lets the user retry just the announce for the same address.
interface PendingAnnounce {
  stealthAddress: string
  cipherText: Hex
  viewTag: Hex
  amountEth: string
  payTx: string
}

export function SendTab({
  cfg,
  wallet,
  ethUsd,
  myMetaAddress,
}: {
  cfg: ChainConfig
  wallet: Wallet
  ethUsd: number | null
  myMetaAddress: string | null
}) {
  const [metaHex, setMetaHex] = useState('')
  const [amount, setAmount] = useState('0.1')
  const [step, setStep] = useState<Step>('idle')
  const [error, setError] = useState<string | null>(null)
  const [sent, setSent] = useState<SentReceipt | null>(null)
  const [pendingAnnounce, setPendingAnnounce] = useState<PendingAnnounce | null>(null)

  const metaCheck = useMemo(() => {
    const trimmed = metaHex.trim()
    if (!trimmed) return null
    try {
      const bytes = fromHex(trimmed)
      decodeMetaAddress(bytes) // validates length + version
      return { ok: true as const, bytes }
    } catch (e) {
      return { ok: false as const, message: e instanceof Error ? e.message : String(e) }
    }
  }, [metaHex])

  const amountWei = useMemo(() => {
    try {
      return parseEther(amount as `${number}`)
    } catch {
      return null
    }
  }, [amount])

  const gate = wallet.gate(cfg)
  const ready = gate === 'ready' && metaCheck?.ok && amountWei != null && amountWei > 0n

  const buttonLabel =
    step === 'derive'
      ? 'Deriving stealth address…'
      : step === 'pay'
        ? 'Sending payment (1/2)…'
        : step === 'announce'
          ? 'Announcing (2/2)…'
          : gate === 'connect'
            ? 'Connect wallet'
            : gate === 'switch'
              ? `Switch to ${cfg.label}`
              : 'Send & announce'

  // Re-emit only the ERC-5564 announcement for an already-paid stealth address.
  // Shared by the happy path and the retry button so both announce the exact
  // same (address, ciphertext, view tag).
  const announceStealth = async (r: PendingAnnounce): Promise<string> => {
    const walletClient = wallet.clientFor(cfg)
    if (!walletClient?.account) throw new Error('Wallet not ready.')
    const publicClient = publicClientFor(cfg)
    const announceTx = await walletClient.writeContract({
      account: walletClient.account,
      chain: cfg.chain,
      address: cfg.announcer,
      abi: ANNOUNCER_ABI,
      functionName: 'announce',
      args: [SCHEME_ID, getAddress(r.stealthAddress), r.cipherText, r.viewTag],
    })
    await publicClient.waitForTransactionReceipt({ hash: announceTx })
    return announceTx
  }

  const retryAnnounce = async () => {
    if (!pendingAnnounce) return
    setError(null)
    try {
      setStep('announce')
      const announceTx = await announceStealth(pendingAnnounce)
      setSent({
        stealthAddress: pendingAnnounce.stealthAddress,
        viewTag: pendingAnnounce.viewTag,
        amountEth: pendingAnnounce.amountEth,
        payTx: pendingAnnounce.payTx,
        announceTx,
      })
      setPendingAnnounce(null)
    } catch (e) {
      setError(parseTxError(e))
    } finally {
      setStep('idle')
    }
  }

  const run = async () => {
    setError(null)
    setPendingAnnounce(null)
    if (gate === 'connect') {
      try {
        wallet.setMode('injected')
        await wallet.connect()
      } catch (e) {
        setError(parseTxError(e))
      }
      return
    }
    if (gate === 'switch') {
      try {
        await wallet.switchChain(cfg)
      } catch (e) {
        setError(parseTxError(e))
      }
      return
    }
    if (!metaCheck?.ok || amountWei == null) return

    const walletClient = wallet.clientFor(cfg)
    if (!walletClient?.account) {
      setError('Wallet not ready.')
      return
    }
    const publicClient = publicClientFor(cfg)

    try {
      setSent(null)
      setStep('derive')
      // fresh encapsulation → shared secret → one-time stealth address
      const meta = decodeMetaAddress(metaCheck.bytes)
      const { cipherText, sharedSecret } = ml_kem768.encapsulate(meta.kemEk)
      const stealthPk = deriveStealthPk(meta.rho, meta.t, sharedSecret)
      const stealthAddress = getAddress(toHex(stealthAddressOf(stealthPk)))
      const viewTag = toHex(computeViewTag(sharedSecret))

      setStep('pay')
      const payTx = await walletClient.sendTransaction({
        account: walletClient.account,
        chain: cfg.chain,
        to: stealthAddress,
        value: amountWei,
      })
      await publicClient.waitForTransactionReceipt({ hash: payTx })

      // pay is mined — preserve the announce inputs so a failed announce stays
      // retryable without re-encapsulating (which pays a new address and would
      // strand these funds). pendingAnnounce != null ⇒ "paid, announce pending".
      const recovery: PendingAnnounce = {
        stealthAddress,
        cipherText: toHex(cipherText) as Hex,
        viewTag: viewTag as Hex,
        amountEth: formatEther(amountWei),
        payTx,
      }
      setPendingAnnounce(recovery)

      setStep('announce')
      const announceTx = await announceStealth(recovery)
      setSent({ stealthAddress, viewTag, amountEth: formatEther(amountWei), payTx, announceTx })
      setPendingAnnounce(null)
    } catch (e) {
      setError(parseTxError(e))
    } finally {
      setStep('idle')
    }
  }

  const amountNum = Number(amount)

  return (
    <section>
      <h2>Pay to a stealth meta-address</h2>
      <p className="lede">
        Every payment encapsulates a fresh ML-KEM-768 secret, so each one lands on a brand-new address only the
        recipient can find. Two transactions: the payment itself, then the ERC-5564 announcement (scheme{' '}
        {SCHEME_ID.toString()}).
      </p>

      <label className="field">
        <span>Recipient meta-address ({META_ADDRESS_BYTES} bytes hex)</span>
        <textarea
          rows={4}
          spellCheck={false}
          placeholder="0x01…"
          value={metaHex}
          onChange={(e) => setMetaHex(e.target.value)}
        />
      </label>
      {myMetaAddress && (
        <button className="ghost" type="button" onClick={() => setMetaHex(myMetaAddress)}>
          Use my own meta-address (self-payment demo)
        </button>
      )}
      {metaCheck && !metaCheck.ok && <Note kind="error">{metaCheck.message}</Note>}

      <label className="field narrow">
        <span>
          Amount (ETH)
          {Number.isFinite(amountNum) && amountNum > 0 ? usd(amountNum, ethUsd) : ''}
        </span>
        <input type="text" inputMode="decimal" value={amount} onChange={(e) => setAmount(e.target.value)} />
      </label>

      <div className="row">
        <button type="button" disabled={step !== 'idle' || (gate === 'ready' && !ready)} onClick={run}>
          {buttonLabel}
        </button>
      </div>

      {error && <Note kind="error">{error}</Note>}

      {pendingAnnounce && !sent && (
        <Note kind="warn">
          <div>
            Payment of <strong>{pendingAnnounce.amountEth} ETH</strong> to{' '}
            <AddressChip address={pendingAnnounce.stealthAddress} explorer={cfg.explorer} /> is confirmed (
            {txLink(pendingAnnounce.payTx, cfg)}), but the announcement didn't go through. Retry the announcement —
            don't resend, which pays a different address and would strand these funds.
          </div>
          <div className="row">
            <button type="button" disabled={step !== 'idle'} onClick={retryAnnounce}>
              {step === 'announce' ? 'Announcing…' : 'Retry announcement'}
            </button>
          </div>
        </Note>
      )}

      {sent && (
        <Note kind="ok">
          <div>
            Paid{' '}
            <strong>
              {sent.amountEth} ETH{usd(Number(sent.amountEth), ethUsd)}
            </strong>{' '}
            to stealth address <AddressChip address={sent.stealthAddress} explorer={cfg.explorer} /> (view tag{' '}
            <code>{sent.viewTag}</code>)
          </div>
          <div className="fine">
            payment {txLink(sent.payTx, cfg)} · announcement {txLink(sent.announceTx, cfg)}
          </div>
        </Note>
      )}
    </section>
  )
}

function txLink(hash: string, cfg: ChainConfig) {
  const short = `${hash.slice(0, 10)}…`
  return cfg.explorer ? (
    <a href={`${cfg.explorer}/tx/${hash}`} target="_blank" rel="noreferrer">
      {short}
    </a>
  ) : (
    <code>{short}</code>
  )
}
