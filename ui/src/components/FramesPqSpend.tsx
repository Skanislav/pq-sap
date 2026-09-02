/**
 * PQ spend route over EIP-8141 frame transactions (frames testnet, deployment
 * mode `stealth8141`): gas abstraction + a post-quantum authorization.
 *
 *   receive  one 0x06 tx from the throwaway wallet pays the counterfactual
 *            Stealth8141Account AND emits its ERC-5564 announcement
 *   scan     ML-KEM-512 decapsulate → view tag → re-derive the blinded ML-DSA
 *            key → CREATE2 address must match
 *   spend    one 0x06 tx = [VERIFY(sponsor, BOTH), DEFAULT(account.executeFrame)]
 *            with signatures [secp256k1(sponsor), ARBITRARY(ML-DSA)]. The
 *            account reads the tx's sig_hash (TXPARAM) and the ML-DSA bytes
 *            (SIGDATACOPY) through the FrameTxContext helper, verifies on-chain
 *            (~15M gas), and moves the funds. The sponsor — here the user's own
 *            throwaway wallet — pays every wei of gas; the stealth account only
 *            ever holds the amount being spent.
 *
 * Why the account isn't tx.sender: APPROVE_PAYMENT requires sender approval
 * first, so a self-paying PQ account would put its ML-DSA verification inside
 * the mempool-bounded validation prefix (MAX_VERIFY_GAS = 100k). Sponsoring
 * ends the prefix after the sponsor's secp256k1 check, and the PQ verification
 * runs as ordinary execution — the one shape a public network admits today.
 *
 * Why the first spend is two txs: the builder caps a frame tx's total
 * execution gas at 2^24 (EIP-7825) and deploying PKContract + account costs
 * ~43M here, so the deploy goes in a type-2 tx (uncapped on this network) and
 * the spend is the frame tx.
 *
 * Destinations: any address, the sponsor itself ("self"), or a freshly derived
 * stealth account of the demo recipient — then a third DEFAULT frame emits the
 * ERC-5564 announcement in the same tx, so the payment is a stealth-to-stealth
 * transfer the scanner finds again.
 */

import { ml_kem512 } from '@noble/post-quantum/ml-kem.js'
import { useMemo, useState } from 'react'
import { type Address, createWalletClient, encodeFunctionData, formatEther, getAddress, type Hex, http, parseEther } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'

import {
  buildAnnounceTransfer,
  buildSponsoredPqTx,
  defaultFrame,
  SPONSORED_PQ_SIG_INDEX,
} from '../../../js-client/src/frame-tx/actions.ts'
import { ANNOUNCER_ABI } from '../../../js-client/src/sepolia.ts'
import { fetchAnnouncements, type OnchainAnnouncement } from '../lib/announcements.ts'
import { type ChainConfig, publicClientFor, SCHEME_ID } from '../lib/chain.ts'
import { parseTxError } from '../lib/errors.ts'
import { broadcastFrameTx, type FrameReceipt, frameFees, pendingNonce, TX_EXEC_GAS_CAP } from '../lib/frames.ts'
import { fromHex, toHex } from '../lib/hex.ts'
import {
  ACCOUNT_8141_ABI,
  decodePublicKeyData,
  deriveSpendable,
  type DevDeployment,
  FACTORY_ABI,
  signSpendable,
  spendableViewTag,
} from '../lib/spend4337.ts'
import { usd } from '../lib/useEthUsd.ts'
import type { Wallet } from '../lib/useWallet.ts'
import { AddressChip, Note } from './bits.tsx'

interface Hit {
  ann: OnchainAnnouncement
  ssHex: Hex
  pkArgs: ReturnType<typeof decodePublicKeyData>
  account: Address
  balance: bigint
  deployed: boolean
}

/** A freshly derived stealth account of the demo recipient, announced on spend. */
interface FreshStealth {
  account: Address
  cipherHex: Hex
  viewTag: Hex
}

interface SpendOutcome {
  dest: Address
  amount: string
  /** the destination was a fresh stealth account, announced in the same tx */
  announced: boolean
  deploy?: { hash: Hex; gasUsed: bigint } | undefined
  receipt: FrameReceipt
  sigHash: Hex
  sigBytes: number
  rawBytes: number
}

interface SpendState {
  dest: string
  amount: string
  step?: string | undefined
  deriving?: boolean | undefined
  fresh?: FreshStealth | undefined
  error?: string | undefined
  outcome?: SpendOutcome | undefined
}

/** VERIFY(sponsor) is 100k of the cap; the spend frame takes the rest. */
const SPONSOR_VERIFY_GAS = 100_000n
const SPEND_FRAME_EXEC_GAS = TX_EXEC_GAS_CAP - SPONSOR_VERIFY_GAS - 77_216n // 16.6M
const SPEND_FRAME_STATE_GAS = 250_000n
/** the announce frame (stealth-to-stealth spend) is carved out of the spend frame's budget */
const ANNOUNCE_FRAME_GAS = 200_000n
const ACCOUNT_DEPLOY_GAS = 50_000_000n // type-2 tx; ~43M used

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let d = 0
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!
  return d === 0
}

function TxLink({ hash, explorer }: { hash: string; explorer: string | null }) {
  const short = `${hash.slice(0, 10)}…`
  return explorer ? (
    <a href={`${explorer}/tx/${hash}`} target="_blank" rel="noreferrer">
      {short}
    </a>
  ) : (
    <code>{short}</code>
  )
}

export function FramesPqSpend({
  cfg,
  dep,
  ethUsd,
  wallet,
}: {
  cfg: ChainConfig
  dep: DevDeployment
  ethUsd: number | null
  wallet: Wallet
}) {
  // the sponsor is the in-page frames wallet managed in the header
  const sponsor = wallet.throwaway
  const sponsorBalance = wallet.mode === 'throwaway' ? wallet.balance : null
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [hits, setHits] = useState<Hit[] | null>(null)
  const [scanInfo, setScanInfo] = useState<string | null>(null)
  const [receiveAmount, setReceiveAmount] = useState('0.01')
  const [lastReceive, setLastReceive] = useState<FrameReceipt | null>(null)
  const [spendState, setSpendState] = useState<Record<string, SpendState>>({})

  // demo recipient: fixed ML-KEM-512 seeds shared with the signer service
  const demoKem = useMemo(() => {
    if (!dep.demo) return null
    const seed = new Uint8Array(64)
    seed.set(fromHex(dep.demo.kemD), 0)
    seed.set(fromHex(dep.demo.kemZ), 32)
    return ml_kem512.keygen(seed)
  }, [dep])

  const requireSponsor = () => {
    if (!sponsor.address || !sponsor.privateKey) throw new Error('Generate and fund the in-page wallet first (header).')
    if (sponsorBalance === 0n) throw new Error('The in-page wallet (the sponsor) is empty — fund it at the faucet first.')
    return { address: sponsor.address, privateKey: sponsor.privateKey }
  }

  const accountFor = async (pkArgs: Hit['pkArgs']) =>
    publicClientFor(cfg).readContract({ address: dep.factory, abi: FACTORY_ABI, functionName: 'getAccountAddress', args: pkArgs })

  /** Encapsulate to the demo recipient and derive its next counterfactual stealth account. */
  const freshStealth = async (): Promise<FreshStealth> => {
    if (!demoKem) throw new Error('Deployment has no demo recipient seeds.')
    const { cipherText, sharedSecret } = ml_kem512.encapsulate(demoKem.publicKey)
    const derived = await deriveSpendable(dep.signerService, toHex(sharedSecret) as Hex)
    const account = await accountFor(decodePublicKeyData(derived.public_key_data))
    return { account, cipherHex: toHex(cipherText) as Hex, viewTag: derived.view_tag }
  }

  const announceCall = (f: FreshStealth) =>
    encodeFunctionData({ abi: ANNOUNCER_ABI, functionName: 'announce', args: [SCHEME_ID, f.account, f.cipherHex, f.viewTag] })

  const receive = async () => {
    setError(null)
    setBusy('receive')
    try {
      const sp = requireSponsor()
      const fresh = await freshStealth()
      const account = fresh.account
      const value = parseEther(receiveAmount as `${number}`)
      const [nonce, fees] = await Promise.all([pendingNonce(cfg.rpcUrl, sp.address), frameFees(cfg.rpcUrl)])
      const { raw } = await buildAnnounceTransfer({
        chainId: BigInt(cfg.chain.id),
        nonce,
        sender: sp.address,
        stealthAddress: account,
        value,
        announcer: cfg.announcer,
        announceData: announceCall(fresh),
        privateKey: sp.privateKey,
        ...fees,
      })
      const r = await broadcastFrameTx(cfg.rpcUrl, raw)
      if (r.status !== 'success') throw new Error(`receive frame tx reverted (${r.hash})`)
      setLastReceive(r)
      await scan()
    } catch (e) {
      setError(parseTxError(e))
    } finally {
      setBusy(null)
    }
  }

  const scan = async () => {
    setError(null)
    if (!demoKem) return
    setBusy('scan')
    try {
      const publicClient = publicClientFor(cfg)
      const { announcements } = await fetchAnnouncements(cfg, publicClient, setScanInfo)
      const found: Hit[] = []
      for (const ann of announcements) {
        if (ann.ephemeralPubKey.length !== 768) continue // ML-KEM-512 ciphertext only
        let ss: Uint8Array
        try {
          ss = ml_kem512.decapsulate(ann.ephemeralPubKey, demoKem.secretKey)
        } catch {
          continue
        }
        if (!bytesEqual(spendableViewTag(ss), ann.viewTag)) continue
        const ssHex = toHex(ss) as Hex
        const derived = await deriveSpendable(dep.signerService, ssHex)
        const pkArgs = decodePublicKeyData(derived.public_key_data)
        const account = await accountFor(pkArgs)
        if (account.toLowerCase() !== toHex(ann.stealthAddress)) continue
        const [balance, code] = await Promise.all([
          publicClient.getBalance({ address: account }),
          publicClient.getCode({ address: account }),
        ])
        found.push({ ann, ssHex, pkArgs, account, balance, deployed: (code?.length ?? 0) > 2 })
      }
      setHits(found)
      setScanInfo(`${announcements.length} announcements scanned`)
    } catch (e) {
      setError(parseTxError(e))
    } finally {
      setBusy(null)
    }
  }

  const fillFresh = async (hit: Hit) => {
    const key = hit.ann.txHash
    const patch = (p: Partial<SpendState>) =>
      setSpendState((s) => ({ ...s, [key]: { ...(s[key] ?? { dest: '', amount: '' }), ...p } }))
    patch({ deriving: true, error: undefined })
    try {
      const fresh = await freshStealth()
      patch({ deriving: false, fresh, dest: fresh.account })
    } catch (e) {
      patch({ deriving: false, error: parseTxError(e) })
    }
  }

  const spend = async (hit: Hit) => {
    const key = hit.ann.txHash
    const st = spendState[key] ?? { dest: '', amount: '' }
    const patch = (p: Partial<SpendState>) => setSpendState((s) => ({ ...s, [key]: { ...(s[key] ?? st), ...p } }))
    patch({ error: undefined, outcome: undefined })
    try {
      const sp = requireSponsor()
      const dest = getAddress(st.dest.trim())
      const value = parseEther(st.amount as `${number}`)
      // stealth-to-stealth: the tx also announces the destination
      const fresh = st.fresh && st.fresh.account.toLowerCase() === dest.toLowerCase() ? st.fresh : undefined
      if (value > hit.balance)
        throw new Error(
          `The stealth account holds ${formatEther(hit.balance)} ETH. Gas is paid by the sponsor, so that is all it needs to cover.`,
        )
      const publicClient = publicClientFor(cfg)
      const fees = await frameFees(cfg.rpcUrl)
      const front = (SPONSOR_VERIFY_GAS + SPEND_FRAME_EXEC_GAS + SPEND_FRAME_STATE_GAS + 500_000n) * fees.maxFeePerGas
      if (sponsorBalance !== null && sponsorBalance < front)
        throw new Error(
          `The sponsor must front max_cost ≈ ${formatEther(front)} ETH (17M gas × maxFeePerGas; unused gas is refunded) — top it up at the faucet.`,
        )

      let deploy: SpendOutcome['deploy']
      if (!hit.deployed) {
        patch({ step: 'Deploying account (PKContract + CREATE2, type-2 tx, ~43M gas)…' })
        const sponsorWallet = createWalletClient({
          chain: cfg.chain,
          transport: http(cfg.rpcUrl),
          account: privateKeyToAccount(sp.privateKey),
        })
        const h = await sponsorWallet.writeContract({
          address: dep.factory,
          abi: FACTORY_ABI,
          functionName: 'createAccount',
          args: hit.pkArgs,
          gas: ACCOUNT_DEPLOY_GAS,
          ...fees,
        })
        const rc = await publicClient.waitForTransactionReceipt({ hash: h })
        if (rc.status !== 'success') throw new Error(`account deploy reverted (${h})`)
        deploy = { hash: h, gasUsed: rc.gasUsed }
      }

      patch({ step: 'Building the sponsored frame tx…' })
      const nonce = await pendingNonce(cfg.rpcUrl, sp.address)
      let sigBytes = 0
      const { raw, sigHash } = await buildSponsoredPqTx({
        chainId: BigInt(cfg.chain.id),
        nonce,
        sponsor: sp.address,
        sponsorPrivateKey: sp.privateKey,
        frames: [
          defaultFrame({
            target: hit.account,
            executionGas: SPEND_FRAME_EXEC_GAS - (fresh ? ANNOUNCE_FRAME_GAS : 0n),
            stateGas: SPEND_FRAME_STATE_GAS,
            data: encodeFunctionData({
              abi: ACCOUNT_8141_ABI,
              functionName: 'executeFrame',
              args: [SPONSORED_PQ_SIG_INDEX, dest, value, '0x'],
            }),
          }),
          ...(fresh
            ? [
                defaultFrame({
                  target: cfg.announcer,
                  executionGas: ANNOUNCE_FRAME_GAS,
                  stateGas: SPEND_FRAME_STATE_GAS,
                  data: announceCall(fresh),
                }),
              ]
            : []),
        ],
        pqSign: async (h) => {
          patch({ step: `Signing sig_hash ${h.slice(0, 10)}… with the blinded ML-DSA key…` })
          const { sig } = await signSpendable(dep.signerService, hit.ssHex, h)
          sigBytes = (sig.length - 2) / 2
          return sig
        },
        ...fees,
      })
      patch({ step: 'Broadcasting the 0x06 tx (on-chain ML-DSA verify, ~15M gas)…' })
      const receipt = await broadcastFrameTx(cfg.rpcUrl, raw)
      if (receipt.status !== 'success') {
        const failed = receipt.frames.findIndex((f) => f.status !== 'success')
        throw new Error(
          `frame tx ${receipt.hash} reverted${failed >= 0 ? ` at frame ${failed} (${receipt.frames[failed]!.gasUsed} gas used)` : ''}`,
        )
      }
      patch({
        step: undefined,
        outcome: {
          dest,
          amount: st.amount,
          announced: !!fresh,
          deploy,
          receipt,
          sigHash,
          sigBytes,
          rawBytes: (raw.length - 2) / 2,
        },
      })
      await scan()
    } catch (e) {
      patch({ step: undefined, error: parseTxError(e) })
    }
  }

  return (
    <div>
      <h3>PQ route over frame transactions — sponsored gas, ML-DSA authorization</h3>
      <p className="lede">
        The stealth address is the CREATE2 address of a <code>Stealth8141Account</code> bound to the blinded ML-DSA key
        (level-2 profile). Spending is <strong>one type-0x06 transaction</strong>: the sponsor's frame approves payment,
        then an execution frame calls the account, which reads the tx's <code>sig_hash</code> and the ML-DSA signature
        straight from the transaction (<code>TXPARAM</code>/<code>SIGDATACOPY</code>) and verifies it on-chain. The
        account never holds gas money and never signs with a classical key.
      </p>
      <p className="fine">
        Verifier <AddressChip address={dep.verifier} explorer={cfg.explorer} />, factory{' '}
        <AddressChip address={dep.factory} explorer={cfg.explorer} />
        {dep.frameCtx && (
          <>
            , frame context <AddressChip address={dep.frameCtx} explorer={cfg.explorer} />
          </>
        )}
        . Blinded signing runs in the local Python signer service.
      </p>

      <p className="fine">
        The sponsor that pays every frame transaction here is the in-page wallet in the header
        {sponsor.address ? '' : ' — generate and fund it first'}.
      </p>

      <div className="row">
        <label className="field narrow" style={{ margin: 0 }}>
          <span>Receive amount (ETH){usd(Number(receiveAmount), ethUsd)}</span>
          <input value={receiveAmount} inputMode="decimal" onChange={(e) => setReceiveAmount(e.target.value)} />
        </label>
        <button type="button" disabled={busy !== null} onClick={receive}>
          {busy === 'receive' ? 'Receiving…' : 'Receive (self-send, frame tx)'}
        </button>
        <button type="button" className="secondary" disabled={busy !== null} onClick={scan}>
          {busy === 'scan' ? (scanInfo ?? 'Scanning…') : 'Scan for payments'}
        </button>
      </div>
      {error && <Note kind="error">{error}</Note>}
      {lastReceive && (
        <Note kind="ok">
          Paid and announced in one frame tx <TxLink hash={lastReceive.hash} explorer={cfg.explorer} /> (
          {lastReceive.gasUsed.toLocaleString()} gas, frames{' '}
          {lastReceive.frames.map((f) => (f.status === 'success' ? '✓' : '✗')).join(' ')}).
        </Note>
      )}
      {hits && (
        <Note kind={hits.length ? 'ok' : 'info'}>
          {hits.length ? `${hits.length} spendable payment${hits.length === 1 ? '' : 's'} found` : 'No payments found'}
          {scanInfo ? ` — ${scanInfo}` : ''}
        </Note>
      )}
      {hits?.map((h) => {
        const st = spendState[h.ann.txHash] ?? { dest: '', amount: '' }
        const eth = Number(formatEther(h.balance))
        const set = (p: Partial<SpendState>) => setSpendState((s) => ({ ...s, [h.ann.txHash]: { ...st, ...p } }))
        return (
          <div className="hit" key={h.ann.txHash}>
            <div>
              <AddressChip address={h.account} explorer={cfg.explorer} />{' '}
              <strong>
                {formatEther(h.balance)} ETH{usd(eth, ethUsd)}
              </strong>
              <span className="hexmeta">
                {' '}
                · block {h.ann.blockNumber.toString()} ·{' '}
                {h.deployed ? 'account deployed' : 'counterfactual (deploys on first spend)'}
              </span>
            </div>
            <div className="row" style={{ margin: '6px 0 0' }}>
              <div className="inputwrap" style={{ flex: 2, minWidth: 260 }}>
                <input
                  placeholder="destination 0x…"
                  value={st.dest}
                  spellCheck={false}
                  onChange={(e) => set({ dest: e.target.value })}
                />
                <button
                  type="button"
                  className="ghost"
                  title="send back to the in-page wallet (the sponsor)"
                  disabled={!sponsor.address}
                  onClick={() => sponsor.address && set({ dest: sponsor.address })}
                >
                  self
                </button>
                <button
                  type="button"
                  className="ghost"
                  title="derive a fresh stealth account of the demo recipient; the spend announces it too"
                  disabled={!!st.deriving || !demoKem}
                  onClick={() => void fillFresh(h)}
                >
                  {st.deriving ? 'deriving…' : 'new stealth'}
                </button>
              </div>
              <div className="inputwrap" style={{ width: 170 }}>
                <input
                  placeholder="amount ETH"
                  inputMode="decimal"
                  value={st.amount}
                  onChange={(e) => set({ amount: e.target.value })}
                />
                <button
                  type="button"
                  className="ghost"
                  title="the whole balance — gas is paid by the sponsor"
                  onClick={() => set({ amount: formatEther(h.balance) })}
                >
                  max
                </button>
              </div>
              <button type="button" disabled={!!st.step || !st.dest.trim() || !st.amount} onClick={() => spend(h)}>
                {st.step ?? 'Spend (sponsored PQ frame tx)'}
              </button>
            </div>
            {st.fresh && st.fresh.account.toLowerCase() === st.dest.trim().toLowerCase() && (
              <p className="fine" style={{ margin: '4px 0 0' }}>
                Fresh stealth account of the demo recipient — the spend tx also emits its announcement (a third frame),
                so the next scan finds it as a new payment.
              </p>
            )}
            {st.error && <Note kind="error">{st.error}</Note>}
            {st.outcome && <Outcome o={st.outcome} explorer={cfg.explorer} />}
          </div>
        )
      })}
    </div>
  )
}

function Outcome({ o, explorer }: { o: SpendOutcome; explorer: string | null }) {
  const [verify, exec, ann] = [o.receipt.frames[0], o.receipt.frames[1], o.receipt.frames[2]]
  return (
    <div className="panel">
      <Note kind="ok">
        Spent {o.amount} ETH → {o.dest}
        {o.announced ? ' (a fresh stealth account, announced in the same tx)' : ''} in frame tx{' '}
        <TxLink hash={o.receipt.hash} explorer={explorer} /> — {o.receipt.gasUsed.toLocaleString()} gas, all paid by
        the sponsor.
        {o.deploy && (
          <>
            {' '}
            Account deployed first in <TxLink hash={o.deploy.hash} explorer={explorer} /> (
            {o.deploy.gasUsed.toLocaleString()} gas).
          </>
        )}
      </Note>
      <div className="metastrip">
        <span>
          frame 0 · VERIFY(sponsor, BOTH) · secp256k1 ·{' '}
          <strong>
            {verify ? `${verify.status} · ${verify.gasUsed.toLocaleString()} gas` : '—'}
          </strong>
        </span>
        <span>
          frame 1 · DEFAULT(account.executeFrame) · ML-DSA verify ·{' '}
          <strong>{exec ? `${exec.status} · ${exec.gasUsed.toLocaleString()} gas` : '—'}</strong>
        </span>
        {ann && (
          <span>
            frame 2 · DEFAULT(announcer.announce) ·{' '}
            <strong>{`${ann.status} · ${ann.gasUsed.toLocaleString()} gas`}</strong>
          </span>
        )}
      </div>
      <div className="kv">
        <span>
          signatures: <code>secp256k1</code> (sponsor) + <code>ARBITRARY</code> ML-DSA {o.sigBytes.toLocaleString()} B
        </span>
        <span className="val dim">{o.rawBytes.toLocaleString()} B raw</span>
      </div>
      <div className="kv">
        <span>
          sig_hash (signed by both, read back on-chain via TXPARAM) <code>{o.sigHash}</code>
        </span>
      </div>
    </div>
  )
}
