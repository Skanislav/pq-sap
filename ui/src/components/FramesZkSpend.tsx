/**
 * Key-exchange route (D-024) with a client-side zero-knowledge spend (D-025),
 * on the frames testnet (deployment `frames-zk-deployment.json`):
 *
 *   meta      the demo recipient's commitment meta-address, format 0x02:
 *             0x02 || spend_key(32) || ML-KEM-768 ek(1184) = 1,217 B, where
 *             spend_key = keccak("…/preimage/key/v0" || sk) for a 32-byte secret
 *   receive   encapsulate → opener = SHA-256(dom || ss) → commitment =
 *             keccak(dom || spend_key || opener) → CREATE2 account of the
 *             commitment; one 0x06 tx from the in-page wallet pays it AND announces
 *   scan      ML-KEM-768 decapsulate → view tag → re-derive commitment → address
 *   spend     one 0x06 tx = [VERIFY(sponsor), DEFAULT(factory.createAccount)?,
 *             DEFAULT(account.executeFrame)] whose signature #1 is an UltraHonk
 *             proof — made HERE, in a web worker with noir_js + bb.js — that the
 *             spender knows the secret behind the commitment, bound to the tx's
 *             sig_hash. No signature scheme, no signer service, nothing revealed:
 *             spends by the same recipient cannot be linked.
 */

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js'
import { useEffect, useMemo, useRef, useState } from 'react'
import { type Address, encodeFunctionData, formatEther, getAddress, type Hex, hexToBytes, parseEther } from 'viem'

import {
  accountAddress,
  computeViewTag,
  decodeCommitMetaAddress,
  type Deployment,
  deriveCommitment,
  deriveOpener,
  encodeCommitMetaAddress,
  ML_KEM_768_CT_BYTES,
  PREIMAGE_DOMAINS,
  spendKeyFromSecret,
} from '../../../js-client/src/commit-scheme.ts'
import { buildAnnounceTransfer, buildSponsoredPqTx, defaultFrame, SPONSORED_PQ_SIG_INDEX } from '../../../js-client/src/frame-tx/actions.ts'
import { ANNOUNCER_ABI } from '../../../js-client/src/sepolia.ts'
import { fetchAnnouncements, type OnchainAnnouncement } from '../lib/announcements.ts'
import { type ChainConfig, publicClientFor, SCHEME_ID } from '../lib/chain.ts'
import { parseTxError } from '../lib/errors.ts'
import { broadcastFrameTx, type FrameReceipt, frameFees, pendingNonce } from '../lib/frames.ts'
import { fromHex, toHex } from '../lib/hex.ts'
import { secretFromSeed } from '../lib/preimage-prover.ts'
import { ACCOUNT_8141_ABI } from '../lib/spend4337.ts'
import { usd } from '../lib/useEthUsd.ts'
import type { Wallet } from '../lib/useWallet.ts'
import { AddressChip, HexBlob, Note } from './bits.tsx'

interface ZkDeployment {
  scheme: string
  chainId: number
  announcer: Address
  frameCtx: Address
  verifier: Address
  factory: Address
  creationCode: Hex
  demo: { spendSeed: Hex; kemD: Hex; kemZ: Hex }
}

interface Hit {
  ann: OnchainAnnouncement
  ss: Uint8Array
  opener: Hex
  commitment: Hex
  account: Address
  balance: bigint
  deployed: boolean
}

interface ProofTimings {
  witness: number
  prove: number
  total: number
}

interface SpendOutcome {
  dest: Address
  amount: string
  receipt: FrameReceipt
  sigHash: Hex
  proofBytes: number
  rawBytes: number
  timings: ProofTimings
  deployedInTx: boolean
}

interface SpendState {
  dest: string
  amount: string
  step?: string | undefined
  error?: string | undefined
  outcome?: SpendOutcome | undefined
}

const FACTORY_ZK_ABI = [
  { type: 'function', name: 'createAccount', stateMutability: 'nonpayable', inputs: [{ name: 'commitment', type: 'bytes32' }], outputs: [{ type: 'address' }] },
] as const

// measured live (D-023/D-025): deploy frame 37k exec / ~5.7M state on this chain;
// proof verify + call ≈ 3.5M exec (forge 2.94M); an under-budgeted frame dies at 63/64
const SPONSOR_VERIFY_GAS = 100_000n
const DEPLOY_FRAME_EXEC_GAS = 400_000n
const DEPLOY_FRAME_STATE_GAS = 6_000_000n
const SPEND_FRAME_EXEC_GAS = 8_000_000n
const SPEND_FRAME_STATE_GAS = 250_000n

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

/** One worker per component instance; proofs are requested by id. */
function useProver() {
  const workerRef = useRef<Worker | null>(null)
  const pending = useRef(new Map<number, { resolve: (v: { proof: Hex; timings: ProofTimings }) => void; reject: (e: Error) => void }>())
  const nextId = useRef(1)
  useEffect(() => {
    const w = new Worker(new URL('../lib/preimage-worker.ts', import.meta.url), { type: 'module' })
    w.onmessage = (e: MessageEvent<{ id: number; proof?: Hex; timings?: { witness: number; prove: number }; total?: number; error?: string }>) => {
      const p = pending.current.get(e.data.id)
      if (!p) return
      pending.current.delete(e.data.id)
      if (e.data.error || !e.data.proof || !e.data.timings) p.reject(new Error(e.data.error ?? 'prover returned nothing'))
      else p.resolve({ proof: e.data.proof, timings: { ...e.data.timings, total: e.data.total ?? 0 } })
    }
    w.onerror = (ev) => {
      for (const p of pending.current.values()) p.reject(new Error(`prover worker: ${ev.message}`))
      pending.current.clear()
    }
    workerRef.current = w
    return () => w.terminate()
  }, [])
  return (message: Uint8Array, commitment: Uint8Array, sk: Uint8Array, opener: Uint8Array) =>
    new Promise<{ proof: Hex; timings: ProofTimings }>((resolve, reject) => {
      const w = workerRef.current
      if (!w) return reject(new Error('prover worker not ready'))
      const id = nextId.current++
      pending.current.set(id, { resolve, reject })
      w.postMessage({ id, message, commitment, sk, opener })
    })
}

export function FramesZkSpend({ cfg, ethUsd, wallet }: { cfg: ChainConfig; ethUsd: number | null; wallet: Wallet }) {
  const sponsor = wallet.throwaway
  const sponsorBalance = wallet.mode === 'throwaway' ? wallet.balance : null
  const [dep, setDep] = useState<ZkDeployment | null | 'loading'>('loading')
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [hits, setHits] = useState<Hit[] | null>(null)
  const [scanInfo, setScanInfo] = useState<string | null>(null)
  const [receiveAmount, setReceiveAmount] = useState('0.001')
  const [lastReceive, setLastReceive] = useState<{ receipt: FrameReceipt; account: Address; commitment: Hex } | null>(null)
  const [spendState, setSpendState] = useState<Record<string, SpendState>>({})
  const prove = useProver()

  useEffect(() => {
    let alive = true
    fetch('/frames-zk-deployment.json')
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => alive && setDep(d && d.scheme === 'preimage' ? d : null))
      .catch(() => alive && setDep(null))
    return () => {
      alive = false
    }
  }, [])

  // demo recipient: secret from the spend seed, ML-KEM-768 viewing key from the KEM seeds
  const recipient = useMemo(() => {
    if (!dep || dep === 'loading') return null
    const sk = secretFromSeed(fromHex(dep.demo.spendSeed))
    const spendKey = spendKeyFromSecret(sk)
    const seed = new Uint8Array(64)
    seed.set(fromHex(dep.demo.kemD), 0)
    seed.set(fromHex(dep.demo.kemZ), 32)
    const kem = ml_kem768.keygen(seed)
    const metaAddress = encodeCommitMetaAddress(spendKey, kem.publicKey)
    return { sk, spendKey, kem, metaAddress, meta: decodeCommitMetaAddress(metaAddress) }
  }, [dep])

  const deployment = (): Deployment => {
    if (!dep || dep === 'loading') throw new Error('No ZK deployment on this network (ui/public/frames-zk-deployment.json).')
    return { factory: dep.factory, creationCode: dep.creationCode, verifier: dep.verifier, frameCtx: dep.frameCtx }
  }

  const requireSponsor = () => {
    if (!sponsor.address || !sponsor.privateKey) throw new Error('Generate and fund the in-page wallet first (header).')
    if (sponsorBalance === 0n) throw new Error('The in-page wallet (the sponsor) is empty — fund it at the faucet first.')
    return { address: sponsor.address, privateKey: sponsor.privateKey }
  }

  const receive = async () => {
    setError(null)
    setBusy('receive')
    try {
      const sp = requireSponsor()
      if (!recipient) throw new Error('Recipient not ready.')
      const d = deployment()
      const { cipherText, sharedSecret } = ml_kem768.encapsulate(recipient.kem.publicKey)
      const commitment = deriveCommitment(recipient.spendKey, deriveOpener(sharedSecret, PREIMAGE_DOMAINS), PREIMAGE_DOMAINS)
      const account = accountAddress(commitment, d)
      const value = parseEther(receiveAmount as `${number}`)
      const [nonce, fees] = await Promise.all([pendingNonce(cfg.rpcUrl, sp.address), frameFees(cfg.rpcUrl)])
      const { raw } = await buildAnnounceTransfer({
        chainId: BigInt(cfg.chain.id),
        nonce,
        sender: sp.address,
        stealthAddress: account,
        value,
        announcer: cfg.announcer,
        announceData: encodeFunctionData({
          abi: ANNOUNCER_ABI,
          functionName: 'announce',
          args: [SCHEME_ID, account, toHex(cipherText) as Hex, toHex(computeViewTag(sharedSecret)) as Hex],
        }),
        privateKey: sp.privateKey,
        ...fees,
      })
      const receipt = await broadcastFrameTx(cfg.rpcUrl, raw)
      if (receipt.status !== 'success') throw new Error(`receive frame tx reverted (${receipt.hash})`)
      setLastReceive({ receipt, account, commitment })
      await scan()
    } catch (e) {
      setError(parseTxError(e))
    } finally {
      setBusy(null)
    }
  }

  const scan = async () => {
    setError(null)
    if (!recipient) return
    setBusy('scan')
    try {
      const d = deployment()
      const publicClient = publicClientFor(cfg)
      const { announcements } = await fetchAnnouncements(cfg, publicClient, setScanInfo)
      const found: Hit[] = []
      for (const ann of announcements) {
        if (ann.ephemeralPubKey.length !== ML_KEM_768_CT_BYTES) continue
        let ss: Uint8Array
        try {
          ss = ml_kem768.decapsulate(ann.ephemeralPubKey, recipient.kem.secretKey)
        } catch {
          continue
        }
        if (!bytesEqual(computeViewTag(ss), ann.viewTag)) continue
        const opener = deriveOpener(ss, PREIMAGE_DOMAINS)
        const commitment = deriveCommitment(recipient.spendKey, opener, PREIMAGE_DOMAINS)
        const account = accountAddress(commitment, d)
        if (account.toLowerCase() !== toHex(ann.stealthAddress)) continue
        const [balance, code] = await Promise.all([
          publicClient.getBalance({ address: account }),
          publicClient.getCode({ address: account }),
        ])
        found.push({ ann, ss, opener, commitment, account, balance, deployed: (code?.length ?? 0) > 2 })
      }
      setHits(found)
      setScanInfo(`${announcements.length} announcements scanned`)
    } catch (e) {
      setError(parseTxError(e))
    } finally {
      setBusy(null)
    }
  }

  const spend = async (hit: Hit) => {
    const key = hit.ann.txHash
    const st = spendState[key] ?? { dest: '', amount: '' }
    const patch = (p: Partial<SpendState>) => setSpendState((s) => ({ ...s, [key]: { ...(s[key] ?? st), ...p } }))
    patch({ error: undefined, outcome: undefined })
    try {
      const sp = requireSponsor()
      if (!recipient) throw new Error('Recipient not ready.')
      const d = deployment()
      const dest = getAddress(st.dest.trim())
      const value = parseEther(st.amount as `${number}`)
      if (value > hit.balance)
        throw new Error(`The stealth account holds ${formatEther(hit.balance)} ETH. Gas is paid by the sponsor, so that is all it needs to cover.`)
      const fees = await frameFees(cfg.rpcUrl)
      const front =
        (SPONSOR_VERIFY_GAS + SPEND_FRAME_EXEC_GAS + SPEND_FRAME_STATE_GAS + (hit.deployed ? 0n : DEPLOY_FRAME_EXEC_GAS + DEPLOY_FRAME_STATE_GAS) + 500_000n) *
        fees.maxFeePerGas
      if (sponsorBalance !== null && sponsorBalance < front)
        throw new Error(`The sponsor must front max_cost ≈ ${formatEther(front)} ETH (unused gas is refunded) — top it up at the faucet.`)

      patch({ step: 'Building the sponsored frame tx…' })
      const nonce = await pendingNonce(cfg.rpcUrl, sp.address)
      let proofBytes = 0
      let timings: ProofTimings = { witness: 0, prove: 0, total: 0 }
      const frames = [
        ...(hit.deployed
          ? []
          : [
              defaultFrame({
                target: d.factory,
                executionGas: DEPLOY_FRAME_EXEC_GAS,
                stateGas: DEPLOY_FRAME_STATE_GAS,
                data: encodeFunctionData({ abi: FACTORY_ZK_ABI, functionName: 'createAccount', args: [hit.commitment] }),
              }),
            ]),
        defaultFrame({
          target: hit.account,
          executionGas: SPEND_FRAME_EXEC_GAS,
          stateGas: SPEND_FRAME_STATE_GAS,
          data: encodeFunctionData({ abi: ACCOUNT_8141_ABI, functionName: 'executeFrame', args: [SPONSORED_PQ_SIG_INDEX, dest, value, '0x'] }),
        }),
      ]
      const { raw, sigHash } = await buildSponsoredPqTx({
        chainId: BigInt(cfg.chain.id),
        nonce,
        sponsor: sp.address,
        sponsorPrivateKey: sp.privateKey,
        frames,
        pqSign: async (h) => {
          patch({ step: `Proving knowledge of the secret for sig_hash ${h.slice(0, 10)}… in the browser (UltraHonk)…` })
          const r = await prove(hexToBytes(h), hexToBytes(hit.commitment), recipient.sk, hexToBytes(hit.opener))
          proofBytes = (r.proof.length - 2) / 2
          timings = r.timings
          return r.proof
        },
        ...fees,
      })
      patch({ step: 'Broadcasting the 0x06 tx (proof verified on-chain, ~3.5M gas)…' })
      const receipt = await broadcastFrameTx(cfg.rpcUrl, raw)
      if (receipt.status !== 'success') {
        const failed = receipt.frames.findIndex((f) => f.status !== 'success')
        throw new Error(`frame tx ${receipt.hash} reverted${failed >= 0 ? ` at frame ${failed} (${receipt.frames[failed]!.gasUsed} gas used)` : ''}`)
      }
      patch({
        step: undefined,
        outcome: { dest, amount: st.amount, receipt, sigHash, proofBytes, rawBytes: (raw.length - 2) / 2, timings, deployedInTx: !hit.deployed },
      })
      await scan()
    } catch (e) {
      patch({ step: undefined, error: parseTxError(e) })
    }
  }

  if (dep === 'loading') return <p className="fine">Loading ZK deployment…</p>
  if (!dep)
    return (
      <Note kind="warn">
        No preimage-scheme ZK deployment for this network. On the frames testnet run <code>npm run deploy:frames:zk</code>{' '}
        (writes <code>ui/public/frames-zk-deployment.json</code>).
      </Note>
    )

  return (
    <div>
      <h3>Key-exchange route — commitment meta-address, proof of the secret made in the browser</h3>
      <p className="lede">
        The meta-address is <strong>1,217 bytes</strong>: a version byte, a 32-byte hash of the recipient's spending
        secret, and the ML-KEM-768 viewing key. No lattice material, no signature scheme. The sender derives a
        per-payment commitment from the shared secret and pays the CREATE2 account bound to it. Spending proves, in a
        web worker on this machine, that the spender knows the secret behind the commitment — bound to the
        transaction's <code>sig_hash</code> — and the account verifies the proof on-chain. Nothing about the secret
        or the recipient appears on chain, so spends cannot be linked.
      </p>
      <p className="fine">
        Verifier <AddressChip address={dep.verifier} explorer={cfg.explorer} />, factory{' '}
        <AddressChip address={dep.factory} explorer={cfg.explorer} />, frame context{' '}
        <AddressChip address={dep.frameCtx} explorer={cfg.explorer} />. Circuit <code>{dep.scheme}</code>: two keccak
        calls, 40,626 UltraHonk gates; proving takes a few seconds with bb.js.
      </p>
      {recipient && (
        <div className="panel">
          <div className="kv">
            <span>
              demo recipient meta-address · format <code>0x02</code> · {recipient.metaAddress.length.toLocaleString()} B
            </span>
            <span className="val dim">vs 5,633 B for the ML-DSA form</span>
          </div>
          <HexBlob label="meta-address" value={toHex(recipient.metaAddress)} />
          <p className="fine" style={{ margin: '4px 0 0' }}>
            <code>0x02</code> ‖ spend_key <code>{recipient.spendKey}</code> ‖ ML-KEM-768 ek (1,184 B). The secret behind
            spend_key stays in this page; it is derived from the demo seed and never sent anywhere.
          </p>
        </div>
      )}

      <div className="row">
        <label className="field narrow" style={{ margin: 0 }}>
          <span>Receive amount (ETH){usd(Number(receiveAmount), ethUsd)}</span>
          <input value={receiveAmount} inputMode="decimal" onChange={(e) => setReceiveAmount(e.target.value)} />
        </label>
        <button type="button" disabled={busy !== null || !recipient} onClick={receive}>
          {busy === 'receive' ? 'Receiving…' : 'Receive (self-send, frame tx)'}
        </button>
        <button type="button" className="secondary" disabled={busy !== null || !recipient} onClick={scan}>
          {busy === 'scan' ? (scanInfo ?? 'Scanning…') : 'Scan for payments'}
        </button>
      </div>
      {error && <Note kind="error">{error}</Note>}
      {lastReceive && (
        <Note kind="ok">
          Paid <AddressChip address={lastReceive.account} explorer={cfg.explorer} /> and announced in one frame tx{' '}
          <TxLink hash={lastReceive.receipt.hash} explorer={cfg.explorer} /> ({lastReceive.receipt.gasUsed.toLocaleString()}{' '}
          gas). Commitment <code>{lastReceive.commitment.slice(0, 18)}…</code>.
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
        const set = (p: Partial<SpendState>) => setSpendState((s) => ({ ...s, [h.ann.txHash]: { ...st, ...p } }))
        return (
          <div className="hit" key={h.ann.txHash}>
            <div>
              <AddressChip address={h.account} explorer={cfg.explorer} />{' '}
              <strong>
                {formatEther(h.balance)} ETH{usd(Number(formatEther(h.balance)), ethUsd)}
              </strong>
              <span className="hexmeta">
                {' '}
                · block {h.ann.blockNumber.toString()} · {h.deployed ? 'account deployed' : 'counterfactual (deploys inside the spend tx)'}
              </span>
            </div>
            <div className="row" style={{ margin: '6px 0 0' }}>
              <div className="inputwrap" style={{ flex: 2, minWidth: 260 }}>
                <input placeholder="destination 0x…" value={st.dest} spellCheck={false} onChange={(e) => set({ dest: e.target.value })} />
                <button
                  type="button"
                  className="ghost"
                  title="send back to the in-page wallet (the sponsor)"
                  disabled={!sponsor.address}
                  onClick={() => sponsor.address && set({ dest: sponsor.address })}
                >
                  self
                </button>
              </div>
              <div className="inputwrap" style={{ width: 170 }}>
                <input placeholder="amount ETH" inputMode="decimal" value={st.amount} onChange={(e) => set({ amount: e.target.value })} />
                <button type="button" className="ghost" title="the whole balance — gas is paid by the sponsor" onClick={() => set({ amount: formatEther(h.balance) })}>
                  max
                </button>
              </div>
              <button type="button" disabled={!!st.step || !st.dest.trim() || !st.amount} onClick={() => spend(h)}>
                {st.step ?? 'Spend (prove in browser + sponsored frame tx)'}
              </button>
            </div>
            {st.error && <Note kind="error">{st.error}</Note>}
            {st.outcome && <Outcome o={st.outcome} explorer={cfg.explorer} />}
          </div>
        )
      })}
    </div>
  )
}

function Outcome({ o, explorer }: { o: SpendOutcome; explorer: string | null }) {
  const frames = o.receipt.frames
  const labels = o.deployedInTx
    ? ['VERIFY(sponsor, BOTH) · secp256k1', 'DEFAULT(factory.createAccount) · in-tx deploy', 'DEFAULT(account.executeFrame) · proof verify']
    : ['VERIFY(sponsor, BOTH) · secp256k1', 'DEFAULT(account.executeFrame) · proof verify']
  const s = (ms: number) => `${(ms / 1000).toFixed(2)} s`
  return (
    <div className="panel">
      <Note kind="ok">
        Spent {o.amount} ETH → {o.dest} in frame tx <TxLink hash={o.receipt.hash} explorer={explorer} /> —{' '}
        {o.receipt.gasUsed.toLocaleString()} gas, all paid by the sponsor
        {o.deployedInTx ? ', account deployed in the same tx' : ''}.
      </Note>
      <div className="metastrip">
        {frames.map((f, i) => (
          <span key={labels[i] ?? i}>
            frame {i} · {labels[i] ?? 'DEFAULT'} · <strong>{`${f.status} · ${f.gasUsed.toLocaleString()} gas`}</strong>
          </span>
        ))}
      </div>
      <div className="kv">
        <span>
          signatures: <code>secp256k1</code> (sponsor) + <code>ARBITRARY</code> UltraHonk proof {o.proofBytes.toLocaleString()} B, made in this browser
        </span>
        <span className="val dim">{o.rawBytes.toLocaleString()} B raw</span>
      </div>
      <div className="kv">
        <span>
          witness {s(o.timings.witness)} · UltraHonk prove {s(o.timings.prove)} · worker total {s(o.timings.total)}
        </span>
      </div>
      <div className="kv">
        <span>
          sig_hash (public input of the proof, read back on-chain via TXPARAM) <code>{o.sigHash}</code>
        </span>
      </div>
    </div>
  )
}
