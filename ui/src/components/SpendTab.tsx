/**
 * Spending — both routes the project implements:
 *
 *  1. Classical-spend hybrid: the stealth address is a plain EOA
 *     (P = K + t·G), so spending is one ordinary ECDSA transaction —
 *     ecrecover, ~21k gas, entirely in the browser.
 *  2. PQ spend (D-014): the stealth address is the counterfactual address
 *     of an ERC-4337 account bound to the blinded ML-DSA key; spending is a
 *     self-bundled userOp whose on-chain validation runs the real lattice
 *     verifier. Two backends by deployment mode: locally, a self-contained
 *     ERC-7913 single-signer account (Stealth7913Factory); on Sepolia, the
 *     already-deployed ZKNOX hybrid account (ethereum/kohaku).
 */

import { ml_kem512, ml_kem768 } from '@noble/post-quantum/ml-kem.js'
import { useEffect, useMemo, useState } from 'react'
import {
  type Address,
  createWalletClient,
  encodeFunctionData,
  formatEther,
  getAddress,
  type Hex,
  http,
  parseEther,
} from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { ANNOUNCER_ABI } from '../../../js-client/src/sepolia.ts'
import { type ChainConfig, publicClientFor, SCHEME_ID } from '../lib/chain.ts'
import {
  type ClassicalKeys,
  checkClassicalAnnouncement,
  classicalViewTag,
  decodeClassicalMeta,
  deriveClassicalKeys,
  deriveStealthPrivkey,
  deriveStealthPubkey,
  encodeCompactMeta,
  ethAddressOfPoint,
  randomClassicalSeeds,
} from '../lib/classical.ts'
import { pimlicoUrl, submitSponsoredUserOp } from '../lib/pimlico.ts'
import { registerViewingKey } from '../lib/registry.ts'
import {
  buildSpendUserOp,
  type DevDeployment,
  decodePublicKeyData,
  deriveSpendable,
  ENTRYPOINT_ABI,
  FACTORY_ABI,
  fetchDeployment,
  requiredPrefund,
  signSpendable,
  spendableViewTag,
} from '../lib/spend4337.ts'
import {
  buildSpendUserOp as buildHybridUserOp,
  dummyHybridSignature,
  ACCOUNT_ABI as HYBRID_ACCOUNT_ABI,
  ENTRYPOINT_ABI as HYBRID_ENTRYPOINT_ABI,
  packHybridSignature,
  preQuantumDemoKey,
  requiredPrefund as requiredPrefundHybrid,
  ZKNOX_FACTORY_ABI,
} from '../lib/spendHybrid.ts'

/** ERC-4337 accounts must hold value + prefund at validation; a clear
 *  message beats the raw "FailedOp … AA21 didn't pay prefund". */
function ensureFunded(balance: bigint, value: bigint, prefund: bigint): void {
  const need = value + prefund
  if (balance >= need) return
  const eth = (w: bigint) => formatEther(w)
  throw new Error(
    `Account holds ${eth(balance)} ETH but this spend needs ~${eth(need)} ` +
      `(amount ${eth(value)} + ~${eth(prefund)} gas prefund). ` +
      `Fund it first with "Receive demo payment".`,
  )
}

import { fetchAnnouncements, type OnchainAnnouncement } from '../lib/announcements.ts'
import { parseTxError } from '../lib/errors.ts'
import { fromHex, toHex } from '../lib/hex.ts'
import { clearClassicalSeeds, loadClassicalSeeds, saveClassicalSeeds } from '../lib/storage.ts'
import { usd } from '../lib/useEthUsd.ts'
import type { Wallet } from '../lib/useWallet.ts'
import { AddressChip, HexBlob, Note } from './bits.tsx'

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let d = 0
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!
  return d === 0
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

export function SpendTab({ cfg, wallet, ethUsd }: { cfg: ChainConfig; wallet: Wallet; ethUsd: number | null }) {
  return (
    <section>
      <h2>Spend received payments</h2>
      <p className="lede">
        Two spend routes: the <strong>classical hybrid</strong> spends from a plain EOA with one ECDSA transaction
        (ecrecover, ~21k gas, quantum-vulnerable ownership); the <strong>PQ route</strong> spends through an ERC-4337
        account whose ERC-7913 signer verifies the blinded ML-DSA key on-chain (~15M gas).
      </p>
      <ClassicalSpend cfg={cfg} wallet={wallet} ethUsd={ethUsd} />
      <hr className="split" />
      <PqSpend cfg={cfg} wallet={wallet} ethUsd={ethUsd} />
    </section>
  )
}

// ---------------------------------------------------------------------------
// 1. classical hybrid — EOA spend
// ---------------------------------------------------------------------------

interface ClassicalHit {
  ann: OnchainAnnouncement
  sharedSecret: Uint8Array
  address: Address
  balance: bigint
}

function ClassicalSpend({ cfg, wallet, ethUsd }: { cfg: ChainConfig; wallet: Wallet; ethUsd: number | null }) {
  const [keys, setKeys] = useState<ClassicalKeys | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [hits, setHits] = useState<ClassicalHit[] | null>(null)
  const [scanInfo, setScanInfo] = useState<string | null>(null)
  const [receiveAmount, setReceiveAmount] = useState('0.25')
  const [dep, setDep] = useState<DevDeployment | null>(null)
  const [compact, setCompact] = useState<{ index: bigint; bytes: Uint8Array } | null>(null)
  const [spendState, setSpendState] = useState<
    Record<
      string,
      {
        dest: string
        amount: string
        result?: string | undefined
        error?: string | undefined
        pending?: boolean | undefined
      }
    >
  >({})

  useEffect(() => {
    const seeds = loadClassicalSeeds()
    if (seeds) {
      try {
        setKeys(deriveClassicalKeys(seeds))
      } catch {
        clearClassicalSeeds()
      }
    }
  }, [])

  useEffect(() => {
    setCompact(null)
    fetchDeployment(cfg.key).then((d) => setDep(d))
  }, [cfg.key])

  const registerCompact = async () => {
    if (!keys || !dep?.registry) return
    setError(null)
    const walletClient = wallet.clientFor(cfg)
    if (!walletClient?.account) {
      setError('Connect a wallet (or use the anvil dev account).')
      return
    }
    setBusy('register')
    try {
      const publicClient = publicClientFor(cfg)
      const meta = decodeClassicalMeta(keys.metaAddress)
      const { index } = await registerViewingKey(publicClient, walletClient, cfg, dep.registry, meta.kemEk)
      setCompact({ index, bytes: encodeCompactMeta(meta.spendPub, index) })
    } catch (e) {
      setError(parseTxError(e))
    } finally {
      setBusy(null)
    }
  }

  const identity = (source: 'random' | 'vector-a') => {
    setBusy('identity')
    setTimeout(async () => {
      try {
        let k: ClassicalKeys
        if (source === 'vector-a') {
          const cv = (await import('../../../python/vectors/classical/v0/vectors.json')).default
          const s = (
            cv as {
              recipients: Record<string, { seeds: { spend_seed: string; kem_d: string; kem_z: string } }>
            }
          ).recipients.A!.seeds
          k = deriveClassicalKeys({
            spendSeed: fromHex(s.spend_seed),
            kemD: fromHex(s.kem_d),
            kemZ: fromHex(s.kem_z),
          })
        } else {
          k = deriveClassicalKeys(randomClassicalSeeds())
        }
        saveClassicalSeeds(k.seeds)
        setKeys(k)
        setHits(null)
        setError(null)
      } catch (e) {
        setError(parseTxError(e))
      } finally {
        setBusy(null)
      }
    }, 20)
  }

  const receive = async () => {
    if (!keys) return
    setError(null)
    const walletClient = wallet.clientFor(cfg)
    if (!walletClient?.account) {
      setError('Connect a wallet (or use the anvil dev account).')
      return
    }
    setBusy('receive')
    try {
      const publicClient = publicClientFor(cfg)
      const meta = decodeClassicalMeta(keys.metaAddress)
      const { cipherText, sharedSecret } = ml_kem768.encapsulate(meta.kemEk)
      const P = deriveStealthPubkey(meta.spendPub, sharedSecret)
      const addr = getAddress(toHex(ethAddressOfPoint(P)))
      const value = parseEther(receiveAmount as `${number}`)
      const payTx = await walletClient.sendTransaction({
        account: walletClient.account,
        chain: cfg.chain,
        to: addr,
        value,
      })
      await publicClient.waitForTransactionReceipt({ hash: payTx })
      const annTx = await walletClient.writeContract({
        account: walletClient.account,
        chain: cfg.chain,
        address: cfg.announcer,
        abi: ANNOUNCER_ABI,
        functionName: 'announce',
        args: [SCHEME_ID, addr, toHex(cipherText) as Hex, toHex(classicalViewTag(sharedSecret)) as Hex],
      })
      await publicClient.waitForTransactionReceipt({ hash: annTx })
      await scan()
    } catch (e) {
      setError(parseTxError(e))
    } finally {
      setBusy(null)
    }
  }

  const scan = async () => {
    if (!keys) return
    setError(null)
    setBusy('scan')
    try {
      const publicClient = publicClientFor(cfg)
      const meta = decodeClassicalMeta(keys.metaAddress)
      const { announcements, fromBlock, toBlock } = await fetchAnnouncements(cfg, publicClient, (m) => setScanInfo(m))
      const found: ClassicalHit[] = []
      for (const ann of announcements) {
        const payment = checkClassicalAnnouncement(meta, keys.kemDk, ann)
        if (!payment) continue
        const address = getAddress(toHex(ann.stealthAddress))
        found.push({
          ann,
          sharedSecret: payment.sharedSecret,
          address,
          balance: await publicClient.getBalance({ address }),
        })
      }
      setHits(found)
      setScanInfo(`${announcements.length} announcements scanned (blocks ${fromBlock}–${toBlock})`)
    } catch (e) {
      setError(parseTxError(e))
    } finally {
      setBusy(null)
    }
  }

  const spend = async (hit: ClassicalHit) => {
    const key = hit.ann.txHash
    const st = spendState[key] ?? { dest: '', amount: '' }
    const patch = (p: Partial<typeof st>) => setSpendState((s) => ({ ...s, [key]: { ...(s[key] ?? st), ...p } }))
    patch({ error: undefined, result: undefined, pending: true })
    try {
      if (!keys) throw new Error('no keys')
      const dest = getAddress(st.dest.trim())
      const value = parseEther(st.amount as `${number}`)
      const priv = deriveStealthPrivkey(keys.seeds.spendSeed, hit.sharedSecret)
      const stealthAccount = privateKeyToAccount(toHex(priv) as Hex)
      if (stealthAccount.address.toLowerCase() !== hit.address.toLowerCase())
        throw new Error('derived key does not control this stealth address')
      const stealthWallet = createWalletClient({
        chain: cfg.chain,
        transport: http(cfg.rpcUrl),
        account: stealthAccount,
      })
      const publicClient = publicClientFor(cfg)
      const hash = await stealthWallet.sendTransaction({ to: dest, value })
      const rcpt = await publicClient.waitForTransactionReceipt({ hash })
      patch({
        pending: false,
        result: `Spent ${st.amount} ETH → ${dest} (${rcpt.gasUsed} gas, plain ECDSA). Tx ${hash.slice(0, 10)}…`,
      })
      await scan()
    } catch (e) {
      patch({ pending: false, error: parseTxError(e) })
    }
  }

  return (
    <div>
      <h3>Classical hybrid — spend from the EOA (ecrecover)</h3>
      <p className="fine">
        Scheme <code>secp256k1+ML-KEM-768</code> (1,218 B meta-address): discovery is post-quantum, the spending key is
        secp256k1 — <code>p = k + t</code> controls the stealth EOA directly.
      </p>
      <div className="row">
        <button type="button" className="secondary" disabled={busy !== null} onClick={() => identity('vector-a')}>
          Use test recipient A
        </button>
        <button type="button" className="secondary" disabled={busy !== null} onClick={() => identity('random')}>
          Generate new identity
        </button>
      </div>
      {keys && (
        <>
          <HexBlob label="Full meta-address (1,218 B)" value={toHex(keys.metaAddress)} />
          <div className="row">
            <button
              type="button"
              className="secondary"
              disabled={busy !== null || !dep?.registry}
              onClick={registerCompact}
            >
              {busy === 'register' ? 'Registering…' : 'Register viewing key → 65-byte compact meta-address'}
            </button>
          </div>
          {!dep?.registry && (
            <p className="fine">
              (Compact meta-address needs the StealthKeyRegistry — run <code>npm run chain</code>, or deploy it to{' '}
              {cfg.label} with <code>npm run deploy:sepolia</code>.)
            </p>
          )}
          {compact && (
            <>
              <HexBlob label={`Compact meta-address (registry #${compact.index})`} value={toHex(compact.bytes)} />
              <p className="fine">
                65 bytes: spend pubkey (33 B, SEC1 compressed — its parity byte is the version) ‖ registry index (32 B).
                Share this instead of the 1,218-byte form; the viewing key is fetched from the registry by index. A
                malicious registry can only deny detection, never redirect funds — the spend pubkey is inline.
              </p>
            </>
          )}
          <div className="row">
            <label className="field narrow" style={{ margin: 0 }}>
              <span>Receive amount (ETH){usd(Number(receiveAmount), ethUsd)}</span>
              <input value={receiveAmount} inputMode="decimal" onChange={(e) => setReceiveAmount(e.target.value)} />
            </label>
            <button type="button" disabled={busy !== null} onClick={receive}>
              {busy === 'receive' ? 'Receiving…' : 'Receive demo payment'}
            </button>
            <button type="button" disabled={busy !== null} onClick={scan}>
              {busy === 'scan' ? (scanInfo ?? 'Scanning…') : 'Scan for payments'}
            </button>
          </div>
        </>
      )}
      {error && <Note kind="error">{error}</Note>}
      {hits && (
        <Note kind={hits.length ? 'ok' : 'info'}>
          {hits.length ? `${hits.length} spendable payment${hits.length === 1 ? '' : 's'} found` : 'No payments found'}
          {scanInfo ? ` — ${scanInfo}` : ''}
        </Note>
      )}
      {hits?.map((h) => {
        const st = spendState[h.ann.txHash] ?? { dest: '', amount: '' }
        const eth = Number(formatEther(h.balance))
        return (
          <div className="hit" key={h.ann.txHash}>
            <div>
              <AddressChip address={h.address} explorer={cfg.explorer} />{' '}
              <strong>
                {formatEther(h.balance)} ETH{usd(eth, ethUsd)}
              </strong>
              <span className="hexmeta"> · block {h.ann.blockNumber.toString()} · plain EOA</span>
            </div>
            <div className="row" style={{ margin: '6px 0 0' }}>
              <input
                placeholder="destination 0x…"
                value={st.dest}
                style={{ flex: 2, minWidth: 220 }}
                onChange={(e) => setSpendState((s) => ({ ...s, [h.ann.txHash]: { ...st, dest: e.target.value } }))}
              />
              <input
                placeholder="amount ETH"
                inputMode="decimal"
                value={st.amount}
                style={{ width: 110 }}
                onChange={(e) => setSpendState((s) => ({ ...s, [h.ann.txHash]: { ...st, amount: e.target.value } }))}
              />
              <button type="button" disabled={st.pending || !st.dest.trim() || !st.amount} onClick={() => spend(h)}>
                {st.pending ? 'Spending…' : 'Spend (ECDSA tx)'}
              </button>
            </div>
            {st.error && <Note kind="error">{st.error}</Note>}
            {st.result && <Note kind="ok">{st.result}</Note>}
          </div>
        )
      })}
    </div>
  )
}

// ---------------------------------------------------------------------------
// 2. PQ route — ERC-4337 + ERC-7913 (level-2 profile, local dev chain)
// ---------------------------------------------------------------------------

interface PqHit {
  ann: OnchainAnnouncement
  ssHex: Hex
  pkArgs: ReturnType<typeof decodePublicKeyData>
  account: Address
  balance: bigint
  deployed: boolean
}

function PqSpend({ cfg, wallet, ethUsd }: { cfg: ChainConfig; wallet: Wallet; ethUsd: number | null }) {
  const [dep, setDep] = useState<DevDeployment | null | 'loading'>('loading')
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [hits, setHits] = useState<PqHit[] | null>(null)
  const [scanInfo, setScanInfo] = useState<string | null>(null)
  const [receiveAmount, setReceiveAmount] = useState('0.5')
  const [spendState, setSpendState] = useState<
    Record<
      string,
      {
        dest: string
        amount: string
        step?: string | undefined
        result?: string | undefined
        error?: string | undefined
      }
    >
  >({})

  useEffect(() => {
    setDep('loading')
    fetchDeployment(cfg.key).then(setDep)
  }, [cfg.key])

  const demoKem = useMemo(() => {
    if (dep == null || dep === 'loading' || !dep.demo) return null
    const seed = new Uint8Array(64)
    seed.set(fromHex(dep.demo.kemD), 0)
    seed.set(fromHex(dep.demo.kemZ), 32)
    return ml_kem512.keygen(seed)
  }, [dep])

  if (dep === 'loading') return <p className="fine">Loading deployment…</p>
  if (dep && dep.mode === 'zknox-hybrid')
    return <HybridSepoliaSpend cfg={cfg} wallet={wallet} ethUsd={ethUsd} dep={dep} />
  if (!dep) {
    return (
      <div>
        <h3>PQ route — ERC-4337 account, on-chain ML-DSA verify</h3>
        <Note kind="warn">
          {cfg.key === 'anvil' ? (
            <>
              No dev deployment found — start the dev chain first: <code>npm run chain</code> (it deploys the
              EntryPoint, verifier, factory, and registry, and starts the blinded-key signer service).
            </>
          ) : (
            <>
              No {cfg.label} deployment found. Deploy the contracts (<code>npm run deploy:sepolia</code>) and run the
              signer service (<code>npm run signer</code>) first; both write the deployment file this tab reads.
            </>
          )}
        </Note>
      </div>
    )
  }

  const receive = async () => {
    setError(null)
    const walletClient = wallet.clientFor(cfg)
    if (!walletClient?.account || !demoKem) {
      setError('Wallet not ready.')
      return
    }
    setBusy('receive')
    try {
      const publicClient = publicClientFor(cfg)
      const { cipherText, sharedSecret } = ml_kem512.encapsulate(demoKem.publicKey)
      const ssHex = toHex(sharedSecret)
      const derived = await deriveSpendable(dep.signerService, ssHex)
      const pkArgs = decodePublicKeyData(derived.public_key_data)
      const account = await publicClient.readContract({
        address: dep.factory,
        abi: FACTORY_ABI,
        functionName: 'getAccountAddress',
        args: pkArgs,
      })
      const value = parseEther(receiveAmount as `${number}`)
      const payTx = await walletClient.sendTransaction({
        account: walletClient.account,
        chain: cfg.chain,
        to: account,
        value,
      })
      await publicClient.waitForTransactionReceipt({ hash: payTx })
      const annTx = await walletClient.writeContract({
        account: walletClient.account,
        chain: cfg.chain,
        address: cfg.announcer,
        abi: ANNOUNCER_ABI,
        functionName: 'announce',
        args: [SCHEME_ID, account, toHex(cipherText) as Hex, derived.view_tag],
      })
      await publicClient.waitForTransactionReceipt({ hash: annTx })
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
      const found: PqHit[] = []
      for (const ann of announcements) {
        if (ann.ephemeralPubKey.length !== 768) continue // ML-KEM-512 ct only
        let ss: Uint8Array
        try {
          ss = ml_kem512.decapsulate(ann.ephemeralPubKey, demoKem.secretKey)
        } catch {
          continue
        }
        if (!bytesEqual(spendableViewTag(ss), ann.viewTag)) continue
        const ssHex = toHex(ss)
        const derived = await deriveSpendable(dep.signerService, ssHex)
        const pkArgs = decodePublicKeyData(derived.public_key_data)
        const account = await publicClient.readContract({
          address: dep.factory,
          abi: FACTORY_ABI,
          functionName: 'getAccountAddress',
          args: pkArgs,
        })
        if (account.toLowerCase() !== toHex(ann.stealthAddress)) continue
        const [balance, code] = await Promise.all([
          publicClient.getBalance({ address: account }),
          publicClient.getCode({ address: account }),
        ])
        found.push({
          ann,
          ssHex,
          pkArgs,
          account,
          balance,
          deployed: (code?.length ?? 0) > 2,
        })
      }
      setHits(found)
      setScanInfo(`${announcements.length} announcements scanned`)
    } catch (e) {
      setError(parseTxError(e))
    } finally {
      setBusy(null)
    }
  }

  const spend = async (hit: PqHit) => {
    const key = hit.ann.txHash
    const st = spendState[key] ?? { dest: '', amount: '' }
    const patch = (p: Partial<typeof st>) => setSpendState((s) => ({ ...s, [key]: { ...(s[key] ?? st), ...p } }))
    patch({ error: undefined, result: undefined })
    const walletClient = wallet.clientFor(cfg)
    if (!walletClient?.account) {
      patch({ error: 'Wallet not ready.' })
      return
    }
    try {
      const dest = getAddress(st.dest.trim())
      const value = parseEther(st.amount as `${number}`)
      const publicClient = publicClientFor(cfg)

      if (!hit.deployed) {
        patch({ step: 'Deploying account (PKContract + CREATE2)…' })
        const h = await walletClient.writeContract({
          account: walletClient.account,
          chain: cfg.chain,
          address: dep.factory,
          abi: FACTORY_ABI,
          functionName: 'createAccount',
          args: hit.pkArgs,
          gas: 12_000_000n,
        })
        await publicClient.waitForTransactionReceipt({ hash: h })
      }

      patch({ step: 'Building userOp…' })
      const op = await buildSpendUserOp(publicClient, dep.entryPoint, hit.account, dest, value)
      ensureFunded(await publicClient.getBalance({ address: hit.account }), value, requiredPrefund(op))
      const userOpHash = await publicClient.readContract({
        address: dep.entryPoint,
        abi: ENTRYPOINT_ABI,
        functionName: 'getUserOpHash',
        args: [op],
      })

      patch({ step: 'Signing with the blinded ML-DSA key…' })
      const { sig } = await signSpendable(dep.signerService, hit.ssHex, userOpHash)
      op.signature = sig

      patch({ step: 'Submitting through EntryPoint.handleOps…' })
      const opsTx = await walletClient.writeContract({
        account: walletClient.account,
        chain: cfg.chain,
        address: dep.entryPoint,
        abi: ENTRYPOINT_ABI,
        functionName: 'handleOps',
        args: [[op], walletClient.account.address],
        gas: 25_000_000n,
      })
      const rcpt = await publicClient.waitForTransactionReceipt({ hash: opsTx })
      if (rcpt.status !== 'success') throw new Error('handleOps reverted')
      patch({
        step: undefined,
        result: `Spent ${st.amount} ETH → ${dest} via EntryPoint (${rcpt.gasUsed} gas incl. on-chain ML-DSA verify). Tx ${opsTx.slice(0, 10)}…`,
      })
      await scan()
    } catch (e) {
      patch({ step: undefined, error: parseTxError(e) })
    }
  }

  return (
    <div>
      <h3>PQ route — ERC-4337 account, on-chain ML-DSA verify</h3>
      <p className="fine">
        Level-2 (ZKNOX Dilithium2) demo profile — the parameter set of the deployed verifier. The announced stealth
        address is the counterfactual CREATE2 address of a <code>Stealth7913Account4337</code> whose 40-byte signer is{' '}
        <code>verifier ‖ PKContract</code>; blinded signing runs in the local Python service. EntryPoint{' '}
        {txLink(dep.entryPoint, cfg)}, factory {txLink(dep.factory, cfg)}.
      </p>
      <div className="row">
        <label className="field narrow" style={{ margin: 0 }}>
          <span>Receive amount (ETH){usd(Number(receiveAmount), ethUsd)}</span>
          <input value={receiveAmount} inputMode="decimal" onChange={(e) => setReceiveAmount(e.target.value)} />
        </label>
        <button type="button" disabled={busy !== null} onClick={receive}>
          {busy === 'receive' ? 'Receiving…' : 'Receive demo payment'}
        </button>
        <button type="button" disabled={busy !== null} onClick={scan}>
          {busy === 'scan' ? (scanInfo ?? 'Scanning…') : 'Scan for payments'}
        </button>
      </div>
      {error && <Note kind="error">{error}</Note>}
      {hits && (
        <Note kind={hits.length ? 'ok' : 'info'}>
          {hits.length ? `${hits.length} spendable payment${hits.length === 1 ? '' : 's'} found` : 'No payments found'}
          {scanInfo ? ` — ${scanInfo}` : ''}
        </Note>
      )}
      {hits?.map((h) => {
        const st = spendState[h.ann.txHash] ?? { dest: '', amount: '' }
        const eth = Number(formatEther(h.balance))
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
              <input
                placeholder="destination 0x…"
                value={st.dest}
                style={{ flex: 2, minWidth: 220 }}
                onChange={(e) => setSpendState((s) => ({ ...s, [h.ann.txHash]: { ...st, dest: e.target.value } }))}
              />
              <input
                placeholder="amount ETH"
                inputMode="decimal"
                value={st.amount}
                style={{ width: 110 }}
                onChange={(e) => setSpendState((s) => ({ ...s, [h.ann.txHash]: { ...st, amount: e.target.value } }))}
              />
              <button type="button" disabled={!!st.step || !st.dest.trim() || !st.amount} onClick={() => spend(h)}>
                {st.step ?? 'Spend (4337 userOp)'}
              </button>
            </div>
            {st.error && <Note kind="error">{st.error}</Note>}
            {st.result && <Note kind="ok">{st.result}</Note>}
          </div>
        )
      })}
    </div>
  )
}

// ---------------------------------------------------------------------------
// 2b. PQ route on Sepolia — the DEPLOYED ZKNOX hybrid account (kohaku)
// ---------------------------------------------------------------------------

interface HybridHit {
  ann: OnchainAnnouncement
  account: Address
  balance: bigint
  deployed: boolean
}

function HybridSepoliaSpend({
  cfg,
  wallet,
  ethUsd,
  dep,
}: {
  cfg: ChainConfig
  wallet: Wallet
  ethUsd: number | null
  dep: DevDeployment
}) {
  const [demo, setDemo] = useState<{ publicKeyData: Hex; kemCt: Hex; viewTag: Hex } | null>(null)
  const [account, setAccount] = useState<Address | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [hits, setHits] = useState<HybridHit[] | null>(null)
  const [scanInfo, setScanInfo] = useState<string | null>(null)
  const [receiveAmount, setReceiveAmount] = useState('0.02')
  const [apiKey, setApiKey] = useState(() => {
    try {
      return localStorage.getItem('pq-stealth.pimlico-key') ?? ''
    } catch {
      return ''
    }
  })
  const [spendState, setSpendState] = useState<
    Record<
      string,
      {
        dest: string
        amount: string
        step?: string | undefined
        result?: string | undefined
        error?: string | undefined
      }
    >
  >({})
  const usePimlico = apiKey.trim().length > 0
  const setKey = (k: string) => {
    setApiKey(k)
    try {
      localStorage.setItem('pq-stealth.pimlico-key', k)
    } catch {
      /* ignore */
    }
  }

  // fetch the fixed demo identity from the signer service, then its account address
  useEffect(() => {
    let alive = true
    ;(async () => {
      try {
        const r = await fetch(`${dep.signerService}/hybrid/derive`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: '{}',
        })
        if (!r.ok) throw new Error(await r.text())
        const d = (await r.json()) as { public_key_data: Hex; kem_ct: Hex; view_tag: Hex }
        if (!alive) return
        setDemo({ publicKeyData: d.public_key_data, kemCt: d.kem_ct, viewTag: d.view_tag })
        const acct = await publicClientFor(cfg).readContract({
          address: dep.factory,
          abi: ZKNOX_FACTORY_ABI,
          functionName: 'getAddress',
          args: [preQuantumDemoKey().address, d.public_key_data],
        })
        if (alive) setAccount(acct)
      } catch (e) {
        if (alive) setError(`signer service unreachable — run \`npm run signer\`. (${parseTxError(e)})`)
      }
    })()
    return () => {
      alive = false
    }
  }, [dep, cfg])

  const receive = async () => {
    if (!demo || !account) return
    setError(null)
    const walletClient = wallet.clientFor(cfg)
    if (!walletClient?.account) {
      setError('Connect a browser wallet.')
      return
    }
    setBusy('receive')
    try {
      const publicClient = publicClientFor(cfg)
      const value = parseEther(receiveAmount as `${number}`)
      const payTx = await walletClient.sendTransaction({
        account: walletClient.account,
        chain: cfg.chain,
        to: account,
        value,
      })
      await publicClient.waitForTransactionReceipt({ hash: payTx })
      const annTx = await walletClient.writeContract({
        account: walletClient.account,
        chain: cfg.chain,
        address: cfg.announcer,
        abi: ANNOUNCER_ABI,
        functionName: 'announce',
        args: [SCHEME_ID, account, demo.kemCt, demo.viewTag],
      })
      await publicClient.waitForTransactionReceipt({ hash: annTx })
      await scan()
    } catch (e) {
      setError(parseTxError(e))
    } finally {
      setBusy(null)
    }
  }

  const scan = async () => {
    if (!account) return
    setError(null)
    setBusy('scan')
    try {
      const publicClient = publicClientFor(cfg)
      const { announcements } = await fetchAnnouncements(cfg, publicClient, setScanInfo)
      const found: HybridHit[] = []
      for (const ann of announcements) {
        if (toHex(ann.stealthAddress) !== account.toLowerCase()) continue
        const [balance, code] = await Promise.all([
          publicClient.getBalance({ address: account }),
          publicClient.getCode({ address: account }),
        ])
        found.push({ ann, account, balance, deployed: (code?.length ?? 0) > 2 })
      }
      setHits(found)
      setScanInfo(`${announcements.length} announcements scanned`)
    } catch (e) {
      setError(parseTxError(e))
    } finally {
      setBusy(null)
    }
  }

  const spend = async (hit: HybridHit) => {
    if (!demo) return
    const key = hit.ann.txHash
    const st = spendState[key] ?? { dest: '', amount: '' }
    const patch = (p: Partial<typeof st>) => setSpendState((s) => ({ ...s, [key]: { ...(s[key] ?? st), ...p } }))
    patch({ error: undefined, result: undefined })
    const walletClient = wallet.clientFor(cfg)
    if (!walletClient?.account) {
      patch({ error: 'Connect a browser wallet.' })
      return
    }
    try {
      const dest = getAddress(st.dest.trim())
      const value = parseEther(st.amount as `${number}`)
      const publicClient = publicClientFor(cfg)

      if (!hit.deployed) {
        patch({ step: 'Deploying ZKNOX account…' })
        const h = await walletClient.writeContract({
          account: walletClient.account,
          chain: cfg.chain,
          address: dep.factory,
          abi: ZKNOX_FACTORY_ABI,
          functionName: 'createAccount',
          args: [preQuantumDemoKey().address, demo.publicKeyData],
          gas: 10_000_000n,
        })
        await publicClient.waitForTransactionReceipt({ hash: h })
      }

      // the blinded ML-DSA half always comes from the signer service
      const signHybrid = async (userOpHash: Hex): Promise<Hex> => {
        const sr = await fetch(`${dep.signerService}/hybrid/sign`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ challenge: userOpHash }),
        })
        if (!sr.ok) throw new Error(await sr.text())
        const { sig } = (await sr.json()) as { sig: Hex }
        return packHybridSignature(userOpHash, sig)
      }

      if (usePimlico) {
        // gasless: Pimlico's paymaster sponsors the gas; the account needs
        // only the value it sends. Pimlico also bundles the op.
        ensureFunded(await publicClient.getBalance({ address: hit.account }), value, 0n)
        const nonce = await publicClient.readContract({
          address: dep.entryPoint,
          abi: HYBRID_ENTRYPOINT_ABI,
          functionName: 'getNonce',
          args: [hit.account, 0n],
        })
        const callData = encodeFunctionData({
          abi: HYBRID_ACCOUNT_ABI,
          functionName: 'execute',
          args: [dest, value, '0x'],
        })
        const res = await submitSponsoredUserOp({
          url: pimlicoUrl(cfg.chain.id, apiKey.trim()),
          chainId: cfg.chain.id,
          sender: hit.account,
          nonce,
          callData,
          dummySignature: await dummyHybridSignature(),
          sign: signHybrid,
          onStep: (m) => patch({ step: m }),
        })
        if (!res.success) throw new Error('the sponsored userOp reverted on-chain')
        patch({
          step: undefined,
          result:
            `Spent ${st.amount} ETH -> ${dest}, gas sponsored by the Pimlico paymaster ` +
            `(${res.gasUsed} gas, account paid 0 for gas). Tx ${res.txHash.slice(0, 10)}...`,
        })
        await scan()
        return
      }

      patch({ step: 'Building userOp…' })
      const op = await buildHybridUserOp(publicClient, dep.entryPoint, hit.account, dest, value)
      ensureFunded(await publicClient.getBalance({ address: hit.account }), value, requiredPrefundHybrid(op))
      const userOpHash = await publicClient.readContract({
        address: dep.entryPoint,
        abi: HYBRID_ENTRYPOINT_ABI,
        functionName: 'getUserOpHash',
        args: [op],
      })

      patch({ step: 'Signing (ECDSA + blinded ML-DSA)…' })
      op.signature = await signHybrid(userOpHash)

      patch({ step: 'Submitting through EntryPoint.handleOps…' })
      const opsTx = await walletClient.writeContract({
        account: walletClient.account,
        chain: cfg.chain,
        address: dep.entryPoint,
        abi: HYBRID_ENTRYPOINT_ABI,
        functionName: 'handleOps',
        args: [[op], walletClient.account.address],
        gas: 11_000_000n,
      })
      const rcpt = await publicClient.waitForTransactionReceipt({ hash: opsTx })
      if (rcpt.status !== 'success') throw new Error('handleOps reverted')
      patch({
        step: undefined,
        result: `Spent ${st.amount} ETH -> ${dest} via the deployed ZKNOX account (${rcpt.gasUsed} gas incl. on-chain ML-DSA verify). Tx ${opsTx.slice(0, 10)}...`,
      })
      await scan()
    } catch (e) {
      patch({ step: undefined, error: parseTxError(e) })
    }
  }

  return (
    <div>
      <h3>PQ route — deployed ZKNOX hybrid account (on-chain ML-DSA verify)</h3>
      <p className="fine">
        Reuses the ZKNOX pq-account already deployed on {cfg.label} (
        <a href="https://github.com/ethereum/kohaku/tree/master/examples/pq-account" target="_blank" rel="noreferrer">
          ethereum/kohaku
        </a>
        ): the account is a hybrid ECDSA + ML-DSA (level-2) signer, so the userOp carries both a classical signature and
        the blinded ML-DSA signature verified on-chain. Verifier {txLink(dep.verifier, cfg)}, factory{' '}
        {txLink(dep.factory, cfg)}. Fixed demo identity.
      </p>
      {account && (
        <p className="fine">
          Demo stealth account: <AddressChip address={account} explorer={cfg.explorer} />
        </p>
      )}
      <label className="field">
        <span>
          Pimlico API key (optional) —{' '}
          {usePimlico
            ? 'gasless: the paymaster sponsors gas and bundles the op'
            : 'without it, the op self-bundles and the account pays its own gas'}
        </span>
        <input
          type="password"
          placeholder="pim_… (stored in this browser only)"
          value={apiKey}
          onChange={(e) => setKey(e.target.value)}
        />
      </label>
      <div className="row">
        <label className="field narrow" style={{ margin: 0 }}>
          <span>Receive amount (ETH){usd(Number(receiveAmount), ethUsd)}</span>
          <input value={receiveAmount} inputMode="decimal" onChange={(e) => setReceiveAmount(e.target.value)} />
        </label>
        <button type="button" disabled={busy !== null || !account} onClick={receive}>
          {busy === 'receive' ? 'Receiving…' : 'Receive demo payment'}
        </button>
        <button type="button" disabled={busy !== null || !account} onClick={scan}>
          {busy === 'scan' ? (scanInfo ?? 'Scanning…') : 'Scan for payments'}
        </button>
      </div>
      {error && <Note kind="error">{error}</Note>}
      {hits && (
        <Note kind={hits.length ? 'ok' : 'info'}>
          {hits.length ? `${hits.length} spendable payment${hits.length === 1 ? '' : 's'} found` : 'No payments found'}
          {scanInfo ? ` — ${scanInfo}` : ''}
        </Note>
      )}
      {hits?.map((h) => {
        const st = spendState[h.ann.txHash] ?? { dest: '', amount: '' }
        const eth = Number(formatEther(h.balance))
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
              <input
                placeholder="destination 0x…"
                value={st.dest}
                style={{ flex: 2, minWidth: 220 }}
                onChange={(e) => setSpendState((s) => ({ ...s, [h.ann.txHash]: { ...st, dest: e.target.value } }))}
              />
              <input
                placeholder="amount ETH"
                inputMode="decimal"
                value={st.amount}
                style={{ width: 110 }}
                onChange={(e) => setSpendState((s) => ({ ...s, [h.ann.txHash]: { ...st, amount: e.target.value } }))}
              />
              <button type="button" disabled={!!st.step || !st.dest.trim() || !st.amount} onClick={() => spend(h)}>
                {st.step ?? (usePimlico ? 'Spend (gasless, Pimlico)' : 'Spend (4337 userOp)')}
              </button>
            </div>
            {st.error && <Note kind="error">{st.error}</Note>}
            {st.result && <Note kind="ok">{st.result}</Note>}
          </div>
        )
      })}
    </div>
  )
}
