#!/usr/bin/env node
/**
 * Live end-to-end of the frame-transaction PQ spend route on the public
 * frames testnet — exactly what the Spend tab does on "Frames testnet":
 *
 *   1. self-send: ML-KEM-512 encapsulate to the demo recipient, derive the
 *      blinded ML-DSA stealth key (signer service), predict the CREATE2
 *      Stealth8141Account address, pay it AND announce in ONE 0x06 tx
 *   2. scan: find the announcement, decapsulate, re-derive, match the address
 *   3. spend: (first time) deploy the account with a type-2 tx, then ONE
 *      sponsored 0x06 tx = [VERIFY(sponsor), DEFAULT(account.executeFrame(1,
 *      dest, value))], authorized by a blinded ML-DSA signature over the tx's
 *      sig_hash (ARBITRARY signature #1), gas paid by the sponsor
 *
 * Needs: frames-deployment.json (scripts/deploy-frames.mjs), the signer
 * service (`npm run signer`), Node 26, a funded FRAMES_SPONSOR_KEY (default:
 * the shared dev key — fees here are ~100 wei so its dust suffices).
 */

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { ml_kem512 } from '@noble/post-quantum/ml-kem.js'
import { createPublicClient, createWalletClient, encodeFunctionData, formatEther, getAddress, type Hex, http, parseEther } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'

import { ANNOUNCER_ABI } from '../../js-client/src/sepolia.ts'
import {
  buildAnnounceTransfer,
  buildSponsoredPqTx,
  defaultFrame,
  rpc,
  sendRawFrameTx,
  SPONSORED_PQ_SIG_INDEX,
} from '../../js-client/src/frame-tx/actions.ts'
import { framesTestnet, SCHEME_ID } from '../src/lib/chain.ts'
import { fromHex, toHex } from '../src/lib/hex.ts'
import {
  ACCOUNT_8141_ABI,
  decodePublicKeyData,
  deriveSpendable,
  FACTORY_ABI,
  signSpendable,
  spendableViewTag,
} from '../src/lib/spend4337.ts'

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url))
const dep = JSON.parse(readFileSync(here('../public/frames-deployment.json'), 'utf8'))
const RPC = framesTestnet.rpcUrls.default.http[0]
const CHAIN = BigInt(framesTestnet.id)
const SPONSOR_KEY = (process.env.FRAMES_SPONSOR_KEY ??
  '0xbcdf20249abf0ed6d944c0288fad489e33f66b3960d9e6229c1cd214ed3bbe31') as Hex
const sponsor = privateKeyToAccount(SPONSOR_KEY)
const FEES = { maxFeePerGas: 1_000n, maxPriorityFeePerGas: 100n }
const RECEIVE = parseEther('0.0005')
const SPEND = parseEther('0.0001')
const DEST = '0x000000000000000000000000000000000000dEaD'

const client = createPublicClient({ chain: framesTestnet, transport: http(RPC) })
const nonceOf = async (a: string) => BigInt(await rpc<Hex>(RPC, 'eth_getTransactionCount', [a, 'pending']))

async function broadcast(raw: Hex) {
  let hash: Hex | null = null
  for (let attempt = 1; !hash; attempt++) {
    try {
      hash = await sendRawFrameTx(RPC, raw)
    } catch (e) {
      // the public RPC occasionally drops the connection on large (25 KB) bodies
      const msg = e instanceof Error ? `${e.message}${e.cause ? ` (${(e.cause as Error).message})` : ''}` : String(e)
      if (attempt >= 4 || !/fetch failed|ECONNRESET|socket/i.test(msg)) throw e
      console.log(`  send attempt ${attempt} failed: ${msg} — retrying`)
      await new Promise((x) => setTimeout(x, 3000))
    }
  }
  let r: { status: Hex; gasUsed: Hex; blockNumber: Hex; frameReceipts?: { status: Hex; gasUsed: Hex }[] } | null = null
  for (let i = 0; i < 60 && !r; i++) {
    r = await rpc(RPC, 'eth_getTransactionReceipt', [hash])
    if (!r) await new Promise((x) => setTimeout(x, 1500))
  }
  if (!r) throw new Error(`no receipt for ${hash}`)
  return {
    hash, status: r.status, gasUsed: BigInt(r.gasUsed), block: BigInt(r.blockNumber),
    frames: r.frameReceipts?.map((f) => `${f.status === '0x1' ? 'ok' : 'FAIL'}:${BigInt(f.gasUsed)}`),
  }
}

console.log(`sponsor ${sponsor.address}: ${formatEther(await client.getBalance({ address: sponsor.address }))} ETH`)

// demo recipient (fixed seeds shared with the signer service)
const seed = new Uint8Array(64)
seed.set(fromHex(dep.demo.kemD), 0)
seed.set(fromHex(dep.demo.kemZ), 32)
const kem = ml_kem512.keygen(seed)

// --- 1. self-send: pay + announce in one frame tx ---------------------------
const { cipherText, sharedSecret } = ml_kem512.encapsulate(kem.publicKey)
const ssHex = toHex(sharedSecret) as Hex
const derived = await deriveSpendable(dep.signerService, ssHex)
const pkArgs = decodePublicKeyData(derived.public_key_data)
const account = await client.readContract({ address: dep.factory, abi: FACTORY_ABI, functionName: 'getAccountAddress', args: pkArgs })
console.log('stealth account (counterfactual):', account)
{
  const announceData = encodeFunctionData({
    abi: ANNOUNCER_ABI, functionName: 'announce',
    args: [SCHEME_ID, account, toHex(cipherText) as Hex, derived.view_tag],
  })
  const { raw } = await buildAnnounceTransfer({
    chainId: CHAIN, nonce: await nonceOf(sponsor.address), sender: sponsor.address,
    stealthAddress: account, value: RECEIVE, announcer: dep.announcer, announceData,
    privateKey: SPONSOR_KEY, ...FEES,
  })
  const r = await broadcast(raw)
  console.log(`RECEIVE frame tx ${r.hash} status ${r.status} block ${r.block} gas ${r.gasUsed}`)
  if (r.status !== '0x1') process.exit(1)
}

// --- 2. scan ------------------------------------------------------------------
const logs = await rpc<{ topics: Hex[]; data: Hex; transactionHash: Hex }[]>(RPC, 'eth_getLogs', [
  { address: dep.announcer, fromBlock: '0x0', toBlock: 'latest' },
])
let matched = false
for (const log of logs) {
  const addr = getAddress(`0x${log.topics[2]!.slice(26)}`)
  if (addr !== account) continue
  // decode (bytes ephemeralPubKey, bytes metadata) and re-derive from our side
  const ct = fromHex(`0x${log.data.slice(2 + 64 * 2 + 64, 2 + 64 * 2 + 64 + 768 * 2)}`)
  const ss = ml_kem512.decapsulate(ct, kem.secretKey)
  const tag = spendableViewTag(ss)
  const again = await deriveSpendable(dep.signerService, toHex(ss) as Hex)
  const pk2 = decodePublicKeyData(again.public_key_data)
  const acct2 = await client.readContract({ address: dep.factory, abi: FACTORY_ABI, functionName: 'getAccountAddress', args: pk2 })
  matched = acct2 === account && toHex(tag) === again.view_tag
  console.log(`SCAN: announcement in ${log.transactionHash}, re-derived account ${acct2} — ${matched ? 'MATCH' : 'MISMATCH'}`)
  break
}
if (!matched) process.exit(1)

// --- 3. sponsored PQ spend --------------------------------------------------
// The builder caps a frame tx's total EXECUTION gas at 2^24 = 16,777,216
// (TX_MAX_GAS_LIMIT_AMSTERDAM, EIP-7825) and the ingress does not pre-check it:
// an over-cap tx is accepted and then silently dropped. Deploying the account
// (PKContract + CREATE2 account) needs > 16M, so it goes in an ordinary
// type-2 tx first (those are not capped here — the 22.6M-gas verifier deploy
// went through); the spend itself is the frame tx, at 16.6M execution gas.
const TX_EXEC_GAS_CAP = 16_777_216n
const bal = await client.getBalance({ address: account })
let deployed = ((await client.getCode({ address: account })) ?? '0x').length > 2
console.log(`account balance ${formatEther(bal)} ETH, ${deployed ? 'deployed' : 'counterfactual'}`)
if (!deployed) {
  const wallet = createWalletClient({ chain: framesTestnet, transport: http(RPC), account: sponsor })
  const h = await wallet.writeContract({
    address: dep.factory, abi: FACTORY_ABI, functionName: 'createAccount', args: pkArgs, gas: 50_000_000n, ...FEES,
  })
  const rc = await client.waitForTransactionReceipt({ hash: h })
  console.log(`DEPLOY (type-2) ${h} status ${rc.status} block ${rc.blockNumber} gas ${rc.gasUsed}`)
  if (rc.status !== 'success') process.exit(1)
  deployed = true
}
{
  const frames = [
    defaultFrame({
      target: account, executionGas: TX_EXEC_GAS_CAP - 177_216n, stateGas: 250_000n, // 16.6M: cap minus the sponsor VERIFY frame
      data: encodeFunctionData({ abi: ACCOUNT_8141_ABI, functionName: 'executeFrame', args: [SPONSORED_PQ_SIG_INDEX, DEST, SPEND, '0x'] }),
    }),
  ]
  let signedDigest: Hex | null = null
  const { raw, sigHash, tx } = await buildSponsoredPqTx({
    chainId: CHAIN, nonce: await nonceOf(sponsor.address), sponsor: sponsor.address, sponsorPrivateKey: SPONSOR_KEY,
    frames,
    pqSign: async (h) => {
      signedDigest = h
      const t0 = Date.now()
      const { sig } = await signSpendable(dep.signerService, ssHex, h)
      console.log(`ML-DSA signed sig_hash ${h} in ${((Date.now() - t0) / 1000).toFixed(1)}s (${(sig.length - 2) / 2} B)`)
      return sig
    },
    ...FEES,
  })
  if (signedDigest !== sigHash) throw new Error('pqSign digest mismatch')
  console.log(`SPEND frame tx: ${tx.frames.length} frames, ${tx.signatures.length} signatures, ${(raw.length - 2) / 2} B raw`)
  const r = await broadcast(raw)
  console.log(`SPEND frame tx ${r.hash} status ${r.status} block ${r.block} gas ${r.gasUsed} frames ${JSON.stringify(r.frames)}`)
  const after = await client.getBalance({ address: account })
  const dest = await client.getBalance({ address: DEST })
  console.log(`account ${formatEther(bal)} -> ${formatEther(after)} ETH (dest holds ${formatEther(dest)}), code ${((await client.getCode({ address: account })) ?? '0x').length > 2 ? 'deployed' : 'none'}`)
  if (r.status !== '0x1' || bal - after !== SPEND) process.exit(1)
  console.log('OK: PQ-authorized, sponsor-paid spend over a single frame transaction')
}
