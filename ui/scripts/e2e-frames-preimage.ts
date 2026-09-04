#!/usr/bin/env node
/**
 * Live end-to-end of the key-exchange route with a client-side proof of the
 * spending secret (D-024 + D-025) on the public frames testnet — the exact
 * code path the demo UI runs, minus the browser:
 *
 *   1. receive: ML-KEM-768 encapsulate to the demo recipient, derive
 *      opener/commitment (preimage domains), pay the CREATE2 account AND
 *      announce in ONE 0x06 tx
 *   2. scan: decapsulate, view tag, re-derive, match the address
 *   3. spend: ONE sponsored 0x06 tx = [VERIFY(sponsor), DEFAULT(createAccount)?,
 *      DEFAULT(account.executeFrame)] whose ARBITRARY signature is an UltraHonk
 *      proof (noir_js + bb.js, in-process, ~1-2 s) that the sender knows the
 *      secret behind the commitment, bound to the tx's sig_hash. No signer
 *      service, no signature scheme, nothing revealed.
 *
 * Needs: frames-zk-deployment.json (scripts/deploy-frames-zk.mjs), Node >= 22,
 * a funded FRAMES_SPONSOR_KEY (default: the shared dev key).
 */

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js'
import { createPublicClient, encodeFunctionData, formatEther, getAddress, type Hex, hexToBytes, http, parseEther } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'

import {
  accountAddress, computeViewTag, deriveCommitment, deriveOpener, encodeCommitMetaAddress, ML_KEM_768_CT_BYTES,
  PREIMAGE_DOMAINS, spendKeyFromSecret, type Deployment,
} from '../../js-client/src/commit-scheme.ts'
import { buildAnnounceTransfer, buildSponsoredPqTx, defaultFrame, rpc, sendRawFrameTx, SPONSORED_PQ_SIG_INDEX } from '../../js-client/src/frame-tx/actions.ts'
import { ANNOUNCER_ABI } from '../../js-client/src/sepolia.ts'
import { framesTestnet, SCHEME_ID } from '../src/lib/chain.ts'
import { fromHex, toHex } from '../src/lib/hex.ts'
import { PreimageProver, secretFromSeed } from '../src/lib/preimage-prover.ts'

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url))
const dep = JSON.parse(readFileSync(here('../public/frames-zk-deployment.json'), 'utf8'))
if (dep.scheme !== 'preimage') throw new Error(`frames-zk-deployment.json is for scheme ${dep.scheme}, run deploy-frames-zk.mjs (ZK_CIRCUIT=preimage)`)
const circuit = JSON.parse(readFileSync(here('../public/circuits/preimage_ownership.json'), 'utf8'))
const RPC = framesTestnet.rpcUrls.default.http[0]
const CHAIN = BigInt(framesTestnet.id)
const SPONSOR_KEY = (process.env.FRAMES_SPONSOR_KEY ?? '0xbcdf20249abf0ed6d944c0288fad489e33f66b3960d9e6229c1cd214ed3bbe31') as Hex
const sponsor = privateKeyToAccount(SPONSOR_KEY)
const FEES = { maxFeePerGas: 1_000n, maxPriorityFeePerGas: 100n }
const RECEIVE = parseEther('0.0005')
const SPEND = parseEther('0.0001')
const DEST = '0x000000000000000000000000000000000000dEaD'
const D: Deployment = { factory: dep.factory, creationCode: dep.creationCode, verifier: dep.verifier, frameCtx: dep.frameCtx }

const FACTORY_ABI = [
  { type: 'function', name: 'createAccount', stateMutability: 'nonpayable', inputs: [{ name: 'commitment', type: 'bytes32' }], outputs: [{ type: 'address' }] },
] as const
const ACCOUNT_ABI = [
  { type: 'function', name: 'executeFrame', stateMutability: 'nonpayable', inputs: [
    { name: 'sigIndex', type: 'uint256' }, { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' }, { name: 'data', type: 'bytes' },
  ], outputs: [] },
] as const

const client = createPublicClient({ chain: framesTestnet, transport: http(RPC) })
const nonceOf = async (a: string) => BigInt(await rpc<Hex>(RPC, 'eth_getTransactionCount', [a, 'pending']))

async function broadcast(raw: Hex) {
  let hash: Hex | null = null
  for (let attempt = 1; !hash; attempt++) {
    try {
      hash = await sendRawFrameTx(RPC, raw)
    } catch (e) {
      const msg = e instanceof Error ? `${e.message}${e.cause ? ` (${(e.cause as Error).message})` : ''}` : String(e)
      if (attempt >= 4 || !/fetch failed|ECONNRESET|socket/i.test(msg)) throw e
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

// --- recipient: secret from the demo seed, ML-KEM-768 viewing key -----------------------
const sk = secretFromSeed(fromHex(dep.demo.spendSeed))
const spendKey = spendKeyFromSecret(sk)
const kemSeed = new Uint8Array(64)
kemSeed.set(fromHex(dep.demo.kemD), 0)
kemSeed.set(fromHex(dep.demo.kemZ), 32)
const kem = ml_kem768.keygen(kemSeed)
const meta = encodeCommitMetaAddress(spendKey, kem.publicKey)
console.log(`sponsor ${sponsor.address}: ${formatEther(await client.getBalance({ address: sponsor.address }))} ETH`)
console.log(`recipient meta-address: ${meta.length} B (0x02 || spend_key ${spendKey.slice(0, 18)}… || ML-KEM-768 ek)`)

// --- 1. receive ----------------------------------------------------------------------------
const { cipherText, sharedSecret } = ml_kem768.encapsulate(kem.publicKey)
const opener = deriveOpener(sharedSecret, PREIMAGE_DOMAINS)
const commitment = deriveCommitment(spendKey, opener, PREIMAGE_DOMAINS)
const account = accountAddress(commitment, D)
console.log(`commitment ${commitment}\nstealth account (counterfactual): ${account}`)
{
  const announceData = encodeFunctionData({
    abi: ANNOUNCER_ABI, functionName: 'announce', args: [SCHEME_ID, account, toHex(cipherText) as Hex, toHex(computeViewTag(sharedSecret)) as Hex],
  })
  const { raw } = await buildAnnounceTransfer({
    chainId: CHAIN, nonce: await nonceOf(sponsor.address), sender: sponsor.address,
    stealthAddress: account, value: RECEIVE, announcer: dep.announcer, announceData, privateKey: SPONSOR_KEY, ...FEES,
  })
  const r = await broadcast(raw)
  console.log(`RECEIVE frame tx ${r.hash} status ${r.status} block ${r.block} gas ${r.gasUsed}`)
  if (r.status !== '0x1') process.exit(1)
}

// --- 2. scan -------------------------------------------------------------------------------
const logs = await rpc<{ topics: Hex[]; data: Hex; transactionHash: Hex }[]>(RPC, 'eth_getLogs', [{ address: dep.announcer, fromBlock: '0x0', toBlock: 'latest' }])
let matched = false
for (const log of logs) {
  const addr = getAddress(`0x${log.topics[2]!.slice(26)}`)
  if (addr !== account) continue
  const ct = fromHex(`0x${log.data.slice(2 + 64 * 2 + 64, 2 + 64 * 2 + 64 + ML_KEM_768_CT_BYTES * 2)}`)
  const ss = ml_kem768.decapsulate(ct, kem.secretKey)
  const acct2 = accountAddress(deriveCommitment(spendKey, deriveOpener(ss, PREIMAGE_DOMAINS), PREIMAGE_DOMAINS), D)
  matched = acct2 === account
  console.log(`SCAN: announcement in ${log.transactionHash}, re-derived account ${acct2} — ${matched ? 'MATCH' : 'MISMATCH'}`)
  break
}
if (!matched) process.exit(1)

// --- 3. sponsored spend with a client-side proof ---------------------------------------------
const deployed = ((await client.getCode({ address: account })) ?? '0x').length > 2
const bal = await client.getBalance({ address: account })
console.log(`account balance ${formatEther(bal)} ETH, ${deployed ? 'deployed' : 'counterfactual'}`)
const prover = new PreimageProver(circuit, 8)
{
  const frames = []
  if (!deployed) {
    frames.push(defaultFrame({
      target: dep.factory, executionGas: 400_000n, stateGas: 6_000_000n,
      data: encodeFunctionData({ abi: FACTORY_ABI, functionName: 'createAccount', args: [commitment] }),
    }))
  }
  frames.push(defaultFrame({
    target: account, executionGas: BigInt(process.env.ZK_SPEND_EXEC_GAS ?? '8000000'), stateGas: 250_000n,
    data: encodeFunctionData({ abi: ACCOUNT_ABI, functionName: 'executeFrame', args: [SPONSORED_PQ_SIG_INDEX, DEST, SPEND, '0x'] }),
  }))
  let signedDigest: Hex | null = null
  const { raw, sigHash, tx } = await buildSponsoredPqTx({
    chainId: CHAIN, nonce: await nonceOf(sponsor.address), sponsor: sponsor.address, sponsorPrivateKey: SPONSOR_KEY,
    frames,
    pqSign: async (h) => {
      signedDigest = h
      const p = await prover.prove(hexToBytes(h), hexToBytes(commitment), sk, hexToBytes(opener))
      console.log(`proved knowledge of the secret for sig_hash ${h}: witness ${p.timings.witness} ms, UltraHonk ${p.timings.prove} ms, ${(p.proof.length - 2) / 2} B`)
      return p.proof
    },
    ...FEES,
  })
  if (signedDigest !== sigHash) throw new Error('pqSign digest mismatch')
  console.log(`SPEND frame tx: ${tx.frames.length} frames, ${tx.signatures.length} signatures, ${(raw.length - 2) / 2} B raw`)
  const r = await broadcast(raw)
  console.log(`SPEND frame tx ${r.hash} status ${r.status} block ${r.block} gas ${r.gasUsed} frames ${JSON.stringify(r.frames)}`)
  const after = await client.getBalance({ address: account })
  console.log(`account ${formatEther(bal)} -> ${formatEther(after)} ETH, code ${((await client.getCode({ address: account })) ?? '0x').length > 2 ? 'deployed' : 'none'}`)
  await prover.destroy()
  if (r.status !== '0x1' || bal - after !== SPEND) process.exit(1)
  console.log('OK: client-side proof of the spending secret, sponsor-paid, key-hiding spend over a single frame transaction')
}
