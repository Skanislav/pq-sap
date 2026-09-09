#!/usr/bin/env node
/**
 * Live end-to-end of the ZK SPHINCS- spend route on the public frames testnet:
 *
 *   1. receive: ML-KEM-768 encapsulate to the demo recipient, derive the D-018
 *      commitment (keccak(domain || C13 pk || opener(ss))), predict the CREATE2
 *      Stealth8141ZkAccount address, pay it AND announce in ONE 0x06 tx
 *   2. scan: find the announcement, decapsulate, re-derive, match the address
 *   3. spend: ONE sponsored 0x06 tx = [VERIFY(sponsor), DEFAULT(factory.createAccount)
 *      if needed, DEFAULT(account.executeFrame(1, dest, value))], authorized by an
 *      UltraHonk proof (ARBITRARY signature #1) of a C13 signature over the tx's
 *      sig_hash under a key that opens the commitment. The key never appears on
 *      chain: the spend is unlinkable to the recipient and to their other spends.
 *
 * Proving pipeline per spend: signer-c13 (Rust CLI, upstream lfglabs-dev/SPHINCS-
 * @2a40d0a) -> generate_prover.py --inputs -> nargo execute -> bb prove -t evm.
 *
 * Env: SIGNER_C13 (path to the signer-c13 binary; required), NARGO, BB (default:
 * the aztec-bundled ones), FRAMES_SPONSOR_KEY (default: shared dev key).
 * Needs: frames-zk-c13-deployment.json (scripts/deploy-frames-zk.mjs), Node 26,
 * python with pycryptodome (python/.venv).
 */

import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { createPublicClient, encodeFunctionData, formatEther, getAddress, type Hex, http, parseEther } from 'viem'
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
import { sphincsC13Commitment, sphincsC13Key, sphincsC13Opener } from '../../js-client/src/sphincs.ts'
import { framesTestnet, SCHEME_ID } from '../src/lib/chain.ts'
import { fromHex, toHex } from '../src/lib/hex.ts'

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url))
const dep = JSON.parse(readFileSync(here('../public/frames-zk-c13-deployment.json'), 'utf8'))
const RPC = framesTestnet.rpcUrls.default.http[0]
const CHAIN = BigInt(framesTestnet.id)
const SPONSOR_KEY = (process.env.FRAMES_SPONSOR_KEY ??
  '0xbcdf20249abf0ed6d944c0288fad489e33f66b3960d9e6229c1cd214ed3bbe31') as Hex
const sponsor = privateKeyToAccount(SPONSOR_KEY)
const FEES = { maxFeePerGas: 1_000n, maxPriorityFeePerGas: 100n }
const RECEIVE = parseEther('0.0005')
const SPEND = parseEther('0.0001')
const DEST = '0x000000000000000000000000000000000000dEaD'

const SIGNER = process.env.SIGNER_C13
if (!SIGNER) throw new Error('SIGNER_C13=/path/to/signer-c13 is required')
const NARGO = process.env.NARGO ?? `${process.env.HOME}/.aztec/current/bin/nargo`
const BB = process.env.BB ?? `${process.env.HOME}/.aztec/current/node_modules/.bin/bb`
const PYTHON = process.env.PQ_PYTHON ?? here('../../python/.venv/bin/python')
const CIRCUIT = here('../../noir/sphincs-c13-verify')

const FACTORY_ABI = [
  { type: 'function', name: 'getAccountAddress', stateMutability: 'view', inputs: [{ name: 'commitment', type: 'bytes32' }], outputs: [{ type: 'address' }] },
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

// --- recipient key material (the fixture's seeds) ----------------------------------
const spendSeed = fromHex(dep.demo.spendSeed)
const seedMaterial = sha256(new Uint8Array([...new TextEncoder().encode('pq-stealth/sphincs-c13/keygen/v0'), ...spendSeed]))
const keygen = JSON.parse(execFileSync(SIGNER, ['keygen', toHex(seedMaterial).slice(2)], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })) as { seed: Hex; sk_seed: Hex; root: Hex }
const pk = sphincsC13Key(keygen.seed, keygen.root)
const kemSeed = new Uint8Array(64)
kemSeed.set(fromHex(dep.demo.kemD), 0)
kemSeed.set(fromHex(dep.demo.kemZ), 32)
const kem = ml_kem768.keygen(kemSeed)
console.log(`sponsor ${sponsor.address}: ${formatEther(await client.getBalance({ address: sponsor.address }))} ETH`)
console.log(`recipient C13 key ${pk} (never goes on chain)`)

const accountOf = (commitment: Hex) =>
  client.readContract({ address: dep.factory, abi: FACTORY_ABI, functionName: 'getAccountAddress', args: [commitment] })

// --- 1. receive: pay + announce in one frame tx --------------------------------------
const { cipherText, sharedSecret } = ml_kem768.encapsulate(kem.publicKey)
const opener = sphincsC13Opener(sharedSecret)
const commitment = sphincsC13Commitment(pk, opener)
const account = await accountOf(commitment)
const viewTag = toHex(sha256(sharedSecret).slice(0, 1)) as Hex
console.log(`commitment ${commitment}\nstealth account (counterfactual): ${account}`)
{
  const announceData = encodeFunctionData({
    abi: ANNOUNCER_ABI, functionName: 'announce', args: [SCHEME_ID, account, toHex(cipherText) as Hex, viewTag],
  })
  const { raw } = await buildAnnounceTransfer({
    chainId: CHAIN, nonce: await nonceOf(sponsor.address), sender: sponsor.address,
    stealthAddress: account, value: RECEIVE, announcer: dep.announcer, announceData, privateKey: SPONSOR_KEY, ...FEES,
  })
  const r = await broadcast(raw)
  console.log(`RECEIVE frame tx ${r.hash} status ${r.status} block ${r.block} gas ${r.gasUsed}`)
  if (r.status !== '0x1') process.exit(1)
}

// --- 2. scan -------------------------------------------------------------------------
const logs = await rpc<{ topics: Hex[]; data: Hex; transactionHash: Hex }[]>(RPC, 'eth_getLogs', [
  { address: dep.announcer, fromBlock: '0x0', toBlock: 'latest' },
])
let matched = false
for (const log of logs) {
  const addr = getAddress(`0x${log.topics[2]!.slice(26)}`)
  if (addr !== account) continue
  const ct = fromHex(`0x${log.data.slice(2 + 64 * 2 + 64, 2 + 64 * 2 + 64 + 1088 * 2)}`)
  const ss = ml_kem768.decapsulate(ct, kem.secretKey)
  const acct2 = await accountOf(sphincsC13Commitment(pk, sphincsC13Opener(ss)))
  matched = acct2 === account
  console.log(`SCAN: announcement in ${log.transactionHash}, re-derived account ${acct2} — ${matched ? 'MATCH' : 'MISMATCH'}`)
  break
}
if (!matched) process.exit(1)

// --- 3. sponsored ZK spend, deploy included -------------------------------------------
const deployed = ((await client.getCode({ address: account })) ?? '0x').length > 2
const bal = await client.getBalance({ address: account })
console.log(`account balance ${formatEther(bal)} ETH, ${deployed ? 'deployed' : 'counterfactual'}`)

function proveSpend(sigHash: Hex): Hex {
  const t0 = Date.now()
  const sig = execFileSync(SIGNER, ['sign-with', keygen.seed, keygen.sk_seed, keygen.root, sigHash.slice(2)], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim()
  const tSign = Date.now()
  const dir = mkdtempSync(join(tmpdir(), 'c13zk-'))
  writeFileSync(join(dir, 'inputs.json'), JSON.stringify({
    pk_seed: keygen.seed, pk_root: keygen.root, opener, message: sigHash, sig: sig.startsWith('0x') ? sig : `0x${sig}`, commitment,
  }))
  // nargo resolves --prover-name inside the package dir, so the inputs land there
  execFileSync(PYTHON, [join(CIRCUIT, 'generate_prover.py'), '--inputs', join(dir, 'inputs.json'), '-o', join(CIRCUIT, 'Prover_spend.toml')], { stdio: 'inherit' })
  execFileSync(NARGO, ['execute', '-p', 'Prover_spend', 'spend'], { cwd: CIRCUIT, stdio: 'inherit' })
  const tWit = Date.now()
  execFileSync(BB, ['prove', '-b', join(CIRCUIT, 'target/sphincs_c13_verify.json'), '-w', join(CIRCUIT, 'target/spend.gz'), '-t', 'evm', '-k', join(CIRCUIT, 'out/vk'), '-o', dir], { stdio: 'inherit' })
  const proof = readFileSync(join(dir, 'proof'))
  console.log(`C13 sign ${((tSign - t0) / 1000).toFixed(1)}s, witness ${((tWit - tSign) / 1000).toFixed(1)}s, UltraHonk prove ${((Date.now() - tWit) / 1000).toFixed(1)}s -> ${proof.length} B proof`)
  return `0x${proof.toString('hex')}`
}

{
  const frames = []
  if (!deployed) {
    frames.push(defaultFrame({
      target: dep.factory, executionGas: 400_000n, stateGas: BigInt(process.env.ZK_ACCOUNT_DEPLOY_STATE_GAS ?? '6000000'),
      data: encodeFunctionData({ abi: FACTORY_ABI, functionName: 'createAccount', args: [commitment] }),
    }))
  }
  // forge measures executeFrame at ~3.53M, but on this chain the 11 KB proof copy
  // (SIGDATACOPY + ABI return), two cold contracts and the EIP-8037 schedule push it
  // past 4M — a 4M frame died at exactly 63/64 (out of gas inside the verifier).
  frames.push(defaultFrame({
    target: account, executionGas: BigInt(process.env.ZK_SPEND_EXEC_GAS ?? '9000000'), stateGas: 250_000n,
    data: encodeFunctionData({ abi: ACCOUNT_ABI, functionName: 'executeFrame', args: [SPONSORED_PQ_SIG_INDEX, DEST, SPEND, '0x'] }),
  }))
  let signedDigest: Hex | null = null
  const { raw, sigHash, tx } = await buildSponsoredPqTx({
    chainId: CHAIN, nonce: await nonceOf(sponsor.address), sponsor: sponsor.address, sponsorPrivateKey: SPONSOR_KEY,
    frames,
    pqSign: async (h) => { signedDigest = h; return proveSpend(h) },
    ...FEES,
  })
  if (signedDigest !== sigHash) throw new Error('pqSign digest mismatch')
  console.log(`SPEND frame tx: ${tx.frames.length} frames, ${tx.signatures.length} signatures, ${(raw.length - 2) / 2} B raw`)
  const r = await broadcast(raw)
  console.log(`SPEND frame tx ${r.hash} status ${r.status} block ${r.block} gas ${r.gasUsed} frames ${JSON.stringify(r.frames)}`)
  const after = await client.getBalance({ address: account })
  console.log(`account ${formatEther(bal)} -> ${formatEther(after)} ETH, code ${((await client.getCode({ address: account })) ?? '0x').length > 2 ? 'deployed' : 'none'}`)
  if (r.status !== '0x1' || bal - after !== SPEND) process.exit(1)
  console.log('OK: ZK-authorized (SPHINCS- C13 in-circuit), sponsor-paid, key-hiding spend over a single frame transaction')
}
