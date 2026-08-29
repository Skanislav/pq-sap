/**
 * LIVE gasless spend on real Sepolia via the real Pimlico paymaster+bundler.
 *
 * This BROADCASTS transactions and spends testnet ETH. It is gated behind
 * LIVE=1 so it can sit next to the offline fork test without ever running by
 * accident. It reuses the exact builders the UI's Sepolia path uses
 * (spendHybrid.ts + pimlico.ts) so a green run here validates the real UI.
 *
 * Reads from ../../.env (worktree root):
 *   PIMLICO_API_KEY      pim_…            (paymaster + bundler)
 *   SEPOLIA_PRIVATE_KEY  0x… 32-byte      (funds announce/fund/createAccount)
 *   SEPOLIA_RPC_URL      https://…        (a normal Sepolia RPC for reads/txs)
 *
 * Two stages:
 *   1. on-chain, costs ETH, idempotent — announce, fund the stealth account
 *      with the (tiny) spend value, deploy it via the factory if needed.
 *   2. free + retryable — sponsor via Pimlico, sign the final hash (ECDSA +
 *      blinded ML-DSA), submit through the bundler, wait for the receipt.
 * Re-running after a stage-2 fix re-does stage 1 as a near no-op.
 */

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import {
  type Address,
  createPublicClient,
  createWalletClient,
  encodeFunctionData,
  formatEther,
  getAddress,
  type Hex,
  hexToBytes,
  http,
  parseEther,
} from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { sepolia } from 'viem/chains'

import { ANNOUNCER_ABI, SCHEME_ID, SEPOLIA } from '../../js-client/src/sepolia.ts'
import { KOHAKU_SEPOLIA } from '../src/lib/kohaku.ts'
import { pimlicoUrl, submitSponsoredUserOp } from '../src/lib/pimlico.ts'
import {
  ACCOUNT_ABI,
  dummyHybridSignature,
  ENTRYPOINT_ABI,
  packHybridSignature,
  preQuantumDemoKey,
  ZKNOX_FACTORY_ABI,
} from '../src/lib/spendHybrid.ts'
import { SIGNER_PORT, startSignerService } from './signer-service.mjs'

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url))
const SIGNER = `http://127.0.0.1:${SIGNER_PORT}`
const MLDSA44_SIG_BYTES = 2420

// strip any URL from a string so an API key embedded in an RPC/Pimlico URL is
// never echoed into logs by a downstream error message.
const redact = (s: string) => s.replace(/https?:\/\/\S+/g, '<url-redacted>')

if (process.env.LIVE !== '1') {
  console.error('refusing to broadcast: set LIVE=1 to run the live Sepolia test')
  process.exit(2)
}

// load .env from the worktree root (../../ from ui/scripts/)
try {
  process.loadEnvFile(here('../../.env'))
} catch {
  /* may already be in env */
}
const PIMLICO_API_KEY = process.env.PIMLICO_API_KEY ?? ''
const SEPOLIA_PRIVATE_KEY = (process.env.SEPOLIA_PRIVATE_KEY ?? '') as Hex
const SEPOLIA_RPC_URL = process.env.SEPOLIA_RPC_URL ?? ''
for (const [k, v] of Object.entries({ PIMLICO_API_KEY, SEPOLIA_PRIVATE_KEY, SEPOLIA_RPC_URL })) {
  if (!v) {
    console.error(`missing ${k} in .env`)
    process.exit(2)
  }
}

const demo = JSON.parse(readFileSync(here('../../python/scripts/zknox_demo.json'), 'utf8'))

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const r = await fetch(`${SIGNER}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!r.ok) throw new Error(`${path}: ${await r.text()}`)
  return (await r.json()) as T
}

const signer = startSignerService()
try {
  const publicClient = createPublicClient({ chain: sepolia, transport: http(SEPOLIA_RPC_URL) })
  const eoa = privateKeyToAccount(SEPOLIA_PRIVATE_KEY)
  const wallet = createWalletClient({ chain: sepolia, transport: http(SEPOLIA_RPC_URL), account: eoa })
  const chainId = sepolia.id
  const url = pimlicoUrl(chainId, PIMLICO_API_KEY)

  // recipient = the deployer itself, so the tiny spend value comes back
  const recipient = getAddress(eoa.address)
  const spendValue = parseEther('0.001')

  const preQ = preQuantumDemoKey()
  const account = (await publicClient.readContract({
    address: KOHAKU_SEPOLIA.mldsaK1Factory,
    abi: ZKNOX_FACTORY_ABI,
    functionName: 'getAddress',
    args: [preQ.address, demo.public_key_data as Hex],
  })) as Address
  console.log(`deployer:         ${eoa.address}`)
  console.log(`stealth account:  ${account}`)
  console.log(`recipient:        ${recipient}`)
  console.log(`spend value:      ${formatEther(spendValue)} ETH`)

  const deployerBal = await publicClient.getBalance({ address: eoa.address })
  console.log(`deployer balance: ${formatEther(deployerBal)} ETH`)
  if (deployerBal < spendValue + parseEther('0.003')) {
    throw new Error('deployer underfunded — need ~spendValue + ~0.003 ETH for createAccount gas')
  }

  // ---- stage 1: on-chain (idempotent) --------------------------------------
  console.log('\n[stage 1] on-chain setup')

  // announce (self-emit for discovery; optional for the spend but part of the flow)
  const annHash = await wallet.writeContract({
    address: SEPOLIA.erc5564Announcer,
    abi: ANNOUNCER_ABI,
    functionName: 'announce',
    args: [SCHEME_ID, account, demo.kem_ct as Hex, demo.view_tag as Hex],
  })
  await publicClient.waitForTransactionReceipt({ hash: annHash })
  console.log(`  announced (${annHash.slice(0, 10)}…)`)

  // fund the account with exactly the spend value (paymaster covers all gas)
  const accBal = await publicClient.getBalance({ address: account })
  if (accBal < spendValue) {
    const fundHash = await wallet.sendTransaction({ to: account, value: spendValue - accBal })
    await publicClient.waitForTransactionReceipt({ hash: fundHash })
    console.log(`  funded account with ${formatEther(spendValue - accBal)} ETH`)
  } else {
    console.log(`  account already holds ${formatEther(accBal)} ETH (≥ spend value)`)
  }

  // deploy the account if it isn't already
  const code = await publicClient.getBytecode({ address: account })
  if (!code || code === '0x') {
    const createHash = await wallet.writeContract({
      address: KOHAKU_SEPOLIA.mldsaK1Factory,
      abi: ZKNOX_FACTORY_ABI,
      functionName: 'createAccount',
      args: [preQ.address, demo.public_key_data as Hex],
      gas: 900_000n,
    })
    const cr = await publicClient.waitForTransactionReceipt({ hash: createHash })
    assert.equal(cr.status, 'success', 'createAccount must succeed')
    console.log(`  createAccount ok (gas ${cr.gasUsed})`)
  } else {
    console.log('  account already deployed')
  }

  // ---- stage 2: sponsored spend (free + retryable) -------------------------
  console.log('\n[stage 2] Pimlico-sponsored spend')
  const nonce = (await publicClient.readContract({
    address: KOHAKU_SEPOLIA.entryPoint,
    abi: ENTRYPOINT_ABI,
    functionName: 'getNonce',
    args: [account, 0n],
  })) as bigint
  const callData = encodeFunctionData({
    abi: ACCOUNT_ABI,
    functionName: 'execute',
    args: [recipient, spendValue, '0x'],
  })
  const dummySignature = await dummyHybridSignature()

  const sign = async (userOpHash: Hex): Promise<Hex> => {
    const { sig: blindedSig } = await postJson<{ sig: Hex }>('/hybrid/sign', { challenge: userOpHash })
    const blindedLen = hexToBytes(blindedSig).length
    assert.equal(
      blindedLen,
      MLDSA44_SIG_BYTES,
      `blinded ML-DSA sig must be ${MLDSA44_SIG_BYTES} bytes (got ${blindedLen}) — ` +
        'a different length changes the abi-encoded signature size Pimlico estimated against',
    )
    return packHybridSignature(userOpHash, blindedSig)
  }

  const accBeforeSpend = await publicClient.getBalance({ address: account })
  const res = await submitSponsoredUserOp({
    url,
    chainId,
    sender: account,
    nonce,
    callData,
    dummySignature,
    sign,
    onStep: (m) => console.log(`  ${m}`),
  })
  console.log(`  userOpHash: ${res.userOpHash}`)
  console.log(`  tx:         ${res.txHash}`)
  console.log(`  gasUsed:    ${res.gasUsed}`)
  console.log(`  success:    ${res.success}`)
  assert.equal(res.success, true, 'sponsored userOp must succeed on-chain')

  // paymaster covered gas, so the account is debited by exactly the spend
  // value (robust to any leftover balance from a prior run)
  const accAfter = await publicClient.getBalance({ address: account })
  assert.equal(
    accBeforeSpend - accAfter,
    spendValue,
    'stealth account must be debited by exactly the spend value (paymaster paid gas)',
  )
  console.log(`  account debited by ${formatEther(accBeforeSpend - accAfter)} ETH (gas sponsored) ✓`)
  console.log('\nLIVE gasless spend via Pimlico: OK ✓')
} catch (e) {
  console.error('\nLIVE test failed:', redact((e as Error).message))
  process.exitCode = 1
} finally {
  signer.close()
}
