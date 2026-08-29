/**
 * Offline validation of the UI's Sepolia PQ spend path against the REAL
 * deployed ZKNOX/kohaku contracts, via the js-client fork-replay cache
 * (test/state/sepolia-fork-spend.rpc.json — no network, no key, no cost).
 *
 * Exercises exactly the UI's Sepolia code: spendHybrid.ts (counterfactual
 * account via the deployed mldsa_k1 factory, userOp build, hybrid signature
 * packing) + the signer service's /hybrid endpoints (blinded ML-DSA over
 * the demo identity). Mirrors js-client/test/e2e-sepolia-fork-spend so the
 * calls hit the recorded cache.
 */

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import {
  type Address,
  createPublicClient,
  createWalletClient,
  getAddress,
  type Hex,
  http,
  parseEther,
  toHex as toHexV,
} from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { sepolia } from 'viem/chains'

import { ANNOUNCER_ABI, SCHEME_ID, SEPOLIA } from '../../js-client/src/sepolia.ts'
import { startSepoliaFork } from '../../js-client/test/util/anvil.ts'
import { KOHAKU_SEPOLIA } from '../src/lib/kohaku.ts'
import { computeUserOpHash, packPaymasterAndData } from '../src/lib/pimlico.ts'
import {
  buildSpendUserOp,
  ENTRYPOINT_ABI,
  packHybridSignature,
  preQuantumDemoKey,
  requiredPrefund,
  ZKNOX_FACTORY_ABI,
} from '../src/lib/spendHybrid.ts'
import { SIGNER_PORT, startSignerService } from './signer-service.mjs'

const PORT = 8550
const PROXY_PORT = 9546
const ANVIL_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
const SERVICE = `http://127.0.0.1:${SIGNER_PORT}`

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url))
// fixed demo identity (matches the recorded fork-spend cache)
const demo = JSON.parse(readFileSync(here('../../python/scripts/zknox_demo.json'), 'utf8'))

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const r = await fetch(`${SERVICE}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!r.ok) throw new Error(`${path}: ${await r.text()}`)
  return (await r.json()) as T
}

const signer = startSignerService()
const anvil = await startSepoliaFork({ port: PORT, proxyPort: PROXY_PORT, cache: 'sepolia-fork-spend' })
console.log(`    fork mode: ${anvil.mode}`)
try {
  const publicClient = createPublicClient({ chain: sepolia, transport: http(anvil.rpc) })
  const eoa = privateKeyToAccount(ANVIL_KEY)
  const wallet = createWalletClient({ chain: sepolia, transport: http(anvil.rpc), account: eoa })

  // reuse the deployed kohaku factory + verifier (checked-in addresses)
  assert.equal(
    SEPOLIA.zknoxMldsaK1Factory,
    KOHAKU_SEPOLIA.mldsaK1Factory,
    'sepolia.ts factory must match the kohaku deployment',
  )

  // 1. counterfactual stealth account via the DEPLOYED hybrid factory
  const preQ = preQuantumDemoKey()
  const account = (await publicClient.readContract({
    address: KOHAKU_SEPOLIA.mldsaK1Factory,
    abi: ZKNOX_FACTORY_ABI,
    functionName: 'getAddress',
    args: [preQ.address, demo.public_key_data as Hex],
  })) as Address
  console.log(`    stealth account (deployed factory): ${account}`)

  // 2. announce (the self-send) + fund + deploy
  const annHash = await wallet.writeContract({
    address: SEPOLIA.erc5564Announcer,
    abi: ANNOUNCER_ABI,
    functionName: 'announce',
    args: [SCHEME_ID, account, demo.kem_ct as Hex, demo.view_tag as Hex],
  })
  await publicClient.waitForTransactionReceipt({ hash: annHash })

  const recipient = getAddress('0x00000000000000000000000000000000cafebabe')
  const spendValue = parseEther('0.005')
  const op = await buildSpendUserOp(publicClient, KOHAKU_SEPOLIA.entryPoint, account, recipient, spendValue)
  const funding = spendValue + (requiredPrefund(op) * 12n) / 10n
  const fundHash = await wallet.sendTransaction({ to: account, value: funding })
  await publicClient.waitForTransactionReceipt({ hash: fundHash })

  const createHash = await wallet.writeContract({
    address: KOHAKU_SEPOLIA.mldsaK1Factory,
    abi: ZKNOX_FACTORY_ABI,
    functionName: 'createAccount',
    args: [preQ.address, demo.public_key_data as Hex],
    gas: 10_000_000n,
  })
  const createRcpt = await publicClient.waitForTransactionReceipt({ hash: createHash })
  assert.equal(createRcpt.status, 'success')
  console.log(`    createAccount gas: ${createRcpt.gasUsed}`)

  // 3. hybrid-sign the userOp — ECDSA (browser) + blinded ML-DSA (service)
  const userOpHash = (await publicClient.readContract({
    address: KOHAKU_SEPOLIA.entryPoint,
    abi: ENTRYPOINT_ABI,
    functionName: 'getUserOpHash',
    args: [op],
  })) as Hex

  // parity: the off-chain Pimlico hash formula must equal the EntryPoint's
  const offchain = computeUserOpHash(
    {
      sender: op.sender,
      nonce: op.nonce,
      callData: op.callData,
      verificationGasLimit: BigInt(op.accountGasLimits) >> 128n,
      callGasLimit: BigInt(op.accountGasLimits) & ((1n << 128n) - 1n),
      preVerificationGas: op.preVerificationGas,
      maxPriorityFeePerGas: BigInt(op.gasFees) >> 128n,
      maxFeePerGas: BigInt(op.gasFees) & ((1n << 128n) - 1n),
      signature: op.signature,
    },
    sepolia.id,
  )
  assert.equal(offchain, userOpHash, 'off-chain computeUserOpHash (Pimlico path) must match EntryPoint.getUserOpHash')
  console.log('    userOpHash parity (off-chain == on-chain) ✓')

  // parity #2 — the SPONSORED path: a non-empty paymasterAndData exercises
  // packPaymasterAndData, which the self-bundled op above never touches. This
  // is the exact code the live Pimlico run depends on, so prove it here (free,
  // offline) rather than discovering an AA24 after funding real ETH.
  {
    const pack32 = (hi: bigint, lo: bigint): Hex => toHexV((hi << 128n) | lo, { size: 32 })
    const synthUnpacked = {
      sender: op.sender,
      nonce: 7n,
      callData: op.callData,
      callGasLimit: 400_000n,
      verificationGasLimit: 9_000_000n,
      preVerificationGas: 123_456n,
      maxFeePerGas: 3_000_000_000n,
      maxPriorityFeePerGas: 1_000_000_000n,
      paymaster: '0x1111111111111111111111111111111111111111' as Address,
      paymasterVerificationGasLimit: 111_111n,
      paymasterPostOpGasLimit: 222_222n,
      paymasterData: '0xdeadbeefcafe' as Hex,
      signature: op.signature,
    }
    const synthPacked = {
      sender: synthUnpacked.sender,
      nonce: synthUnpacked.nonce,
      initCode: '0x' as Hex,
      callData: synthUnpacked.callData,
      accountGasLimits: pack32(synthUnpacked.verificationGasLimit, synthUnpacked.callGasLimit),
      preVerificationGas: synthUnpacked.preVerificationGas,
      gasFees: pack32(synthUnpacked.maxPriorityFeePerGas, synthUnpacked.maxFeePerGas),
      paymasterAndData: packPaymasterAndData(synthUnpacked),
      signature: synthUnpacked.signature,
    }
    const onchainPm = (await publicClient.readContract({
      address: KOHAKU_SEPOLIA.entryPoint,
      abi: ENTRYPOINT_ABI,
      functionName: 'getUserOpHash',
      args: [synthPacked],
    })) as Hex
    const offchainPm = computeUserOpHash(synthUnpacked, sepolia.id)
    assert.equal(offchainPm, onchainPm, 'sponsored-op (paymasterAndData) hash parity must hold')
    console.log('    sponsored-op paymasterAndData hash parity ✓')
  }
  const { sig: blindedSig } = await postJson<{ sig: Hex }>('/hybrid/sign', { challenge: userOpHash })
  op.signature = await packHybridSignature(userOpHash, blindedSig)

  // 4. self-bundle through the canonical EntryPoint — on-chain success is the
  //    validation: the deployed ZKNOX account verifies the hybrid signature
  //    (ECDSA + blinded ML-DSA) against the real forked verifier state
  const before = await publicClient.getBalance({ address: recipient })
  const opsHash = await wallet.writeContract({
    address: KOHAKU_SEPOLIA.entryPoint,
    abi: ENTRYPOINT_ABI,
    functionName: 'handleOps',
    args: [[op], eoa.address],
    gas: 11_000_000n,
  })
  const opsRcpt = await publicClient.waitForTransactionReceipt({ hash: opsHash })
  assert.equal(opsRcpt.status, 'success', 'handleOps must succeed')
  const after = await publicClient.getBalance({ address: recipient })
  assert.equal(after - before, spendValue, 'recipient must receive the spent value')
  console.log(`    handleOps gas: ${opsRcpt.gasUsed}`)
  console.log(`    SPENT ${spendValue} wei via the DEPLOYED ZKNOX hybrid account ✓`)
  console.log('sepolia-fork (UI hybrid path): OK')
} finally {
  anvil.stop()
  signer.close()
}
