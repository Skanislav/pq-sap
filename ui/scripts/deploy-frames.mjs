#!/usr/bin/env node
/**
 * Deploy the frame-transaction PQ spend route on the public frames testnet
 * (chain 81410) and write ui/public/frames-deployment.json for the UI:
 *
 *   1. FrameTxContext   — Yul helper exposing TXPARAM/SIGPARAM/SIGDATACOPY
 *   2. ZKNOX_dilithium  — ERC-7913 ML-DSA verifier (ETHDILITHIUM @ df999ed)
 *   3. Stealth8141Factory(verifier, frameCtx) — CREATE2 stealth accounts
 *
 * The announcer is the one already in ui/src/lib/chain.ts (deployed earlier);
 * pass ANNOUNCER=0x… to override. Fees are explicit and tiny: the testnet's
 * base fee is a few wei and its proposer accepts ~100-wei tips, so even the
 * nearly-drained shared dev key can pay (viem's auto-fee would overshoot).
 *
 * Env: FRAMES_DEPLOYER_KEY (default: the shared ethereum-package dev key),
 *      FRAMES_RPC (default https://rpc1.frames.ethrex.xyz), ANNOUNCER.
 * Prereqs: `forge build` + `bash script/build-yul.sh` in js-client/contracts.
 */

import { readFileSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { createPublicClient, createWalletClient, formatEther, getAddress, http } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'

import { DEMO, SIGNER_PORT } from './signer-service.mjs'

const here = (p) => fileURLToPath(new URL(p, import.meta.url))
const RPC = process.env.FRAMES_RPC ?? 'https://rpc1.frames.ethrex.xyz'
const CHAIN_ID = 81410
const DEPLOYER_KEY =
  process.env.FRAMES_DEPLOYER_KEY ?? '0xbcdf20249abf0ed6d944c0288fad489e33f66b3960d9e6229c1cd214ed3bbe31'
const ANNOUNCER = getAddress(process.env.ANNOUNCER ?? '0x9fcf7d13d10dedf17d0f24c62f0cf4ed462f65b7')
const FEES = { maxFeePerGas: 1_000n, maxPriorityFeePerGas: 100n } // wei

const OUT = here('../../js-client/contracts/out')
const artifact = (rel) => JSON.parse(readFileSync(`${OUT}/${rel}`, 'utf8'))

const chain = {
  id: CHAIN_ID,
  name: 'Frames Testnet',
  nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
  rpcUrls: { default: { http: [RPC] } },
}
const account = privateKeyToAccount(DEPLOYER_KEY)
const publicClient = createPublicClient({ chain, transport: http(RPC) })
const walletClient = createWalletClient({ chain, transport: http(RPC), account })

console.log(`deployer ${account.address}: ${formatEther(await publicClient.getBalance({ address: account.address }))} ETH`)

async function deploy(name, art, args, gas) {
  const hash = await walletClient.deployContract({ abi: art.abi ?? [], bytecode: art.bytecode.object, args, gas, ...FEES })
  const rcpt = await publicClient.waitForTransactionReceipt({ hash })
  if (rcpt.status !== 'success') throw new Error(`${name}: deploy reverted (${hash})`)
  console.log(`  ${name.padEnd(18)} ${rcpt.contractAddress}  block ${rcpt.blockNumber}  gas ${rcpt.gasUsed}`)
  return getAddress(rcpt.contractAddress)
}

// Contract creation is far pricier here than on mainnet (EIP-8037 state gas +
// EIP-7976 calldata floor: ~2.5k gas per deployed byte — the 150-B helper costs
// 424k, the 14.5-KB verifier tens of millions), so give limits near the 60M
// block limit; unused gas is refunded and fees are ~nothing.
const frameCtx = await deploy('FrameTxContext', artifact('FrameTxContext.yul/FrameTxContext.json'), [], 2_000_000n) // ~424k used
const verifier = await deploy('ZKNOX_dilithium', artifact('ZKNOX_dilithium.sol/ZKNOX_dilithium.json'), [], 55_000_000n)
const factory = await deploy(
  'Stealth8141Factory',
  artifact('Stealth8141Factory.sol/Stealth8141Factory.json'),
  [verifier, frameCtx],
  40_000_000n,
)

const deployment = {
  mode: 'stealth8141',
  chainId: CHAIN_ID,
  announcer: ANNOUNCER,
  entryPoint: null,
  verifier,
  factory,
  frameCtx,
  registry: null,
  signerService: `http://127.0.0.1:${SIGNER_PORT}`,
  demo: DEMO,
  deployedAt: { block: Number(await publicClient.getBlockNumber()), by: account.address },
}
const file = here('../public/frames-deployment.json')
writeFileSync(file, JSON.stringify(deployment, null, 2) + '\n')
console.log(`\nwrote ${file}
  frameCtx  ${frameCtx}
  verifier  ${verifier}
  factory   ${factory}
Run the signer service (\`npm run signer\`) and open the Spend tab on "Frames testnet".`)
