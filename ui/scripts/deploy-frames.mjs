#!/usr/bin/env node
/**
 * Deploy the frame-transaction PQ spend route on the public frames testnet
 * (chain 81410) and write ui/public/frames-deployment.json for the UI:
 *
 *   1. FrameTxContext   — Yul helper exposing TXPARAM/SIGPARAM/SIGDATACOPY
 *   2. ZKNOX_dilithium  — ERC-7913 ML-DSA verifier (ETHDILITHIUM @ df999ed)
 *   3. Stealth8141Factory(verifier, frameCtx) — CREATE2 stealth accounts
 *
 * The announcer defaults to the one in ui/src/lib/chain.ts; pass ANNOUNCER=0x…
 * to override. This testnet is reset without notice, which wipes every address
 * above — so if the configured announcer has no code, a fresh ERC5564Announcer
 * is deployed here (step 0) and printed for chain.ts. Fees are explicit and
 * tiny: the testnet's
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
let ANNOUNCER = getAddress(process.env.ANNOUNCER ?? '0xb4b46bdaa835f8e4b4d8e208b6559cd267851051')
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

/** block of the most recent deploy() — step 0 reports it as the new scanFromBlock */
let lastDeployBlock = 0n

async function deploy(name, art, args, gas) {
  const hash = await walletClient.deployContract({ abi: art.abi ?? [], bytecode: art.bytecode.object, args, gas, ...FEES })
  const rcpt = await publicClient.waitForTransactionReceipt({ hash })
  if (rcpt.status !== 'success') throw new Error(`${name}: deploy reverted (${hash})`)
  console.log(`  ${name.padEnd(18)} ${rcpt.contractAddress}  block ${rcpt.blockNumber}  gas ${rcpt.gasUsed}`)
  lastDeployBlock = rcpt.blockNumber
  return getAddress(rcpt.contractAddress)
}

// Step 0 — the announcer. `announce` returns nothing, so announcing at a
// code-less address SUCCEEDS and emits no log: every payment made against a
// stale announcer is silently undiscoverable. Check, don't assume.
let announcerDeployBlock = null
const announcerCode = await publicClient.getCode({ address: ANNOUNCER })
if (announcerCode && announcerCode.length > 2) {
  console.log(`  ${'ERC5564Announcer'.padEnd(18)} ${ANNOUNCER}  (reused)`)
} else {
  console.log(`  no code at announcer ${ANNOUNCER} — the chain was reset; deploying a fresh one`)
  ANNOUNCER = await deploy('ERC5564Announcer', artifact('ERC5564Announcer.sol/ERC5564Announcer.json'), [], 4_000_000n)
  announcerDeployBlock = lastDeployBlock
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
  // SIGNER_URL: the hosted signer (npm run deploy:signer); local service otherwise
  signerService: process.env.SIGNER_URL ?? `http://127.0.0.1:${SIGNER_PORT}`,
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

if (announcerDeployBlock !== null)
  console.log(`
A NEW announcer was deployed, so ui/src/lib/chain.ts must be edited by hand —
the UI reads the announcer from there, not from frames-deployment.json:

  frames: {
    announcer: '${ANNOUNCER.toLowerCase()}',
    scanFromBlock: ${announcerDeployBlock}n, // announcer deploy block
  }

Then re-run \`node scripts/deploy-frames-zk.mjs\` (and ZK_CIRCUIT=c13) so the ZK
deployments pick up the new announcer from frames-deployment.json.`)
