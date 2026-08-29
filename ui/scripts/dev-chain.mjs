#!/usr/bin/env node
/**
 * Local dev chain + signer service for the UI.
 *
 * Chain (anvil :8545):
 *   1. deploy the forge-built ERC-5564 announcer as the FIRST tx (so its
 *      address is the deterministic 0x5FbD…0aa3 the UI expects)
 *   2. deploy the ERC-4337 v0.8 EntryPoint, the ZKNOX_dilithium ERC-7913
 *      verifier (ETHDILITHIUM @ df999ed), and the Stealth7913Factory
 *   3. seed announcements:
 *        - ML-DSA-65 conformance vectors (2 genuine funded + 3 tampered)
 *        - classical-spend vectors (2 genuine funded — spendable EOAs)
 *        - one PQ-spendable payment (level-2 fixture): counterfactual
 *          account address announced + funded
 *   4. write ui/public/dev-deployment.json for the UI
 *
 * Signer service (:8546, localhost only): wraps the Python blinded-key
 * helper (python/scripts/spendable_helper.py) —
 *   POST /derive {ss}            -> {view_tag, stealth_pk, public_key_data}
 *   POST /sign   {ss, challenge} -> {sig, ...}
 * The blinded secret never leaves the Python process; the service returns
 * public outputs and signatures only.
 *
 * Prereqs: `anvil`/`forge` on PATH, `npm i` here, the vendored
 * ETHDILITHIUM lib (js-client/README "Vendored verifier"), and the
 * python venv (python/.venv) with kyber-py, eth-abi, polyntt.
 */

import { execFileSync, spawn } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { createPublicClient, createWalletClient, getAddress, http, parseEther } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { foundry } from 'viem/chains'

import { DEMO, SIGNER_PORT, startSignerService } from './signer-service.mjs'

const PORT = 8545
const RPC = `http://127.0.0.1:${PORT}`
const EXPECTED_ANNOUNCER = '0x5FbDB2315678afecb367f032d93F642f64180aa3'
const DEV_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
const SCHEME_ID = 2n

const here = (p) => fileURLToPath(new URL(p, import.meta.url))
const contractsRoot = here('../../js-client/contracts')
const OUT = `${contractsRoot}/out`

const artifact = (rel) => JSON.parse(readFileSync(`${OUT}/${rel}`, 'utf8'))

const NEEDED = [
  'ERC5564Announcer.sol/ERC5564Announcer.json',
  'EntryPoint.sol/EntryPoint.json',
  'ZKNOX_dilithium.sol/ZKNOX_dilithium.json',
  'Stealth7913Factory.sol/Stealth7913Factory.json',
]
if (NEEDED.some((rel) => !existsSync(`${OUT}/${rel}`))) {
  console.log('forge artifacts missing — running forge build…')
  execFileSync('forge', ['build'], { cwd: contractsRoot, stdio: 'inherit' })
}

const vectors = JSON.parse(readFileSync(here('../../python/vectors/v0/vectors.json'), 'utf8'))
const classicalVectors = JSON.parse(readFileSync(here('../../python/vectors/classical/v0/vectors.json'), 'utf8'))
const fixture = JSON.parse(readFileSync(here('../../python/scripts/zknox_7913_demo.json'), 'utf8'))

// ---------------------------------------------------------------------------
// signer service (Python wrapper — see signer-service.mjs)
// ---------------------------------------------------------------------------
const signer = startSignerService()

// ---------------------------------------------------------------------------
// anvil + deployments
// ---------------------------------------------------------------------------
console.log(`starting anvil on :${PORT}…`)
const anvil = spawn('anvil', ['--port', String(PORT), '--chain-id', '31337'], { stdio: ['ignore', 'pipe', 'inherit'] })
anvil.on('exit', (code) => {
  console.log(`anvil exited (${code ?? 'signal'})`)
  signer.close()
  process.exit(code ?? 0)
})
process.on('SIGINT', () => anvil.kill('SIGINT'))
process.on('SIGTERM', () => anvil.kill('SIGTERM'))

const publicClient = createPublicClient({ chain: foundry, transport: http(RPC) })
const walletClient = createWalletClient({
  chain: foundry,
  transport: http(RPC),
  account: privateKeyToAccount(DEV_KEY),
})

for (let i = 0; ; i++) {
  try {
    await publicClient.getBlockNumber()
    break
  } catch {
    if (i > 100) {
      console.error('anvil did not come up')
      process.exit(1)
    }
    await new Promise((r) => setTimeout(r, 100))
  }
}

async function deploy(art, args = []) {
  const hash = await walletClient.deployContract({
    abi: art.abi,
    bytecode: art.bytecode.object,
    args,
    gas: 30_000_000n,
  })
  const rcpt = await publicClient.waitForTransactionReceipt({ hash })
  if (rcpt.status !== 'success') throw new Error('deploy failed')
  return getAddress(rcpt.contractAddress)
}

const announcerArt = artifact('ERC5564Announcer.sol/ERC5564Announcer.json')
const announcer = await deploy(announcerArt)
if (announcer !== EXPECTED_ANNOUNCER) {
  console.warn(`WARNING: announcer at ${announcer}, but the UI expects ${EXPECTED_ANNOUNCER}.`)
  console.warn('Restart this script against a FRESH anvil (the deploy must be tx #1).')
}
const entryPoint = await deploy(artifact('EntryPoint.sol/EntryPoint.json'))
const verifier = await deploy(artifact('ZKNOX_dilithium.sol/ZKNOX_dilithium.json'))
const factoryArt = artifact('Stealth7913Factory.sol/Stealth7913Factory.json')
const factory = await deploy(factoryArt, [verifier, entryPoint])
const registryArt = artifact('StealthKeyRegistry.sol/StealthKeyRegistry.json')
const registry = await deploy(registryArt)
console.log(
  `deployed  entryPoint ${entryPoint}\n          verifier   ${verifier}\n          factory    ${factory}\n          registry   ${registry}`,
)

// register classical test-recipient A's viewing key at index 0, so the
// 65-byte compact meta-address (spend_pub || 0) resolves out of the box
{
  const metaHex = classicalVectors.recipients.A.meta_address
  const ekHex = '0x' + metaHex.slice(2 + 2 * 34) // version(1) + spend_pub(33)
  const h = await walletClient.writeContract({
    address: registry,
    abi: registryArt.abi,
    functionName: 'register',
    args: [ekHex],
  })
  await publicClient.waitForTransactionReceipt({ hash: h })
  console.log('  registered classical recipient A viewing key at index 0')
}

async function announce(stealthAddress, ephemeralPubKey, viewTag) {
  const h = await walletClient.writeContract({
    address: announcer,
    abi: announcerArt.abi,
    functionName: 'announce',
    args: [SCHEME_ID, stealthAddress, ephemeralPubKey, viewTag],
  })
  await publicClient.waitForTransactionReceipt({ hash: h })
}

async function fund(to, amountEth) {
  const h = await walletClient.sendTransaction({ to, value: parseEther(amountEth) })
  await publicClient.waitForTransactionReceipt({ hash: h })
}

// --- ML-DSA-65 conformance vectors (discovery demo) ------------------------
const WANTED_65 = [
  ['positive/basic-match', '0.5'],
  ['positive/second-payment-unlinkable', '1.25'],
  ['negative/wrong-view-tag', null],
  ['negative/truncated-ciphertext', null],
  ['negative/bitflipped-ciphertext', null],
]
for (const [name, amount] of WANTED_65) {
  const a = vectors.cases.find((x) => x.name === name).announcement
  const addr = getAddress(a.stealth_address)
  if (amount) await fund(addr, amount)
  await announce(addr, a.ephemeral_pub_key, a.view_tag)
  console.log(`  seeded ml-dsa-65 ${name}${amount ? ` (${amount} ETH)` : ''}`)
}

// --- classical-spend vectors (spendable EOAs) ------------------------------
const WANTED_CLASSICAL = [
  ['positive/basic-match', '0.4'],
  ['positive/second-payment-unlinkable', '0.8'],
]
for (const [name, amount] of WANTED_CLASSICAL) {
  const a = classicalVectors.cases.find((x) => x.name === name).announcement
  const addr = getAddress(a.stealth_address)
  await fund(addr, amount)
  await announce(addr, a.ephemeral_pub_key, a.view_tag)
  console.log(`  seeded classical ${name} (${amount} ETH, spendable EOA)`)
}

// --- one PQ-spendable payment (level-2 fixture) ----------------------------
// counterfactual account address from the fixture's public_key_data
const { decodeAbiParameters } = await import('viem')
const [aHatEnc, tr, t1Enc] = decodeAbiParameters(
  [{ type: 'bytes' }, { type: 'bytes' }, { type: 'bytes' }],
  fixture.public_key_data,
)
const [aHat] = decodeAbiParameters([{ type: 'uint256[][][]' }], aHatEnc)
const [t1] = decodeAbiParameters([{ type: 'uint256[][]' }], t1Enc)
const spendableAccount = await publicClient.readContract({
  address: factory,
  abi: factoryArt.abi,
  functionName: 'getAccountAddress',
  args: [aHat, tr, t1],
})
await fund(spendableAccount, '1')
await announce(getAddress(spendableAccount), fixture.kem_ct, fixture.view_tag)
console.log(`  seeded pq-spendable payment -> counterfactual account ${spendableAccount} (1 ETH)`)

// --- hand the UI what it needs ---------------------------------------------
const deployment = {
  mode: 'stealth7913',
  chainId: 31337,
  announcer,
  entryPoint,
  verifier,
  factory,
  registry,
  signerService: `http://127.0.0.1:${SIGNER_PORT}`,
  demo: DEMO,
}
mkdirSync(here('../public'), { recursive: true })
writeFileSync(here('../public/dev-deployment.json'), JSON.stringify(deployment, null, 2) + '\n')

console.log(`
dev chain ready
  RPC             ${RPC}  (chain id 31337)
  announcer       ${announcer}
  entryPoint      ${entryPoint}  (ERC-4337 v0.8, local deploy)
  7913 verifier   ${verifier}
  stealth factory ${factory}
  key registry    ${registry}  (compact 65-B meta-addresses)
  signer service  http://127.0.0.1:${SIGNER_PORT}  (blinded ML-DSA signing)
  dev key         ${DEV_KEY}

Seeded: 5 ML-DSA-65 announcements (2 funded), 2 classical spendable EOAs,
1 PQ-spendable counterfactual account (level-2 profile).
UI: network "Local anvil", signer "anvil dev account". Ctrl-C stops everything.`)
