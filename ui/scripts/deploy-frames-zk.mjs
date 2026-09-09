#!/usr/bin/env node
/**
 * Deploy the ZK SPHINCS- spend route on the public frames testnet (chain 81410)
 * and write ui/public/frames-zk-deployment.json:
 *
 *   1. HonkVerifier          — bb-generated UltraHonk verifier for noir/sphincs-c13-verify
 *                              (js-client/contracts/src/frames/zk/SphincsC13HonkVerifier.sol)
 *   2. Stealth8141ZkFactory  — CREATE2 accounts keyed by the D-018 commitment
 *
 * FrameTxContext and the announcer are reused from frames-deployment.json.
 * The verifier's runtime code is ~26 kB: if the chain enforces EIP-170 the
 * first deploy reverts, which is itself a finding — the script reports it.
 *
 * Env: FRAMES_DEPLOYER_KEY (default: shared dev key), FRAMES_RPC.
 * Prereqs: `forge build --root contracts` in js-client (after copying the
 * verifier from noir/sphincs-c13-verify/out/Verifier.sol).
 */

import { readFileSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { createPublicClient, createWalletClient, formatEther, getAddress, http } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'

const here = (p) => fileURLToPath(new URL(p, import.meta.url))
const RPC = process.env.FRAMES_RPC ?? 'https://rpc1.frames.ethrex.xyz'
const CHAIN_ID = 81410
const DEPLOYER_KEY =
  process.env.FRAMES_DEPLOYER_KEY ?? '0xbcdf20249abf0ed6d944c0288fad489e33f66b3960d9e6229c1cd214ed3bbe31'
const FEES = { maxFeePerGas: 1_000n, maxPriorityFeePerGas: 100n } // wei

const base = JSON.parse(readFileSync(here('../public/frames-deployment.json'), 'utf8'))
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
  if (rcpt.status !== 'success') throw new Error(`${name}: deploy reverted (${hash}) — runtime ${art.deployedBytecode?.object ? (art.deployedBytecode.object.length - 2) / 2 : '?'} B; EIP-170?`)
  console.log(`  ${name.padEnd(22)} ${rcpt.contractAddress}  block ${rcpt.blockNumber}  gas ${rcpt.gasUsed}`)
  return getAddress(rcpt.contractAddress)
}

// bb's verifier calls ZKTranscriptLib through an external (public) library, so it is a
// separate contract that has to be deployed first and linked into the bytecode.
const libArt = artifact('SphincsC13HonkVerifier.sol/ZKTranscriptLib.json')
console.log(`ZKTranscriptLib runtime ${(libArt.deployedBytecode.object.length - 2) / 2} B`)
const transcriptLib = await deploy('ZKTranscriptLib', libArt, [], 40_000_000n)

const honkArt = artifact('SphincsC13HonkVerifier.sol/HonkVerifier.json')
{
  let code = honkArt.bytecode.object
  const refs = honkArt.bytecode.linkReferences?.['src/frames/zk/SphincsC13HonkVerifier.sol']?.ZKTranscriptLib ?? []
  for (const { start, length } of refs) {
    code = code.slice(0, 2 + start * 2) + transcriptLib.slice(2).toLowerCase() + code.slice(2 + (start + length) * 2)
  }
  if (code.includes('__$')) throw new Error('unlinked library placeholder left in HonkVerifier bytecode')
  honkArt.bytecode.object = code
}
console.log(`HonkVerifier runtime ${(honkArt.deployedBytecode.object.length - 2) / 2} B (EIP-170 limit 24576)`)
const verifier = await deploy('HonkVerifier', honkArt, [], 58_000_000n)
const factory = await deploy(
  'Stealth8141ZkFactory',
  artifact('Stealth8141ZkFactory.sol/Stealth8141ZkFactory.json'),
  [verifier, base.frameCtx],
  30_000_000n,
)

const deployment = {
  mode: 'stealth8141-zk-sphincs',
  chainId: CHAIN_ID,
  announcer: base.announcer,
  frameCtx: base.frameCtx,
  transcriptLib,
  verifier,
  factory,
  circuit: 'noir/sphincs-c13-verify',
  // demo recipient: the fixture's seeds (C13 spend seed, ML-KEM-768 d/z)
  demo: { spendSeed: `0x${'81'.repeat(32)}`, kemD: `0x${'83'.repeat(32)}`, kemZ: `0x${'84'.repeat(32)}` },
  deployedAt: { block: Number(await publicClient.getBlockNumber()), by: account.address },
}
const file = here('../public/frames-zk-deployment.json')
writeFileSync(file, JSON.stringify(deployment, null, 2) + '\n')
console.log(`\nwrote ${file}\n  verifier ${verifier}\n  factory  ${factory}`)
