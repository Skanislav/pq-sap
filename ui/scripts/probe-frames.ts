#!/usr/bin/env node
// Diagnostic: isolate which part of the sponsored PQ spend the builder drops.
//   node scripts/probe-frames.ts ctx      -> [VERIFY(sponsor), DEFAULT(frameCtx.sigHash())] + ARBITRARY sig
//   node scripts/probe-frames.ts sig      -> same with frameCtx.signature(1) (SIGPARAM len + SIGDATACOPY)
//   node scripts/probe-frames.ts two      -> two 15M-execution-gas frames (per-frame vs per-tx cap probe)
//   node scripts/probe-frames.ts deploy   -> [VERIFY(sponsor), DEFAULT(factory.createAccount(pk))]
//   node scripts/probe-frames.ts deploy <execM> <stateM>  (defaults 8 / 40)
//   node scripts/probe-frames.ts estimate -> eth_estimateGas of createAccount (type-2 tx)
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { createPublicClient, encodeFunctionData, type Hex, http, parseAbi } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { buildFramesTx, buildSponsoredPqTx, defaultFrame, rpc, sendRawFrameTx, verifyFrame } from '../../js-client/src/frame-tx/actions.ts'
import { APPROVE_SCOPE } from '../../js-client/src/frame-tx/serialize.ts'
import { framesTestnet } from '../src/lib/chain.ts'
import { decodePublicKeyData, deriveSpendable, FACTORY_ABI } from '../src/lib/spend4337.ts'

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url))
const dep = JSON.parse(readFileSync(here('../public/frames-deployment.json'), 'utf8'))
const RPC = framesTestnet.rpcUrls.default.http[0]
const KEY = '0xbcdf20249abf0ed6d944c0288fad489e33f66b3960d9e6229c1cd214ed3bbe31' as Hex
const sponsor = privateKeyToAccount(KEY)
const FEES = { maxFeePerGas: 1_000n, maxPriorityFeePerGas: 100n }
const client = createPublicClient({ chain: framesTestnet, transport: http(RPC) })
const mode = process.argv[2] ?? 'ctx'
const nonce = BigInt(await rpc<Hex>(RPC, 'eth_getTransactionCount', [sponsor.address, 'pending']))

let raw: Hex
if (mode === 'ctx' || mode === 'sig' || mode === 'two') {
  const ctxAbi = parseAbi(['function sigHash() view returns (bytes32)', 'function signature(uint256 i) view returns (bytes)'])
  const data = mode === 'ctx'
    ? encodeFunctionData({ abi: ctxAbi, functionName: 'sigHash' })
    : encodeFunctionData({ abi: ctxAbi, functionName: 'signature', args: [1n] })
  const r = await buildSponsoredPqTx({
    chainId: 81410n, nonce, sponsor: sponsor.address, sponsorPrivateKey: KEY,
    frames: mode === 'two'
      ? [15_000_000n, 15_000_000n].map((g) => defaultFrame({ target: dep.frameCtx, executionGas: g, stateGas: 100_000n, data }))
      : [defaultFrame({ target: dep.frameCtx, executionGas: 100_000n, stateGas: 100_000n, data })],
    pqSign: async () => `0x${'ab'.repeat(2420)}`,
    ...FEES,
  })
  raw = r.raw
} else {
  const derived = await deriveSpendable(dep.signerService, `0x${'11'.repeat(32)}`)
  const pkArgs = decodePublicKeyData(derived.public_key_data)
  const account = await client.readContract({ address: dep.factory, abi: FACTORY_ABI, functionName: 'getAccountAddress', args: pkArgs })
  console.log('probe account', account, 'code', ((await client.getCode({ address: account })) ?? '0x').length > 2)
  const data = encodeFunctionData({ abi: FACTORY_ABI, functionName: 'createAccount', args: pkArgs })
  if (mode === 'estimate') {
    const g = await client.estimateGas({ account: sponsor.address, to: dep.factory, data })
    console.log('eth_estimateGas createAccount:', g)
    process.exit(0)
  }
  const execGas = BigInt(process.argv[3] ?? '8') * 1_000_000n
  const stateGas = BigInt(process.argv[4] ?? '40') * 1_000_000n
  const r = await buildFramesTx({
    chainId: 81410n, nonce, sender: sponsor.address, privateKey: KEY,
    frames: [
      verifyFrame({ target: sponsor.address, flags: APPROVE_SCOPE.BOTH, executionGas: 100_000n, stateGas: 250_000n }),
      defaultFrame({ target: dep.factory, executionGas: execGas, stateGas, data }),
    ],
    ...FEES,
  })
  raw = r.raw
}
console.log(mode, 'raw bytes', (raw.length - 2) / 2)
const hash = await sendRawFrameTx(RPC, raw)
console.log('sent', hash)
let rcpt: Record<string, unknown> | null = null
for (let i = 0; i < 40 && !rcpt; i++) {
  rcpt = await rpc(RPC, 'eth_getTransactionReceipt', [hash])
  if (!rcpt) await new Promise((x) => setTimeout(x, 1500))
}
console.log(rcpt ? JSON.stringify(rcpt, (_k, v) => (typeof v === 'string' && v.length > 200 ? `${v.slice(0, 80)}…` : v), 1) : 'NO RECEIPT (dropped)')
