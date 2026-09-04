#!/usr/bin/env node
/**
 * Blinded-key signer service (localhost only) — wraps the Python helper
 * (python/scripts/spendable_helper.py) for the PQ spend route:
 *
 *   POST /derive {ss}            -> {view_tag, stealth_pk, public_key_data}
 *   POST /sign   {ss, challenge} -> {sig, ...}
 *
 * ZK SPHINCS- route (needs SIGNER_C13=/path/to/signer-c13, nargo, bb):
 *   POST /c13/key                          -> {pk_seed, pk_root, key, signer}
 *   POST /prove-c13 {sigHash, opener, commitment}
 *                                          -> {proof, sig_bytes, timings_ms}
 *
 * The blinded secret never leaves the Python process; only public outputs
 * and signatures are returned. Started automatically by dev-chain.mjs;
 * run standalone (`npm run signer`) when spending on Sepolia or the frames testnet.
 */

import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = (p) => fileURLToPath(new URL(p, import.meta.url))

export const SIGNER_PORT = 8546
// level-2 spendable demo identity (zknox_counterfactual_demo.py seeds)
export const DEMO = {
  zeta: '0x' + 'd1'.repeat(32),
  kemD: '0x' + 'd2'.repeat(32),
  kemZ: '0x' + 'd3'.repeat(32),
}
// ZK SPHINCS- route (D-023/D-024): the D-018 fixture recipient — C13 spend seed
// and ML-KEM-768 viewing-key seeds; the commitment meta-address is built from
// the C13 key the signer derives from `spendSeed`.
export const DEMO_ZK = {
  spendSeed: '0x' + '81'.repeat(32),
  kemD: '0x' + '83'.repeat(32),
  kemZ: '0x' + '84'.repeat(32),
}
// upstream Rust signer (lfglabs-dev/SPHINCS- @2a40d0a `signer-c13`) + Noir/bb prover
const SIGNER_C13 = process.env.SIGNER_C13 ?? null
const NARGO = process.env.NARGO ?? `${process.env.HOME}/.aztec/current/bin/nargo`
const BB = process.env.BB ?? `${process.env.HOME}/.aztec/current/node_modules/.bin/bb`
const CIRCUIT = here('../../noir/sphincs-c13-verify')
const C13_KEYGEN_DOMAIN = 'pq-stealth/sphincs-c13/keygen/v0'

const PY = process.env.PQ_PYTHON ?? here('../../python/.venv/bin/python')
const PYTHONREF = process.env.ZKNOX_PYTHONREF ?? here('../../js-client/contracts/lib/ETHDILITHIUM/pythonref')
// df999ed 7913-native helper (local Stealth7913 route)
const HELPER = here('../../python/scripts/spendable_helper.py')
// v0.0.10 hybrid helper (deployed ZKNOX/kohaku route on Sepolia)
const HYBRID_HELPER = here('../../python/scripts/zknox_counterfactual_demo.py')
const HEX32 = /^0x[0-9a-fA-F]{64}$/

export function startSignerService(port = SIGNER_PORT) {
  const workDir = mkdtempSync(join(tmpdir(), 'pq-signer-'))
  const deriveCache = new Map()

  // --- ZK SPHINCS- route helpers -------------------------------------------
  const run = (cmd, args, opts = {}) =>
    new Promise((resolve, reject) => {
      execFile(cmd, args, { timeout: 600_000, maxBuffer: 64 << 20, ...opts }, (err, stdout, stderr) => {
        if (err) return reject(new Error(`${cmd.split('/').pop()} failed: ${stderr || err.message}`))
        resolve(stdout)
      })
    })
  let c13KeyCache = null
  async function c13Key() {
    if (!SIGNER_C13) throw new Error('SIGNER_C13 is not set: build lfglabs-dev/SPHINCS- signer-c13 and export its path')
    if (!c13KeyCache) {
      const sm = createHash('sha256').update(Buffer.concat([Buffer.from(C13_KEYGEN_DOMAIN), Buffer.from(DEMO_ZK.spendSeed.slice(2), 'hex')])).digest('hex')
      c13KeyCache = JSON.parse(await run(SIGNER_C13, ['keygen', sm]))
    }
    return c13KeyCache
  }
  // proofs write fixed paths inside the circuit package (Prover_spend.toml,
  // target/spend.gz), so they are serialized through one promise chain
  let proveQueue = Promise.resolve()
  function proveC13(sigHash, opener, commitment) {
    const job = async () => {
      const k = await c13Key()
      const t0 = Date.now()
      const sig = (await run(SIGNER_C13, ['sign-with', k.seed, k.sk_seed, k.root, sigHash.slice(2)])).trim()
      const tSign = Date.now()
      const dir = mkdtempSync(join(workDir, 'c13zk-'))
      writeFileSync(join(dir, 'inputs.json'), JSON.stringify({
        pk_seed: k.seed, pk_root: k.root, opener, message: sigHash, sig: sig.startsWith('0x') ? sig : `0x${sig}`, commitment,
      }))
      await run(PY, [join(CIRCUIT, 'generate_prover.py'), '--inputs', join(dir, 'inputs.json'), '-o', join(CIRCUIT, 'Prover_spend.toml')])
      await run(NARGO, ['execute', '-p', 'Prover_spend', 'spend'], { cwd: CIRCUIT })
      const tWit = Date.now()
      await run(BB, ['prove', '-b', join(CIRCUIT, 'target/sphincs_c13_verify.json'), '-w', join(CIRCUIT, 'target/spend.gz'), '-t', 'evm', '-k', join(CIRCUIT, 'out/vk'), '-o', dir])
      const proof = readFileSync(join(dir, 'proof'))
      return {
        proof: `0x${proof.toString('hex')}`,
        sig_bytes: (sig.length - (sig.startsWith('0x') ? 2 : 0)) / 2,
        timings_ms: { sign: tSign - t0, witness: tWit - tSign, prove: Date.now() - tWit },
      }
    }
    const p = proveQueue.then(job, job)
    proveQueue = p.catch(() => {})
    return p
  }

  function runHelper(ss, challenge) {
    return new Promise((resolve, reject) => {
      const out = join(workDir, `out-${Math.random().toString(36).slice(2)}.json`)
      const args = [HELPER, '--pythonref', PYTHONREF, '--zeta', DEMO.zeta, '--ss', ss, '-o', out]
      if (challenge) args.push('--sign-challenge', challenge)
      execFile(PY, args, { timeout: 120_000 }, (err, _stdout, stderr) => {
        if (err) return reject(new Error(`helper failed: ${stderr || err.message}`))
        resolve(JSON.parse(readFileSync(out, 'utf8')))
      })
    })
  }

  // v0.0.10 hybrid helper — fixed demo identity, signs a challenge with the
  // blinded ML-DSA key for the deployed ZKNOX/kohaku Sepolia account.
  function runHybridHelper(challenge) {
    return new Promise((resolve, reject) => {
      const out = join(workDir, `hy-${Math.random().toString(36).slice(2)}.json`)
      const args = [HYBRID_HELPER, '--pythonref', PYTHONREF, '-o', out]
      if (challenge) args.push('--sign-challenge', challenge)
      execFile(PY, args, { timeout: 120_000 }, (err, _stdout, stderr) => {
        if (err) return reject(new Error(`hybrid helper failed: ${stderr || err.message}`))
        resolve(JSON.parse(readFileSync(out, 'utf8')))
      })
    })
  }
  let hybridDemo = null

  const server = createServer(async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*')
    res.setHeader('Access-Control-Allow-Headers', 'content-type')
    if (req.method === 'OPTIONS') {
      res.writeHead(204)
      return res.end()
    }
    if (req.method === 'GET') {
      res.writeHead(200)
      return res.end('{"ok":true}')
    }
    let body = ''
    req.on('data', (c) => {
      body += c
    })
    req.on('end', async () => {
      try {
        const { ss, challenge, sigHash, opener, commitment } = JSON.parse(body || '{}')
        const json = (obj) => {
          res.writeHead(200, { 'content-type': 'application/json' })
          res.end(JSON.stringify(obj))
        }
        // --- ZK SPHINCS- route: C13 key of the demo recipient, and proofs ---
        if (req.url === '/c13/key') {
          const k = await c13Key()
          return json({ pk_seed: k.seed, pk_root: k.root, key: k.seed.slice(0, 34) + k.root.slice(2, 34), signer: !!SIGNER_C13 })
        }
        if (req.url === '/prove-c13') {
          if (!SIGNER_C13) throw new Error('SIGNER_C13 is not set: build lfglabs-dev/SPHINCS- signer-c13 and export its path')
          if (!HEX32.test(sigHash ?? '')) throw new Error('sigHash must be 32 bytes hex')
          if (!HEX32.test(opener ?? '')) throw new Error('opener must be 32 bytes hex')
          if (!HEX32.test(commitment ?? '')) throw new Error('commitment must be 32 bytes hex')
          return json(await proveC13(sigHash, opener, commitment))
        }
        // --- local Stealth7913 route (df999ed 7913-native) ---
        if (req.url === '/derive') {
          if (!HEX32.test(ss ?? '')) throw new Error('ss must be 32 bytes hex')
          if (!deriveCache.has(ss)) deriveCache.set(ss, await runHelper(ss, null))
          return json(deriveCache.get(ss))
        }
        if (req.url === '/sign') {
          if (!HEX32.test(ss ?? '')) throw new Error('ss must be 32 bytes hex')
          if (!HEX32.test(challenge ?? '')) throw new Error('challenge must be 32 bytes hex')
          return json(await runHelper(ss, challenge))
        }
        // --- deployed ZKNOX/kohaku hybrid route (fixed demo identity) ---
        if (req.url === '/hybrid/derive') {
          if (!hybridDemo) hybridDemo = await runHybridHelper(null)
          return json({
            public_key_data: hybridDemo.public_key_data,
            kem_ct: hybridDemo.kem_ct,
            view_tag: hybridDemo.view_tag,
            stealth_pk: hybridDemo.stealth_pk,
          })
        }
        if (req.url === '/hybrid/sign') {
          if (!HEX32.test(challenge ?? '')) throw new Error('challenge must be 32 bytes hex')
          return json({ sig: (await runHybridHelper(challenge)).sig })
        }
        throw new Error(`unknown endpoint ${req.url}`)
      } catch (e) {
        res.writeHead(400, { 'content-type': 'text/plain' })
        res.end(e instanceof Error ? e.message : String(e))
      }
    })
  })
  server.listen(port, '127.0.0.1')
  return server
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  startSignerService()
  console.log(`signer service on http://127.0.0.1:${SIGNER_PORT} (python: ${PY}) — Ctrl-C stops it`)
}
