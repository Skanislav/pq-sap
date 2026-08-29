#!/usr/bin/env node
/**
 * Blinded-key signer service (localhost only) — wraps the Python helper
 * (python/scripts/spendable_helper.py) for the PQ spend route:
 *
 *   POST /derive {ss}            -> {view_tag, stealth_pk, public_key_data}
 *   POST /sign   {ss, challenge} -> {sig, ...}
 *
 * The blinded secret never leaves the Python process; only public outputs
 * and signatures are returned. Started automatically by dev-chain.mjs;
 * run standalone (`npm run signer`) when spending on Sepolia.
 */

import { execFile } from 'node:child_process'
import { mkdtempSync, readFileSync } from 'node:fs'
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
        const { ss, challenge } = JSON.parse(body || '{}')
        const json = (obj) => {
          res.writeHead(200, { 'content-type': 'application/json' })
          res.end(JSON.stringify(obj))
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
