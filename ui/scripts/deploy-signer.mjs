#!/usr/bin/env node
/**
 * Deploy the blinded-key signer service to Railway.
 *
 *   npm run deploy:signer                 # stage + `railway up` + print the public URL
 *   npm run deploy:signer -- --stage-only # just assemble the build context and print its path
 *
 * Prerequisites: `railway login` done once, and the repo linked to a project
 * (`railway init -n pq-stealth-signer` from the repo root, or `railway link`).
 * The service name defaults to "signer" (override with RAILWAY_SERVICE).
 *
 * Why staging: the repo checkout is huge (lean, wiki, vendored libs), so
 * instead of `railway up` from the root, the handful of files the container
 * needs are copied to a temp dir and uploaded with --path-as-root:
 *   ui/signer/Dockerfile, python/scripts/, ui/scripts/signer-service.mjs
 *
 * After a successful deploy the printed https URL is written into
 * ui/public/sepolia-deployment.json (signerService) so the next `npm run build`
 * targets it. Pass --keep-local to skip that.
 */

import { execFileSync, spawnSync } from 'node:child_process'
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = (p) => fileURLToPath(new URL(p, import.meta.url))
const args = process.argv.slice(2)
const stageOnly = args.includes('--stage-only')
const keepLocal = args.includes('--keep-local')
const service = process.env.RAILWAY_SERVICE ?? 'signer'

// --- stage ---------------------------------------------------------------
const stage = mkdtempSync(join(tmpdir(), 'pq-signer-ctx-'))
cpSync(here('../signer/Dockerfile'), join(stage, 'Dockerfile'))
cpSync(here('../../python/scripts'), join(stage, 'python/scripts'), {
  recursive: true,
  filter: (src) => !src.includes('__pycache__'),
})
mkdirSync(join(stage, 'ui/scripts'), { recursive: true })
cpSync(here('signer-service.mjs'), join(stage, 'ui/scripts/signer-service.mjs'))
console.log(`build context: ${stage}`)
if (stageOnly) process.exit(0)

// --- deploy --------------------------------------------------------------
const railway = (cmdArgs, opts = {}) => {
  const r = spawnSync('railway', cmdArgs, { stdio: 'inherit', cwd: here('..'), ...opts })
  if (r.status !== 0) {
    console.error(`railway ${cmdArgs.join(' ')} failed (exit ${r.status})`)
    process.exit(r.status ?? 1)
  }
}

railway(['up', stage, '--path-as-root', '--service', service, '--ci'])

// --- public URL ----------------------------------------------------------
let domain = null
try {
  const out = execFileSync('railway', ['domain', '--service', service, '--json'], {
    cwd: here('..'),
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'inherit'],
  })
  const j = JSON.parse(out)
  domain = j.domain ?? j.serviceDomain ?? (Array.isArray(j) ? j[0]?.domain : null) ?? null
} catch {}
if (!domain) {
  console.log(`\nDeployed. Could not read the service domain; run: railway domain --service ${service}`)
  process.exit(0)
}
const url = `https://${domain.replace(/^https?:\/\//, '').replace(/\/$/, '')}`
console.log(`\nsigner: ${url}   (GET / → {"ok":true} once the container is up)`)

if (!keepLocal) {
  // both hosted-chain routes call the signer: Sepolia (zknox-hybrid) and the frames testnet (stealth8141)
  for (const name of ['sepolia-deployment.json', 'frames-deployment.json']) {
    const file = here(`../public/${name}`)
    if (!existsSync(file)) continue
    const dep = JSON.parse(readFileSync(file, 'utf8'))
    dep.signerService = url
    writeFileSync(file, JSON.stringify(dep, null, 2) + '\n')
    console.log(`ui/public/${name}: signerService → ${url}`)
  }
}
