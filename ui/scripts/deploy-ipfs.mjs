#!/usr/bin/env node
/**
 * Publish the built UI (ui/dist) to IPFS through Pinata.
 *
 *   npm run build
 *   PINATA_JWT=eyJ… npm run deploy:ipfs            # upload dist/ → folder CID
 *   npm run deploy:ipfs -- --dry-run               # list what would be uploaded
 *
 * Environment (read from ../.env and ./.env via --env-file-if-exists):
 *   PINATA_JWT       required — API key JWT with pinFileToIPFS scope
 *                    (app.pinata.cloud → API Keys). Never pass it on the CLI.
 *   PINATA_GATEWAY   optional — your dedicated gateway host, e.g.
 *                    example.mypinata.cloud, used only for the printed URLs.
 *   PINATA_NAME      optional — pin name shown in the Pinata dashboard
 *                    (default: pq-stealth-ui-<git short sha>).
 *
 * The whole dist/ tree is uploaded as one directory so the result is a single
 * CID that serves index.html at its root; vite.config.ts sets base: './' so
 * the bundle works under /ipfs/<cid>/ on any gateway. Nothing is unpinned —
 * old versions stay reachable until you remove them in the dashboard.
 */

import { execSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = (p) => fileURLToPath(new URL(p, import.meta.url))
const DIST = here('../dist')
const ENDPOINT = 'https://api.pinata.cloud/pinning/pinFileToIPFS'
const dryRun = process.argv.includes('--dry-run')

if (!existsSync(join(DIST, 'index.html'))) {
  console.error('ui/dist/index.html not found — run: npm run build')
  process.exit(1)
}

const JWT = process.env.PINATA_JWT
if (!dryRun && !JWT) {
  console.error('Set PINATA_JWT (Pinata API key JWT) in ui/.env or the repo-root .env, or use --dry-run.')
  process.exit(1)
}

let sha = 'local'
try {
  sha = execSync('git rev-parse --short HEAD', { cwd: here('..'), stdio: ['ignore', 'pipe', 'ignore'] })
    .toString()
    .trim()
} catch {}
const folder = process.env.PINATA_NAME ?? `pq-stealth-ui-${sha}`

// Collect every file under dist/, posix-relative so the paths become the
// directory layout inside the pinned folder. Dotfiles (e.g. the .gitignore
// Vite copies from public/) are not part of the site.
const walk = (dir) =>
  readdirSync(dir, { withFileTypes: true }).flatMap((d) => {
    if (d.name.startsWith('.')) return []
    const p = join(dir, d.name)
    return d.isDirectory() ? walk(p) : [p]
  })
const files = walk(DIST).sort()
const relPath = (p) => relative(DIST, p).split(sep).join('/')
const total = files.reduce((n, p) => n + statSync(p).size, 0)

console.log(`${folder}: ${files.length} files, ${(total / 1024).toFixed(1)} KiB`)
for (const p of files) console.log(`  ${relPath(p)}  (${statSync(p).size} B)`)
if (files.some((p) => relPath(p) === 'dev-deployment.json')) {
  console.log('note: dev-deployment.json (local anvil addresses) is included; harmless, but delete it from ui/public first if unwanted.')
}
if (dryRun) {
  console.log('\n--dry-run: nothing uploaded.')
  process.exit(0)
}

const form = new FormData()
for (const p of files) {
  form.append('file', new File([readFileSync(p)], relPath(p)), `${folder}/${relPath(p)}`)
}
form.append('pinataMetadata', JSON.stringify({ name: folder, keyvalues: { app: 'pq-stealth-ui', commit: sha } }))
form.append('pinataOptions', JSON.stringify({ cidVersion: 1 }))

process.stdout.write('uploading to Pinata… ')
const res = await fetch(ENDPOINT, {
  method: 'POST',
  headers: { Authorization: `Bearer ${JWT}` },
  body: form,
})
const body = await res.text()
if (!res.ok) {
  console.error(`\nPinata returned ${res.status}: ${body}`)
  process.exit(1)
}
const { IpfsHash: cid, PinSize: size, isDuplicate } = JSON.parse(body)
console.log(`${cid}${isDuplicate ? ' (already pinned)' : ''} — ${size} B pinned`)

const gw = process.env.PINATA_GATEWAY
console.log(`
  ipfs://${cid}
  https://ipfs.io/ipfs/${cid}/
  https://${cid}.ipfs.dweb.link/${gw ? `\n  https://${gw}/ipfs/${cid}/` : ''}

ENS contenthash: ipfs://${cid}
The PQ spend route still needs the local signer service (npm run signer);
the classical route and everything else works straight from the gateway.`)
