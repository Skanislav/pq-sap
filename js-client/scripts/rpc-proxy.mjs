#!/usr/bin/env node
/**
 * Minimal local JSON-RPC forward proxy, with record/replay.
 *
 * anvil's HTTP client cannot reach remote RPCs on some networks where
 * Node's fetch can (IPv6/DNS quirks). This forwards POSTs from localhost
 * to the upstream, so `anvil --fork-url http://127.0.0.1:<port>` works.
 *
 * With --cache it additionally makes fork runs reproducible:
 *   --mode record   forward to the upstream AND save every response,
 *                   keyed by (method, params), into the cache file
 *   --mode replay   serve ONLY from the cache file — no network at all;
 *                   a cache miss returns a JSON-RPC error (loud, not silent)
 *
 * Replay is exact as long as anvil forks at the same pinned block number
 * (the requests it makes are then deterministic). The block is stored in
 * the cache file's `meta` by whoever records (see test/util/anvil.ts).
 *
 * Usage: node rpc-proxy.mjs [--port 9545] [--upstream https://sepolia.drpc.org]
 *                           [--cache file.json] [--mode record|replay]
 *                           [--meta '{"block":123}']
 */

import { createServer } from 'node:http';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

const args = process.argv.slice(2);
const flag = (name, dflt) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : dflt;
};
const PORT = Number(flag('port', '9545'));
const UPSTREAM = flag('upstream', 'https://ethereum-sepolia-rpc.publicnode.com');
const CACHE = flag('cache', '');
const MODE = flag('mode', 'forward'); // forward | record | replay
const META = flag('meta', '');

const keyOf = (req) => `${req.method} ${JSON.stringify(req.params ?? [])}`;

const entries = new Map();
let meta = META ? JSON.parse(META) : {};
if (MODE === 'replay') {
  const saved = JSON.parse(readFileSync(CACHE, 'utf8'));
  meta = saved.meta ?? {};
  for (const [k, v] of Object.entries(saved.entries)) entries.set(k, v);
}

let dirty = false;
function flush() {
  if (MODE !== 'record' || !dirty) return;
  mkdirSync(dirname(CACHE), { recursive: true });
  writeFileSync(CACHE, JSON.stringify(
    { meta: { ...meta, upstream: UPSTREAM, recordedAt: new Date().toISOString() },
      entries: Object.fromEntries(entries) }, null, 1));
  dirty = false;
}
for (const sig of ['SIGTERM', 'SIGINT']) {
  process.on(sig, () => { flush(); process.exit(0); });
}
process.on('exit', flush);

/** Answer one JSON-RPC request object from the cache (replay mode). */
const fromCache = (req) => {
  const hit = entries.get(keyOf(req));
  if (hit === undefined) {
    return { jsonrpc: '2.0', id: req.id, error: { code: -32000,
      message: `rpc-proxy replay: cache miss for ${keyOf(req)} — ` +
        're-record with FORK_RECORD=1 (test changed or anvil version differs)' } };
  }
  return { jsonrpc: '2.0', id: req.id, ...hit };
};

createServer(async (req, res) => {
  if (req.method === 'GET') { // health check for wait-until-ready
    res.writeHead(200); res.end('ok'); return;
  }
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const body = Buffer.concat(chunks);

  if (MODE === 'replay') {
    const parsed = JSON.parse(body.toString('utf8'));
    const answer = Array.isArray(parsed)
      ? parsed.map(fromCache) : fromCache(parsed);
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(answer));
    return;
  }

  try {
    const upstream = await fetch(UPSTREAM, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body,
    });
    const respBody = Buffer.from(await upstream.arrayBuffer());
    if (MODE === 'record' && upstream.ok) {
      const reqs = JSON.parse(body.toString('utf8'));
      const resps = JSON.parse(respBody.toString('utf8'));
      const pairs = Array.isArray(reqs)
        ? reqs.map((r) => [r, resps.find((x) => x.id === r.id)])
        : [[reqs, resps]];
      for (const [r, x] of pairs) {
        // don't poison the cache with upstream throttling errors
        if (!x || x.error) continue;
        entries.set(keyOf(r), { result: x.result });
        dirty = true;
      }
      flush();
    }
    res.writeHead(upstream.status, { 'content-type': 'application/json' });
    res.end(respBody);
  } catch (e) {
    res.writeHead(502, { 'content-type': 'application/json' });
    res.end(JSON.stringify({
      jsonrpc: '2.0', id: null,
      error: { code: -32000, message: `proxy: ${e.message}` },
    }));
  }
}).listen(PORT, '127.0.0.1', () => {
  console.log(`rpc-proxy on 127.0.0.1:${PORT} -> ` +
    (MODE === 'replay' ? `${CACHE} (offline replay)` : `${UPSTREAM} (${MODE})`));
});
