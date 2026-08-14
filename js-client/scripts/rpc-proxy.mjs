#!/usr/bin/env node
/**
 * Minimal local JSON-RPC forward proxy.
 *
 * anvil's HTTP client cannot reach remote RPCs on some networks where
 * Node's fetch can (IPv6/DNS quirks). This forwards POSTs from localhost
 * to the upstream, so `anvil --fork-url http://127.0.0.1:<port>` works.
 *
 * Usage: node rpc-proxy.mjs [--port 9545] [--upstream https://sepolia.drpc.org]
 */

import { createServer } from 'node:http';

const args = process.argv.slice(2);
const flag = (name, dflt) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : dflt;
};
const PORT = Number(flag('port', '9545'));
const UPSTREAM = flag('upstream', 'https://sepolia.drpc.org');

createServer(async (req, res) => {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  try {
    const upstream = await fetch(UPSTREAM, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: Buffer.concat(chunks),
    });
    const body = Buffer.from(await upstream.arrayBuffer());
    res.writeHead(upstream.status, { 'content-type': 'application/json' });
    res.end(body);
  } catch (e) {
    res.writeHead(502, { 'content-type': 'application/json' });
    res.end(JSON.stringify({
      jsonrpc: '2.0', id: null,
      error: { code: -32000, message: `proxy: ${e.message}` },
    }));
  }
}).listen(PORT, '127.0.0.1', () => {
  console.log(`rpc-proxy on 127.0.0.1:${PORT} -> ${UPSTREAM}`);
});
