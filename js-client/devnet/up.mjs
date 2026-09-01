#!/usr/bin/env node
// Bring up the EIP-8141 two-client frame-tx enclave (T-enc) and record its
// endpoints. Wraps `kurtosis run github.com/ethpandaops/ethereum-package`.
//
//   node devnet/up.mjs            # start (idempotent-ish: down first if --clean)
//   node devnet/up.mjs --clean    # tear the enclave down first, then start
//
// Writes devnet/enclave.json: { enclave, chainId, nethermind: {rpc}, ethrex: {rpc} }.
// The frame-tx client (src/frame-tx/chains.ts) and the e2e tests read that file.
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const ENCLAVE = 'frames';
const PARAMS = join(HERE, 'network_params.yaml');
const CHAIN_ID = 3151908; // ethereum-package default network_id

const sh = (bin, args, opts = {}) =>
  execFileSync(bin, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'], ...opts });

if (process.argv.includes('--clean')) {
  try { sh('kurtosis', ['enclave', 'rm', '-f', ENCLAVE]); } catch { /* not present */ }
}

console.error(`[up] kurtosis run ethereum-package into enclave "${ENCLAVE}" …`);
sh('kurtosis', [
  'run', '--enclave', ENCLAVE,
  'github.com/ethpandaops/ethereum-package',
  '--args-file', PARAMS,
], { stdio: 'inherit' });

// Pull the mapped host RPC ports back out of the enclave inspection.
const inspect = sh('kurtosis', ['enclave', 'inspect', ENCLAVE, '-o', 'json']);
const data = JSON.parse(inspect);

// Service names look like `el-1-nethermind-lighthouse`, `el-2-ethrex-lighthouse`.
// Find each EL's public rpc (port name "rpc") host:port.
function rpcFor(elType) {
  const svcs = data.user_services ?? data.services ?? {};
  for (const [name, svc] of Object.entries(svcs)) {
    if (!name.startsWith('el-') || !name.includes(elType)) continue;
    const ports = svc.ports ?? svc.public_ports ?? {};
    const rpc = ports.rpc ?? ports['rpc'];
    if (rpc) {
      const host = rpc.host ?? '127.0.0.1';
      const port = rpc.number ?? rpc.port;
      return `http://${host}:${port}`;
    }
  }
  return null;
}

const out = {
  enclave: ENCLAVE,
  chainId: CHAIN_ID,
  nethermind: { rpc: rpcFor('nethermind') },
  ethrex: { rpc: rpcFor('ethrex') },
};
if (!out.nethermind.rpc || !out.ethrex.rpc) {
  console.error('[up] WARNING: could not resolve both RPCs from `kurtosis enclave inspect`.');
  console.error('[up] Run `kurtosis enclave inspect frames` and fill devnet/enclave.json by hand.');
}
const dest = join(HERE, 'enclave.json');
writeFileSync(dest, JSON.stringify(out, null, 2) + '\n');
console.error(`[up] wrote ${dest}:`);
console.error(JSON.stringify(out, null, 2));
