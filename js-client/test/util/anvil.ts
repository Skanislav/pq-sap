/**
 * Shared anvil plumbing for the e2e tests.
 *
 * Two entry points:
 *
 *   startAnvil()        — plain local chain (deterministic dev accounts)
 *   startSepoliaFork()  — Sepolia fork with a RECORD/REPLAY cache:
 *
 * The first run (or FORK_RECORD=1) forks upstream through
 * scripts/rpc-proxy.mjs pinned at a block, recording every upstream
 * response into test/state/<name>.rpc.json. Later runs replay from that
 * file — no network, no RPC quota, byte-identical fork state.
 *
 * Why not anvil_dumpState/--load-state for forks? Measured (anvil 1.4.1):
 * the dump only contains accounts touched by local TRANSACTIONS — state
 * reached only via eth_call/readContract is silently absent after reload,
 * and the chain id is not preserved either. Recording at the RPC boundary
 * is complete by construction. dump/load stays sound for non-fork chains.
 */

import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));

export interface Anvil {
  rpc: string;
  /** 'record' | 'replay' for forks, 'local' otherwise */
  mode: string;
  stop(): void;
}

async function waitHttp(url: string, tries: number, delayMs: number,
  post?: string): Promise<void> {
  for (let i = 0; ; i++) {
    try {
      const res = await fetch(url, post
        ? { method: 'POST', headers: { 'content-type': 'application/json' },
            body: post }
        : {});
      if (res.ok) return;
      throw new Error(`status ${res.status}`);
    } catch (e) {
      if (i >= tries) throw new Error(`${url} not up: ${(e as Error).message}`);
      await new Promise((r) => setTimeout(r, delayMs));
    }
  }
}

const waitRpc = (rpc: string, tries = 300, delayMs = 200) =>
  waitHttp(rpc, tries, delayMs,
    '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}');

/** Plain local anvil chain. */
export async function startAnvil(port: number,
  extraArgs: string[] = []): Promise<Anvil> {
  const proc = spawn('anvil',
    ['--port', String(port), '--silent', ...extraArgs], { stdio: 'ignore' });
  const rpc = `http://127.0.0.1:${port}`;
  try {
    await waitRpc(rpc, 50, 100);
  } catch (e) {
    proc.kill();
    throw e;
  }
  return { rpc, mode: 'local', stop: () => proc.kill() };
}

export interface ForkOptions {
  port: number;
  proxyPort: number;
  /** cache name — state lands in test/state/<name>.rpc.json */
  cache: string;
}

export async function startSepoliaFork(
  { port, proxyPort, cache }: ForkOptions): Promise<Anvil> {
  const cacheFile = here(`../state/${cache}.rpc.json`);
  const record = !!process.env.FORK_RECORD || !existsSync(cacheFile);
  // drpc dropped Sepolia from the free plan (2026-08); publicnode is fine
  // through the proxy (only anvil's OWN http client can't reach it)
  const upstream = process.env.SEPOLIA_RPC_URL
    ?? 'https://ethereum-sepolia-rpc.publicnode.com';

  let forkBlock: number;
  const proxyArgs = [here('../../scripts/rpc-proxy.mjs'),
    '--port', String(proxyPort), '--cache', cacheFile];
  if (record) {
    forkBlock = process.env.SEPOLIA_FORK_BLOCK
      ? Number(process.env.SEPOLIA_FORK_BLOCK)
      : await latestBlock(upstream) - 5; // small reorg-safety margin
    proxyArgs.push('--mode', 'record', '--upstream', upstream,
      '--meta', JSON.stringify({ block: forkBlock }));
  } else {
    forkBlock = JSON.parse(readFileSync(cacheFile, 'utf8')).meta.block;
    proxyArgs.push('--mode', 'replay');
  }

  const proxy = spawn(process.execPath, proxyArgs, { stdio: 'ignore' });
  const procs: ChildProcess[] = [proxy];
  const stop = () => { for (const p of procs) p.kill(); };
  const rpc = `http://127.0.0.1:${port}`;
  try {
    await waitHttp(`http://127.0.0.1:${proxyPort}`, 50, 100);
    procs.push(spawn('anvil',
      ['--port', String(port),
       '--fork-url', `http://127.0.0.1:${proxyPort}`,
       '--fork-block-number', String(forkBlock),
       '--silent'], { stdio: 'ignore' }));
    await waitRpc(rpc);
  } catch (e) {
    stop();
    throw e;
  }
  return { rpc, mode: record ? 'record' : 'replay', stop };
}

async function latestBlock(upstream: string): Promise<number> {
  const res = await fetch(upstream, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}',
  });
  const { result } = await res.json() as { result: string };
  return Number(result);
}
