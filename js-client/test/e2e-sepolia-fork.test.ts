/**
 * Sepolia FORK rehearsal — the full flow against the REAL deployed
 * contracts, on a local anvil fork. No private key, no cost. This is the
 * compatibility gate to pass before touching a funded key:
 *
 *   1. announce a stealth payment on the canonical ERC-5564 announcer
 *   2. scan the announcement back with the TS client
 *   3. counterfactual account address from the deployed ZKNOX factory
 *   4. setKey + verify the blinded-key signature against the DEPLOYED
 *      ZKNOX MLDSA verifier (v0.0.10 on Sepolia — older than the git HEAD
 *      we tested locally, hence this rehearsal)
 *
 * Requires network access to a Sepolia RPC (SEPOLIA_RPC_URL overrides).
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { createPublicClient, createWalletClient, http, getAddress, type Hex, type Address } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { sepolia } from 'viem/chains';

import { decodeMetaAddress, scan } from '../src/scheme.ts';
import { SEPOLIA, ANNOUNCER_ABI, ZKNOX_VERIFIER_ABI, FACTORY_ABI, SCHEME_ID } from '../src/sepolia.ts';

const PORT = 8549;
const PROXY_PORT = 9545;
const RPC = `http://127.0.0.1:${PORT}`;
// anvil's own HTTP client can't reach remote RPCs on this network; fork
// through the local Node proxy (scripts/rpc-proxy.mjs) instead
const UPSTREAM = process.env.SEPOLIA_RPC_URL ?? 'https://sepolia.drpc.org';
const ANVIL_KEY =
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const PRE_QUANTUM_PUBKEY = '0x1111111111111111111111111111111111111111' as Hex;

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const demo = JSON.parse(
  readFileSync(here('../../python/scripts/zknox_demo.json'), 'utf8'));
const vectors = JSON.parse(
  readFileSync(here('../../python/vectors/v0/vectors.json'), 'utf8'));
const unhex = (s: string): Uint8Array =>
  Uint8Array.from(Buffer.from(s.slice(2), 'hex'));

test('sepolia fork: announce, scan, counterfactual, on-chain verify', async () => {
  const proxy = spawn(process.execPath,
    [here('../scripts/rpc-proxy.mjs'), '--port', String(PROXY_PORT),
     '--upstream', UPSTREAM], { stdio: 'ignore' });
  await new Promise((r) => setTimeout(r, 500));
  const anvil = spawn('anvil',
    ['--port', String(PORT), '--fork-url', `http://127.0.0.1:${PROXY_PORT}`,
     '--silent'],
    { stdio: 'ignore' });
  try {
    const publicClient = createPublicClient({ chain: sepolia, transport: http(RPC) });
    for (let i = 0; ; i++) {
      try { await publicClient.getBlockNumber(); break; }
      catch (e) {
        if (i > 300) throw new Error(`anvil fork did not start: ${(e as Error).message}`);
        await new Promise((r) => setTimeout(r, 200));
      }
    }
    const wallet = createWalletClient({
      chain: sepolia, transport: http(RPC),
      account: privateKeyToAccount(ANVIL_KEY),
    });

    // -- 1. announce on the CANONICAL ERC-5564 announcer ------------------
    const ann = vectors.cases[0].announcement;
    const announceHash = await wallet.writeContract({
      address: SEPOLIA.erc5564Announcer, abi: ANNOUNCER_ABI,
      functionName: 'announce',
      args: [SCHEME_ID, getAddress(ann.stealth_address),
        ann.ephemeral_pub_key as Hex, ann.view_tag as Hex],
    });
    const annRcpt = await publicClient.waitForTransactionReceipt(
      { hash: announceHash });
    assert.equal(annRcpt.status, 'success');
    console.log(`    announce gas (canonical announcer): ${annRcpt.gasUsed}`);

    // -- 2. scan it back with the client ----------------------------------
    const logs = await publicClient.getLogs({
      address: SEPOLIA.erc5564Announcer, event: ANNOUNCER_ABI[0],
      args: { schemeId: SCHEME_ID }, fromBlock: annRcpt.blockNumber,
    });
    assert.equal(logs.length, 1);
    const recA = vectors.recipients.A;
    const hits = scan(decodeMetaAddress(unhex(recA.meta_address)),
      unhex(recA.kem_dk), logs.map((l) => ({
        stealthAddress: unhex(l.args.stealthAddress!.toLowerCase()),
        ephemeralPubKey: unhex(l.args.ephemeralPubKey!),
        viewTag: unhex(l.args.metadata!).slice(0, 1),
      })));
    assert.equal(hits.length, 1, 'client must detect the announced payment');

    // -- 3. counterfactual address from the DEPLOYED factory --------------
    const counterfactual = await publicClient.readContract({
      address: SEPOLIA.zknoxMldsaK1Factory, abi: FACTORY_ABI,
      functionName: 'getAddress',
      args: [PRE_QUANTUM_PUBKEY, demo.public_key_data as Hex],
    }) as Address;
    assert.ok(/^0x[0-9a-fA-F]{40}$/.test(counterfactual));
    console.log(`    counterfactual account (deployed factory): ${counterfactual}`);

    // -- 4. blinded sig against the DEPLOYED verifier ---------------------
    const { result: pkPointer } = await publicClient.simulateContract({
      address: SEPOLIA.zknoxMldsaVerifier, abi: ZKNOX_VERIFIER_ABI,
      functionName: 'setKey', args: [demo.public_key_data as Hex],
      account: wallet.account,
    }) as { result: Hex };
    const setKeyHash = await wallet.writeContract({
      address: SEPOLIA.zknoxMldsaVerifier, abi: ZKNOX_VERIFIER_ABI,
      functionName: 'setKey', args: [demo.public_key_data as Hex],
      gas: 30_000_000n,
    });
    const setKeyRcpt = await publicClient.waitForTransactionReceipt(
      { hash: setKeyHash });
    assert.equal(setKeyRcpt.status, 'success');
    console.log(`    setKey gas (deployed verifier): ${setKeyRcpt.gasUsed}`);

    const ok = await publicClient.readContract({
      address: SEPOLIA.zknoxMldsaVerifier, abi: ZKNOX_VERIFIER_ABI,
      functionName: 'verify',
      args: [pkPointer, demo.challenge as Hex, demo.sig as Hex, '0x'],
    });
    assert.equal(ok, true,
      'blinded sig must verify against the verifier DEPLOYED on Sepolia');
    console.log('    deployed-verifier compatibility: OK');
  } finally {
    anvil.kill();
    proxy.kill();
  }
});
