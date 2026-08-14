/**
 * Sepolia FORK rehearsal of the full receive -> SPEND cycle against the
 * real deployed contracts (no key, no cost):
 *
 *   1. fresh counterfactual stealth account (pre-quantum key we control)
 *   2. announce it on the canonical ERC-5564 announcer + fund it (the
 *      "self-send"), createAccount via the deployed ZKNOX factory
 *   3. build a v0.7 UserOp: execute(recipient, 0.005 ETH, ""), hash via
 *      the canonical EntryPoint, sign with ECDSA + the BLINDED stealth key
 *   4. submit self-bundled through EntryPoint.handleOps and assert the
 *      recipient received the funds — a post-quantum stealth SPEND
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { createPublicClient, createWalletClient, http, parseEther, getAddress, type Hex, type Address } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { sepolia } from 'viem/chains';

import { SEPOLIA, ANNOUNCER_ABI, FACTORY_ABI, SCHEME_ID } from '../src/sepolia.ts';
import {
  ENTRYPOINT_V07, ENTRYPOINT_ABI, preQuantumDemoKey,
  buildSpendUserOp, signUserOp, requiredPrefund,
} from '../src/spend.ts';

const PORT = 8550;
const PROXY_PORT = 9546;
const RPC = `http://127.0.0.1:${PORT}`;
const UPSTREAM = process.env.SEPOLIA_RPC_URL ?? 'https://sepolia.drpc.org';
const ANVIL_KEY =
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const demo = JSON.parse(
  readFileSync(here('../../python/scripts/zknox_demo.json'), 'utf8'));

test('sepolia fork: fund, deploy, and SPEND from the stealth account', async () => {
  const proxy = spawn(process.execPath,
    [here('../scripts/rpc-proxy.mjs'), '--port', String(PROXY_PORT),
     '--upstream', UPSTREAM], { stdio: 'ignore' });
  await new Promise((r) => setTimeout(r, 500));
  const anvil = spawn('anvil',
    ['--port', String(PORT), '--fork-url', `http://127.0.0.1:${PROXY_PORT}`,
     '--silent'], { stdio: 'ignore' });
  try {
    const publicClient = createPublicClient({ chain: sepolia, transport: http(RPC) });
    for (let i = 0; ; i++) {
      try { await publicClient.getBlockNumber(); break; }
      catch (e) {
        if (i > 300) throw new Error(`anvil fork did not start: ${(e as Error).message}`);
        await new Promise((r) => setTimeout(r, 200));
      }
    }
    const eoa = privateKeyToAccount(ANVIL_KEY);
    const wallet = createWalletClient({
      chain: sepolia, transport: http(RPC), account: eoa,
    });

    // -- 1. fresh counterfactual with a pre-quantum key we control --------
    const preQ = preQuantumDemoKey();
    const stealthAccount = await publicClient.readContract({
      address: SEPOLIA.zknoxMldsaK1Factory, abi: FACTORY_ABI,
      functionName: 'getAddress',
      args: [preQ.address, demo.public_key_data as Hex],
    }) as Address;
    console.log(`    spendable stealth account: ${stealthAccount}`);

    // -- 2. announce (the self-send), fund, deploy ------------------------
    const annHash = await wallet.writeContract({
      address: SEPOLIA.erc5564Announcer, abi: ANNOUNCER_ABI,
      functionName: 'announce',
      args: [SCHEME_ID, stealthAccount, demo.kem_ct as Hex,
        demo.view_tag as Hex],
    });
    await publicClient.waitForTransactionReceipt({ hash: annHash });

    // build the op first so the funding covers the exact prefund
    const recipient = getAddress('0x00000000000000000000000000000000cafebabe');
    const spendValue = parseEther('0.005');
    const op = await buildSpendUserOp(
      publicClient, stealthAccount, recipient, spendValue);
    const prefund = requiredPrefund(op);
    const funding = spendValue + (prefund * 12n) / 10n;
    console.log(`    prefund ${prefund} wei -> funding with ${funding} wei`);

    const fundHash = await wallet.sendTransaction({
      to: stealthAccount, value: funding });
    await publicClient.waitForTransactionReceipt({ hash: fundHash });

    const createHash = await wallet.writeContract({
      address: SEPOLIA.zknoxMldsaK1Factory, abi: FACTORY_ABI,
      functionName: 'createAccount',
      args: [preQ.address, demo.public_key_data as Hex], gas: 10_000_000n,
    });
    const createRcpt = await publicClient.waitForTransactionReceipt(
      { hash: createHash });
    assert.equal(createRcpt.status, 'success');
    console.log(`    createAccount gas: ${createRcpt.gasUsed}`);

    // -- 3. hybrid-sign the spend UserOp ----------------------------------
    const userOpHash = await publicClient.readContract({
      address: ENTRYPOINT_V07, abi: ENTRYPOINT_ABI,
      functionName: 'getUserOpHash', args: [op],
    }) as Hex;
    op.signature = await signUserOp(userOpHash);
    console.log(`    userOpHash: ${userOpHash}`);

    // -- 4. self-bundle through the canonical EntryPoint ------------------
    const before = await publicClient.getBalance({ address: recipient });
    const opsHash = await wallet.writeContract({
      address: ENTRYPOINT_V07, abi: ENTRYPOINT_ABI,
      functionName: 'handleOps', args: [[op], eoa.address],
      gas: 11_000_000n,
    });
    const opsRcpt = await publicClient.waitForTransactionReceipt(
      { hash: opsHash });
    assert.equal(opsRcpt.status, 'success');
    console.log(`    handleOps gas: ${opsRcpt.gasUsed}`);

    const after = await publicClient.getBalance({ address: recipient });
    assert.equal(after - before, spendValue,
      'recipient must receive the spent value');
    console.log(`    SPENT ${spendValue} wei from the stealth account ✔`);
  } finally {
    anvil.kill();
    proxy.kill();
  }
});
