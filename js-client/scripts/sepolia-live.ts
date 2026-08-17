#!/usr/bin/env node --env-file-if-exists=.env
/**
 * Live Sepolia runner for the PQ stealth flow. Spends real (test) ETH —
 * every write step is opt-in via the command line.
 *
 * Setup:  put SEPOLIA_PRIVATE_KEY=0x... in js-client/.env (gitignored)
 * Usage:  node scripts/sepolia-live.ts <step...>
 *   precheck   read-only: balance, contract code, counterfactual address
 *   announce   announce the demo stealth payment on the CANONICAL announcer
 *   scan       scan recent announcer logs for our payment (read-only)
 *   verify     setKey (1 tx, ~5.2M gas) + verify blinded sig (read-only)
 *   account    createAccount on the deployed ZKNOX factory (~6.2M gas)
 *   all        precheck announce scan verify account
 *
 * Rehearsed first on an anvil fork — see test/e2e-sepolia-fork.test.ts.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { createPublicClient, createWalletClient, http, getAddress, formatEther, type Hex, type Address } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { sepolia } from 'viem/chains';

import { decodeMetaAddress, scan } from '../src/scheme.ts';
import { SEPOLIA, ANNOUNCER_ABI, ZKNOX_VERIFIER_ABI, FACTORY_ABI, SCHEME_ID } from '../src/sepolia.ts';
import {
  ENTRYPOINT_V07, ENTRYPOINT_ABI, preQuantumDemoKey,
  buildSpendUserOp, signUserOp, requiredPrefund,
} from '../src/spend.ts';

// drpc dropped Sepolia from the free plan (2026-08)
const RPC = process.env.SEPOLIA_RPC_URL
  ?? 'https://ethereum-sepolia-rpc.publicnode.com';
const PRE_QUANTUM_PUBKEY = '0x1111111111111111111111111111111111111111' as Hex;
const ETHERSCAN = 'https://sepolia.etherscan.io';

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const demo = JSON.parse(
  readFileSync(here('../../python/scripts/zknox_demo.json'), 'utf8'));
const vectors = JSON.parse(
  readFileSync(here('../../python/vectors/v0/vectors.json'), 'utf8'));
const unhex = (s: string): Uint8Array =>
  Uint8Array.from(Buffer.from(s.slice(2), 'hex'));

const steps = process.argv.slice(2).flatMap((s) =>
  s === 'all' ? ['precheck', 'announce', 'scan', 'verify', 'account'] : [s]);
if (steps.length === 0) steps.push('precheck');

const publicClient = createPublicClient({ chain: sepolia, transport: http(RPC) });

function wallet() {
  const key = process.env.SEPOLIA_PRIVATE_KEY;
  if (!key) throw new Error(
    'SEPOLIA_PRIVATE_KEY not set — put it in js-client/.env');
  return createWalletClient({
    chain: sepolia, transport: http(RPC),
    account: privateKeyToAccount(key as Hex),
  });
}

async function send(label: string, req: {
  address: Address; abi: readonly unknown[]; functionName: string;
  args: readonly unknown[]; gas?: bigint;
}) {
  const w = wallet();
  const hash = await w.writeContract({ ...req, abi: req.abi as [] });
  console.log(`${label}: ${ETHERSCAN}/tx/${hash}`);
  const rcpt = await publicClient.waitForTransactionReceipt({ hash });
  console.log(`  status=${rcpt.status} gasUsed=${rcpt.gasUsed}`);
  if (rcpt.status !== 'success') throw new Error(`${label} reverted`);
  return rcpt;
}

const ann = vectors.cases[0].announcement;

for (const step of steps) {
  console.log(`\n== ${step} ==`);
  if (step === 'precheck') {
    for (const [name, addr] of Object.entries(SEPOLIA)) {
      if (name === 'chainId') continue;
      const code = await publicClient.getCode({ address: addr as Address });
      console.log(`${name} ${addr}: code ${((code?.length ?? 2) - 2) / 2} B`);
    }
    const counterfactual = await publicClient.readContract({
      address: SEPOLIA.zknoxMldsaK1Factory, abi: FACTORY_ABI,
      functionName: 'getAddress',
      args: [PRE_QUANTUM_PUBKEY, demo.public_key_data as Hex],
    });
    console.log(`counterfactual stealth account: ${counterfactual}`);
    if (process.env.SEPOLIA_PRIVATE_KEY) {
      const addr = wallet().account.address;
      const bal = await publicClient.getBalance({ address: addr });
      console.log(`funded account ${addr}: ${formatEther(bal)} ETH`);
      const gasPrice = await publicClient.getGasPrice();
      const worstCase = 67_580n + 5_195_801n + 6_200_000n;
      console.log(`gas price ${gasPrice} wei; full run ~${worstCase} gas`
        + ` ~= ${formatEther(worstCase * gasPrice)} ETH`);
    } else {
      console.log('(no SEPOLIA_PRIVATE_KEY set — read-only mode)');
    }
  } else if (step === 'announce') {
    await send('announce (canonical ERC-5564)', {
      address: SEPOLIA.erc5564Announcer, abi: ANNOUNCER_ABI,
      functionName: 'announce',
      args: [SCHEME_ID, getAddress(ann.stealth_address),
        ann.ephemeral_pub_key as Hex, ann.view_tag as Hex],
    });
  } else if (step === 'scan') {
    const latest = await publicClient.getBlockNumber();
    const RANGE = 9_900n; // free-tier RPCs cap getLogs at 10k blocks
    const logs = await publicClient.getLogs({
      address: SEPOLIA.erc5564Announcer, event: ANNOUNCER_ABI[0],
      args: { schemeId: SCHEME_ID }, fromBlock: latest - RANGE,
    });
    console.log(`${logs.length} announcement(s) with our scheme id in last ${RANGE} blocks`);
    const recA = vectors.recipients.A;
    const hits = scan(decodeMetaAddress(unhex(recA.meta_address)),
      unhex(recA.kem_dk), logs.map((l) => ({
        stealthAddress: unhex(l.args.stealthAddress!.toLowerCase()),
        ephemeralPubKey: unhex(l.args.ephemeralPubKey!),
        viewTag: unhex(l.args.metadata!).slice(0, 1),
      })));
    console.log(`recipient A detects ${hits.length} payment(s)`);
  } else if (step === 'verify') {
    const { result: pkPointer } = await publicClient.simulateContract({
      address: SEPOLIA.zknoxMldsaVerifier, abi: ZKNOX_VERIFIER_ABI,
      functionName: 'setKey', args: [demo.public_key_data as Hex],
      account: wallet().account,
    }) as { result: Hex };
    await send('setKey (deployed ZKNOX verifier)', {
      address: SEPOLIA.zknoxMldsaVerifier, abi: ZKNOX_VERIFIER_ABI,
      functionName: 'setKey', args: [demo.public_key_data as Hex],
      gas: 8_000_000n,
    });
    const ok = await publicClient.readContract({
      address: SEPOLIA.zknoxMldsaVerifier, abi: ZKNOX_VERIFIER_ABI,
      functionName: 'verify',
      args: [pkPointer, demo.challenge as Hex, demo.sig as Hex, '0x'],
    });
    console.log(`blinded-sig verification on Sepolia: ${ok}`);
    if (!ok) throw new Error('on-chain verification failed');
  } else if (step === 'account') {
    const predicted = await publicClient.readContract({
      address: SEPOLIA.zknoxMldsaK1Factory, abi: FACTORY_ABI,
      functionName: 'getAddress',
      args: [PRE_QUANTUM_PUBKEY, demo.public_key_data as Hex],
    }) as Address;
    await send('createAccount (deployed ZKNOX factory)', {
      address: SEPOLIA.zknoxMldsaK1Factory, abi: FACTORY_ABI,
      functionName: 'createAccount',
      args: [PRE_QUANTUM_PUBKEY, demo.public_key_data as Hex],
      gas: 10_000_000n,
    });
    const code = await publicClient.getCode({ address: predicted });
    console.log(`stealth account ${predicted}: code ${((code?.length ?? 2) - 2) / 2} B`);
    console.log(`${ETHERSCAN}/address/${predicted}`);
  } else if (step === 'spend') {
    // full receive->spend cycle on the spendABLE stealth account (fresh
    // counterfactual whose pre-quantum half we control; the demo pre-quantum
    // key is deterministic and PUBLIC — testnet only)
    const w = wallet();
    const preQ = preQuantumDemoKey();
    const stealthAccount = await publicClient.readContract({
      address: SEPOLIA.zknoxMldsaK1Factory, abi: FACTORY_ABI,
      functionName: 'getAddress',
      args: [preQ.address, demo.public_key_data as Hex],
    }) as Address;
    console.log(`spendable stealth account: ${stealthAccount}`);

    const recipient = w.account.address;  // spend back to the funded EOA
    const spendValue = 5_000_000_000_000_000n; // 0.005 ETH
    const op = await buildSpendUserOp(
      publicClient, stealthAccount, recipient, spendValue);
    const prefund = requiredPrefund(op);
    const needed = spendValue + (prefund * 12n) / 10n;

    // resumable: skip announce/fund/create if already done on-chain
    const already = await publicClient.getCode({ address: stealthAccount });
    if (!already || already.length <= 2) {
      await send('announce (self-send to spendable account)', {
        address: SEPOLIA.erc5564Announcer, abi: ANNOUNCER_ABI,
        functionName: 'announce',
        args: [SCHEME_ID, stealthAccount, demo.kem_ct as Hex,
          demo.view_tag as Hex],
      });
      await send('createAccount (deployed ZKNOX factory)', {
        address: SEPOLIA.zknoxMldsaK1Factory, abi: FACTORY_ABI,
        functionName: 'createAccount',
        args: [preQ.address, demo.public_key_data as Hex], gas: 10_000_000n,
      });
    } else {
      console.log('stealth account already deployed — skipping announce/create');
    }
    const bal0 = await publicClient.getBalance({ address: stealthAccount });
    if (bal0 < needed) {
      const funding = needed - bal0;
      console.log(`funding stealth account: +${formatEther(funding)} ETH`
        + ` (need ${formatEther(needed)}, have ${formatEther(bal0)})`);
      const fundHash = await w.sendTransaction(
        { to: stealthAccount, value: funding });
      console.log(`fund: ${ETHERSCAN}/tx/${fundHash}`);
      await publicClient.waitForTransactionReceipt({ hash: fundHash });
    } else {
      console.log(`stealth account already holds ${formatEther(bal0)} ETH`);
    }

    const userOpHash = await publicClient.readContract({
      address: ENTRYPOINT_V07, abi: ENTRYPOINT_ABI,
      functionName: 'getUserOpHash', args: [op],
    }) as Hex;
    console.log(`userOpHash: ${userOpHash} — signing with blinded key...`);
    op.signature = await signUserOp(userOpHash);

    await send('handleOps (SPEND from stealth account)', {
      address: ENTRYPOINT_V07, abi: ENTRYPOINT_ABI,
      functionName: 'handleOps', args: [[op], w.account.address],
      gas: 11_000_000n,  // fork showed ~8.4M; public RPCs cap the outer tx
    });
    const bal = await publicClient.getBalance({ address: stealthAccount });
    console.log(`stealth account balance after spend: ${formatEther(bal)} ETH`);
  } else {
    throw new Error(`unknown step: ${step}`);
  }
}
