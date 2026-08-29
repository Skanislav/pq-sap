/**
 * Headless end-to-end over the running dev chain (`npm run chain`):
 * exercises the same code paths the UI runs.
 *
 *   1. ML-DSA-65 discovery: scan finds the 2 seeded payments; send a fresh
 *      one; rescan finds 3 (Recipient/Send/Scan tabs)
 *   2. classical hybrid: scan finds the 2 seeded spendable EOAs; SPEND from
 *      one with the derived key — plain ECDSA transaction (Spend tab §1)
 *   3. PQ route: scan detects the seeded counterfactual-account payment,
 *      deploys the account via the factory, signs the userOp with the
 *      blinded ML-DSA key (signer service), submits handleOps (Spend tab §2)
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

import {
  createPublicClient, createWalletClient, http, getAddress, parseEther,
  formatEther, parseAbiItem, type Address, type Hex,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';
import { ml_kem512, ml_kem768 } from '@noble/post-quantum/ml-kem.js';

import {
  decodeMetaAddress, deriveStealthPk, stealthAddressOf, computeViewTag,
  scan, type AnnouncementData,
} from '../../js-client/src/scheme.ts';
import { ANNOUNCER_ABI } from '../../js-client/src/sepolia.ts';
import { deriveMetaAddress } from '../src/lib/keygen.ts';
import {
  deriveClassicalKeys, decodeClassicalMeta, checkClassicalAnnouncement,
  deriveStealthPrivkey, encodeCompactMeta, decodeCompactMeta,
} from '../src/lib/classical.ts';
import { resolveCompactMeta } from '../src/lib/registry.ts';
import {
  decodePublicKeyData, buildSpendUserOp, spendableViewTag,
  ENTRYPOINT_ABI, FACTORY_ABI, type DevDeployment,
} from '../src/lib/spend4337.ts';
import { fromHex, toHex } from '../src/lib/hex.ts';

const RPC = 'http://127.0.0.1:8545';
const ANNOUNCER = '0x5FbDB2315678afecb367f032d93F642f64180aa3' as const;
const DEV_KEY =
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' as const;
const SCHEME_ID = 2n;

const EVENT = parseAbiItem(
  'event Announcement(uint256 indexed schemeId, address indexed stealthAddress, address indexed caller, bytes ephemeralPubKey, bytes metadata)');

const load = (rel: string) => JSON.parse(readFileSync(
  fileURLToPath(new URL(rel, import.meta.url)), 'utf8'));
const vectors = load('../../python/vectors/v0/vectors.json');
const classicalVectors = load('../../python/vectors/classical/v0/vectors.json');
const deployment = load('../public/dev-deployment.json') as DevDeployment;

const publicClient = createPublicClient({ chain: foundry, transport: http(RPC) });
const walletClient = createWalletClient({
  chain: foundry, transport: http(RPC), account: privateKeyToAccount(DEV_KEY) });

interface RawAnnouncement extends AnnouncementData { txHash: string }

async function fetchAnnouncements(): Promise<RawAnnouncement[]> {
  const logs = await publicClient.getLogs({
    address: ANNOUNCER, event: EVENT, args: { schemeId: SCHEME_ID }, fromBlock: 0n });
  return logs.map((l) => ({
    stealthAddress: fromHex(l.args.stealthAddress!.toLowerCase()),
    ephemeralPubKey: fromHex(l.args.ephemeralPubKey!),
    viewTag: fromHex(l.args.metadata!).slice(0, 1),
    txHash: l.transactionHash,
  }));
}

// ---------------------------------------------------------------------------
// 1. ML-DSA-65 discovery loop
// ---------------------------------------------------------------------------
{
  const seeds = vectors.recipients.A.seeds;
  const keys = deriveMetaAddress({
    zeta: fromHex(seeds.zeta), kemD: fromHex(seeds.kem_d), kemZ: fromHex(seeds.kem_z) });
  const meta = decodeMetaAddress(keys.metaAddress);

  const scanAll = async () => {
    const anns = await fetchAnnouncements();
    const hits = scan(meta, keys.kemDk, anns);
    return Promise.all(hits.map(async (h) => {
      const address = getAddress(toHex(h.announcement.stealthAddress));
      return { address, balance: await publicClient.getBalance({ address }) };
    }));
  };

  const initial = await scanAll();
  assert.equal(initial.length, 2, `expected 2 seeded 65-payments, got ${initial.length}`);
  const balances = initial.map((h) => formatEther(h.balance)).sort();
  assert.deepEqual(balances, ['0.5', '1.25']);
  console.log(`ml-dsa-65 scan: 2 seeded payments (${balances.join(', ')} ETH) ✓`);

  const { cipherText, sharedSecret } = ml_kem768.encapsulate(meta.kemEk);
  const stealthAddress = getAddress(toHex(stealthAddressOf(
    deriveStealthPk(meta.rho, meta.t, sharedSecret))));
  let h = await walletClient.sendTransaction({ to: stealthAddress, value: parseEther('0.33') });
  await publicClient.waitForTransactionReceipt({ hash: h });
  h = await walletClient.writeContract({
    address: ANNOUNCER, abi: ANNOUNCER_ABI, functionName: 'announce',
    args: [SCHEME_ID, stealthAddress, toHex(cipherText) as Hex,
      toHex(computeViewTag(sharedSecret)) as Hex] });
  await publicClient.waitForTransactionReceipt({ hash: h });

  const after = await scanAll();
  assert.equal(after.length, 3, `expected 3 after fresh send, got ${after.length}`);
  console.log('ml-dsa-65 send + rescan: fresh payment detected ✓');
}

// ---------------------------------------------------------------------------
// 2. classical hybrid: scan + EOA SPEND (the ecrecover trick)
// ---------------------------------------------------------------------------
{
  const seeds = classicalVectors.recipients.A.seeds;
  const keys = deriveClassicalKeys({
    spendSeed: fromHex(seeds.spend_seed),
    kemD: fromHex(seeds.kem_d), kemZ: fromHex(seeds.kem_z) });
  const fullMeta = decodeClassicalMeta(keys.metaAddress);

  // compact 65-byte meta-address: registry #0 holds A's viewing key, so
  // resolving (spend_pub || 0) must reconstruct the full key material
  const compactBytes = encodeCompactMeta(fullMeta.spendPub, 0n);
  const compact = decodeCompactMeta(compactBytes);
  const meta = await resolveCompactMeta(publicClient, deployment.registry, compact);
  assert.equal(toHex(meta.kemEk), toHex(fullMeta.kemEk),
    'registry-resolved viewing key must match the full meta-address');
  assert.equal(toHex(meta.spendPub), toHex(fullMeta.spendPub));
  console.log(`compact meta: registry #0 resolves to A's viewing key (65 B → 1,218 B) ✓`);

  const anns = await fetchAnnouncements();
  const hits = [];
  for (const ann of anns) {
    const p = checkClassicalAnnouncement(meta, keys.kemDk, ann);
    if (p) hits.push({ ann, ss: p.sharedSecret });
  }
  assert.equal(hits.length, 2, `expected 2 classical payments, got ${hits.length}`);
  const hit = hits[0]!;
  const stealthAddr = getAddress(toHex(hit.ann.stealthAddress));
  const before = await publicClient.getBalance({ address: stealthAddr });
  console.log(`classical scan: 2 spendable EOAs, first holds ${formatEther(before)} ETH ✓`);

  const priv = deriveStealthPrivkey(keys.seeds.spendSeed, hit.ss);
  const stealthAccount = privateKeyToAccount(toHex(priv) as Hex);
  assert.equal(stealthAccount.address, stealthAddr,
    'derived key must control the stealth EOA');
  const stealthWallet = createWalletClient({
    chain: foundry, transport: http(RPC), account: stealthAccount });
  const dest = getAddress('0x00000000000000000000000000000000CafeBabe');
  const destBefore = await publicClient.getBalance({ address: dest });
  const spendTx = await stealthWallet.sendTransaction({
    to: dest, value: parseEther('0.1') });
  const rcpt = await publicClient.waitForTransactionReceipt({ hash: spendTx });
  assert.equal(rcpt.status, 'success');
  assert.equal(rcpt.gasUsed, 21000n, 'plain EOA transfer must cost exactly 21k gas');
  const destAfter = await publicClient.getBalance({ address: dest });
  assert.equal(destAfter - destBefore, parseEther('0.1'));
  console.log(`classical SPEND: 0.1 ETH from the stealth EOA, ${rcpt.gasUsed} gas (ecrecover) ✓`);
}

// ---------------------------------------------------------------------------
// 3. PQ route: counterfactual account + blinded ML-DSA + 4337
// ---------------------------------------------------------------------------
{
  const kemSeed = new Uint8Array(64);
  kemSeed.set(fromHex(deployment.demo.kemD), 0);
  kemSeed.set(fromHex(deployment.demo.kemZ), 32);
  const demoKem = ml_kem512.keygen(kemSeed);

  const anns = await fetchAnnouncements();
  const hits: Array<{ ann: RawAnnouncement; ssHex: Hex; account: Address;
    pkArgs: ReturnType<typeof decodePublicKeyData> }> = [];
  for (const ann of anns) {
    if (ann.ephemeralPubKey.length !== 768) continue;
    let ss: Uint8Array;
    try { ss = ml_kem512.decapsulate(ann.ephemeralPubKey, demoKem.secretKey); }
    catch { continue; }
    if (toHex(spendableViewTag(ss)) !== toHex(ann.viewTag)) continue;
    const ssHex = toHex(ss) as Hex;
    const r = await fetch(`${deployment.signerService}/derive`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ss: ssHex }) });
    if (!r.ok) throw new Error(`derive service failed: ${await r.text()}`);
    const derived = await r.json() as { public_key_data: Hex };
    const pkArgs = decodePublicKeyData(derived.public_key_data);
    const account = await publicClient.readContract({
      address: deployment.factory, abi: FACTORY_ABI,
      functionName: 'getAccountAddress', args: pkArgs });
    if (account.toLowerCase() !== toHex(ann.stealthAddress)) continue;
    hits.push({ ann, ssHex, account, pkArgs });
  }
  assert.equal(hits.length, 1, `expected 1 pq-spendable payment, got ${hits.length}`);
  const hit = hits[0]!;
  const balance = await publicClient.getBalance({ address: hit.account });
  console.log(`pq scan: counterfactual account ${hit.account} holds ${formatEther(balance)} ETH ✓`);

  // deploy the account (PKContract + CREATE2)
  const createTx = await walletClient.writeContract({
    address: deployment.factory, abi: FACTORY_ABI, functionName: 'createAccount',
    args: hit.pkArgs, gas: 12_000_000n });
  const createRcpt = await publicClient.waitForTransactionReceipt({ hash: createTx });
  assert.equal(createRcpt.status, 'success');
  console.log(`pq spend: account deployed via factory (${createRcpt.gasUsed} gas) ✓`);

  // build + sign + submit the userOp
  const dest = getAddress('0x00000000000000000000000000000000DeadBeef');
  const op = await buildSpendUserOp(
    publicClient, deployment.entryPoint, hit.account, dest, parseEther('0.2'));
  const userOpHash = await publicClient.readContract({
    address: deployment.entryPoint, abi: ENTRYPOINT_ABI,
    functionName: 'getUserOpHash', args: [op] });
  const sr = await fetch(`${deployment.signerService}/sign`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ss: hit.ssHex, challenge: userOpHash }) });
  if (!sr.ok) throw new Error(`sign service failed: ${await sr.text()}`);
  const { sig } = await sr.json() as { sig: Hex };
  op.signature = sig;

  const destBefore = await publicClient.getBalance({ address: dest });
  const opsTx = await walletClient.writeContract({
    address: deployment.entryPoint, abi: ENTRYPOINT_ABI, functionName: 'handleOps',
    args: [[op], walletClient.account.address], gas: 25_000_000n });
  const opsRcpt = await publicClient.waitForTransactionReceipt({ hash: opsTx });
  assert.equal(opsRcpt.status, 'success', 'handleOps must succeed');
  const destAfter = await publicClient.getBalance({ address: dest });
  assert.equal(destAfter - destBefore, parseEther('0.2'),
    'destination must receive the spent value');
  console.log(`pq SPEND: 0.2 ETH via EntryPoint.handleOps, ${opsRcpt.gasUsed} gas ` +
    '(incl. on-chain blinded ML-DSA verify) ✓');
}

console.log('e2e smoke: OK');
