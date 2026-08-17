/**
 * Proof: a ZKNOX account can be driven WITHOUT any classical signature.
 *
 * The ZKNOX_ERC4337_account is generic over two ISigVerifier logic slots and
 * AND-checks them. Every DEPLOYED factory wires slot 1 = ECDSA; but the
 * contract does not require that. Here we deploy our OWN factory instance
 * with the deployed ML-DSA verifier in BOTH slots, then spend with the
 * blinded stealth key signing both — no ECDSA anywhere in the authorization.
 *
 * Everything else (EntryPoint, the ML-DSA verifier, the account/factory
 * bytecode) is the real ZKNOX code, forked from Sepolia.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  createPublicClient, createWalletClient, http, parseEther, getAddress,
  encodeAbiParameters, type Hex, type Address,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { sepolia } from 'viem/chains';

import { SEPOLIA, FACTORY_ABI } from '../src/sepolia.ts';
import { startSepoliaFork } from './util/anvil.ts';
import {
  ENTRYPOINT_V07, ENTRYPOINT_ABI,
  buildSpendUserOp, signWithBlindedKey, requiredPrefund,
} from '../src/spend.ts';

const PORT = 8552;
const PROXY_PORT = 9548;
const ANVIL_KEY =
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const VERSION = 'pq-only-demo-v0';

const KOHAKU_OUT = process.env.KOHAKU_OUT
  ?? '/private/tmp/claude-501/-Users-skas-Ethereum-git-erc-5567/3bbf0a8c-f678-4091-af33-dbab7934a47e/scratchpad/kohaku/packages/pq-account/out';
const art = (rel: string) => JSON.parse(readFileSync(`${KOHAKU_OUT}/${rel}`, 'utf8'));

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const demo = JSON.parse(
  readFileSync(here('../../python/scripts/zknox_demo.json'), 'utf8'));

test('fork: spend a ZKNOX account with ML-DSA in BOTH slots — no ECDSA', {
  skip: !existsSync(KOHAKU_OUT) ? 'kohaku artifacts not built (KOHAKU_OUT)' : false,
}, async () => {
  const anvil = await startSepoliaFork(
    { port: PORT, proxyPort: PROXY_PORT, cache: 'sepolia-fork-pq-only' });
  console.log(`    fork mode: ${anvil.mode}`);
  try {
    const publicClient = createPublicClient({ chain: sepolia, transport: http(anvil.rpc) });
    const eoa = privateKeyToAccount(ANVIL_KEY);
    const wallet = createWalletClient({ chain: sepolia, transport: http(anvil.rpc), account: eoa });
    const deploy = async (a: { abi: unknown; bytecode: { object: Hex } }, args: unknown[]) => {
      const hash = await wallet.deployContract({ abi: a.abi as [], bytecode: a.bytecode.object, args });
      return (await publicClient.waitForTransactionReceipt({ hash })).contractAddress!;
    };

    // our own factory: BOTH verifier slots = the deployed ML-DSA verifier
    const mldsa = SEPOLIA.zknoxMldsaVerifier;
    const factory = await deploy(art('ZKNOX_PQFactory.sol/ZKNOX_AccountFactory.json'),
      [ENTRYPOINT_V07, mldsa, mldsa, VERSION]);
    console.log(`    dual-PQ factory: ${factory} (pre=post=ML-DSA ${mldsa})`);

    // both "keys" are the blinded stealth key's expanded pk
    const pqKey = demo.public_key_data as Hex;
    const account = await publicClient.readContract({
      address: factory, abi: FACTORY_ABI, functionName: 'getAddress',
      args: [pqKey, pqKey],
    }) as Address;

    // build the spend, fund exactly, deploy the account
    const recipient = getAddress('0x00000000000000000000000000000000cafebabe');
    const spendValue = parseEther('0.003');
    const op = await buildSpendUserOp(publicClient, account, recipient,
      spendValue, { verificationGas: 20_000_000n }); // two ML-DSA verifies
    const funding = spendValue + (requiredPrefund(op) * 12n) / 10n;
    await publicClient.waitForTransactionReceipt(
      { hash: await wallet.sendTransaction({ to: account, value: funding }) });
    await publicClient.waitForTransactionReceipt({
      hash: await wallet.writeContract({
        address: factory, abi: FACTORY_ABI, functionName: 'createAccount',
        args: [pqKey, pqKey], gas: 20_000_000n }) }); // two 22.4kB PQ keys

    // sign the userOpHash with the blinded ML-DSA key — used for BOTH slots
    const userOpHash = await publicClient.readContract({
      address: ENTRYPOINT_V07, abi: ENTRYPOINT_ABI,
      functionName: 'getUserOpHash', args: [op] }) as Hex;
    const pqSig = signWithBlindedKey(userOpHash);
    op.signature = encodeAbiParameters(
      [{ type: 'bytes' }, { type: 'bytes' }], [pqSig, pqSig]);
    console.log(`    signed userOpHash with blinded ML-DSA key (both slots)`);

    const before = await publicClient.getBalance({ address: recipient });
    const rcpt = await publicClient.waitForTransactionReceipt({
      hash: await wallet.writeContract({
        address: ENTRYPOINT_V07, abi: ENTRYPOINT_ABI, functionName: 'handleOps',
        args: [[op], eoa.address], gas: 28_000_000n }) });
    assert.equal(rcpt.status, 'success');
    const after = await publicClient.getBalance({ address: recipient });
    assert.equal(after - before, spendValue,
      'recipient must receive the value — spend authorized by ML-DSA only');
    console.log(`    handleOps gas: ${rcpt.gasUsed}`);
    console.log(`    SPENT with post-quantum signatures only — zero ECDSA ✔`);
  } finally {
    anvil.stop();
  }
});
