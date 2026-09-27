/**
 * `ml-dsa-44-commit/v0` on a local anvil, driven from TypeScript:
 *
 *   1. deploy the vendored ZKNOX ML-DSA-44 verifier (ETHDILITHIUM @ df999ed), the
 *      trusted key registry, the committed-key ERC-7913 signer, the frame adapter,
 *      a mock frame context and the (unchanged) Stealth8141ZkFactory
 *   2. TS `accountAddress` over the REAL creation code must equal the factory's
 *      counterfactual address for the fixture commitment (cross-language binding)
 *   3. key setup: register the recipient's expanded key (registrar = deployer)
 *   4. the payload verifies through the ERC-7913 signer and, after createAccount,
 *      spends through `executeFrame`; wrong digest and sender-derived key fail
 *
 * Fixture: python/scripts/mldsa44_commit_7913_demo.json. Requires
 * `npm run build-contracts` and `anvil` on PATH.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  createPublicClient, createTestClient, createWalletClient, decodeAbiParameters, http, parseEther, type Address, type Hex,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';

import { accountAddress, type Deployment } from '../src/commit-scheme.ts';
import { verifyAuthorization } from '../src/profiles.ts';
import { startAnvil } from './util/anvil.ts';

const PORT = 8557;
const ANVIL_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const ENTRY_POINT = '0x00000000000000000000000000000000000000aa' as Address;
const ERC7913_MAGIC = '0x024ad318';
const FAIL = '0xffffffff';

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const OUT = here('../contracts/out');
const artifact = (rel: string) => JSON.parse(readFileSync(`${OUT}/${rel}`, 'utf8'));
const fx = JSON.parse(readFileSync(here('../../python/scripts/mldsa44_commit_7913_demo.json'), 'utf8'));

test('ml-dsa-44-commit/v0: committed ML-DSA-44 key spends through the frame account on anvil', {
  skip: !existsSync(OUT) ? 'contracts not built (npm run build-contracts)' : false,
}, async () => {
  const dilithiumArt = artifact('ZKNOX_dilithium.sol/ZKNOX_dilithium.json');
  const registryArt = artifact('MlDsa44KeyRegistry.sol/TrustedMlDsa44KeyRegistry.json');
  const signerArt = artifact('MlDsa44CommitSigner7913.sol/MlDsa44CommitSigner7913.json');
  const adapterArt = artifact('MlDsa44CommitFrameVerifier.sol/MlDsa44CommitFrameVerifier.json');
  const ctxArt = artifact('ZkAccount.t.sol/MockFrameCtx.json');
  const factoryArt = artifact('Stealth8141ZkFactory.sol/Stealth8141ZkFactory.json');
  const accountArt = artifact('Stealth8141ZkAccount.sol/Stealth8141ZkAccount.json');

  const anvil = await startAnvil(PORT, ['--gas-limit', '60000000']);
  try {
    const publicClient = createPublicClient({ chain: foundry, transport: http(anvil.rpc) });
    const testClient = createTestClient({ chain: foundry, mode: 'anvil', transport: http(anvil.rpc) });
    const wallet = createWalletClient({ chain: foundry, transport: http(anvil.rpc), account: privateKeyToAccount(ANVIL_KEY) });
    const deploy = async (art: { abi: unknown; bytecode: { object: Hex } }, args: unknown[] = []) => {
      const hash = await wallet.deployContract({ abi: art.abi as [], bytecode: art.bytecode.object, args, gas: 30_000_000n });
      const rcpt = await publicClient.waitForTransactionReceipt({ hash });
      assert.equal(rcpt.status, 'success');
      return { address: rcpt.contractAddress!, gas: rcpt.gasUsed };
    };

    // -- 1. one verifier, one registry, one signer, one adapter, one factory -------
    const verifier = await deploy(dilithiumArt);
    const registry = await deploy(registryArt, [wallet.account.address]);
    const signer = await deploy(signerArt, [verifier.address, registry.address]);
    const adapter = await deploy(adapterArt, [signer.address]);
    const ctx = await deploy(ctxArt);
    const factory = await deploy(factoryArt, [adapter.address, ctx.address]);
    console.log(`    deploy gas: verifier ${verifier.gas}, registry ${registry.gas}, signer ${signer.gas}, adapter ${adapter.gas}, factory ${factory.gas}`);

    // -- 2. TS derivation over the real creation code == the factory's address ------
    const commitment = fx.commitment as Hex;
    const dep: Deployment = {
      factory: factory.address, creationCode: accountArt.bytecode.object as Hex, verifier: adapter.address, frameCtx: ctx.address,
    };
    const onChain = await publicClient.readContract({
      address: factory.address, abi: factoryArt.abi, functionName: 'getAccountAddress', args: [commitment],
    }) as Address;
    assert.equal(accountAddress(commitment, dep).toLowerCase(), onChain.toLowerCase(), 'TS CREATE2 binding must match the factory');

    // -- 3. key setup (trusted registrar = deployer) --------------------------------
    const pk = fx.ml_dsa_pk as Hex;
    // the expanded key travels as the ABI blob (uint256 words do not survive JSON.parse)
    const [aHatEnc] = decodeAbiParameters([{ type: 'bytes' }, { type: 'bytes' }, { type: 'bytes' }], fx.public_key_data as Hex);
    const [aHat] = decodeAbiParameters([{ type: 'uint256[][][]' }], aHatEnc);
    const regHash = await wallet.writeContract({
      address: registry.address, abi: registryArt.abi, functionName: 'register', args: [pk, aHat], gas: 30_000_000n,
    });
    const regRcpt = await publicClient.waitForTransactionReceipt({ hash: regHash });
    assert.equal(regRcpt.status, 'success');
    console.log(`    key setup (register: SHAKE256 tr + t1 unpack + PKContract): ${regRcpt.gasUsed}`);

    // -- 4a. ERC-7913 verify: recipient passes, others fail --------------------------
    const digest = fx.digest as Hex;
    const payload = fx.payload as Hex;
    const verify = (key: Hex, h: Hex, sig: Hex) => publicClient.readContract({
      address: signer.address, abi: signerArt.abi, functionName: 'verify', args: [key, h, sig],
    });
    assert.equal(await verify(commitment, digest, payload), ERC7913_MAGIC, 'genuine authorization');
    // gas: send the view call as a transaction (the wrapper never reverts, so an
    // estimate would binary-search down to the out-of-gas FAIL path)
    const verifyTx = await wallet.writeContract({
      address: signer.address, abi: signerArt.abi, functionName: 'verify', args: [commitment, digest, payload], gas: 30_000_000n,
    });
    const verifyRcpt = await publicClient.waitForTransactionReceipt({ hash: verifyTx });
    console.log(`    MlDsa44CommitSigner7913.verify (tx-level, incl. 3,764 B calldata): ${verifyRcpt.gasUsed}`);
    assert.equal(await verify(commitment, fx.other_digest as Hex, payload), FAIL, 'wrong digest');
    assert.equal(await verify(commitment, digest, fx.sender_derived_payload as Hex), FAIL, 'sender-derived key');
    assert.equal(await verify(commitment, digest, fx.payload_other_digest as Hex), FAIL, 'payload for another digest');
    // the reference verifier agrees
    const bytes = (h: Hex) => Uint8Array.from(Buffer.from(h.slice(2), 'hex'));
    assert.equal(verifyAuthorization(commitment, bytes(digest), bytes(payload)), true);
    assert.equal(verifyAuthorization(commitment, bytes(digest), bytes(fx.sender_derived_payload as Hex)), false);

    // -- 4b. frame account: createAccount + executeFrame ------------------------------
    const createHash = await wallet.writeContract({
      address: factory.address, abi: factoryArt.abi, functionName: 'createAccount', args: [commitment], gas: 5_000_000n,
    });
    const createRcpt = await publicClient.waitForTransactionReceipt({ hash: createHash });
    assert.equal(createRcpt.status, 'success');
    console.log(`    account deploy (createAccount): ${createRcpt.gasUsed}`);
    await testClient.setBalance({ address: onChain, value: parseEther('1') });
    await testClient.setBalance({ address: ENTRY_POINT, value: parseEther('1') });
    await testClient.impersonateAccount({ address: ENTRY_POINT });
    const setHash = await wallet.writeContract({ address: ctx.address, abi: ctxArt.abi, functionName: 'set', args: [digest, 1n, payload] });
    await publicClient.waitForTransactionReceipt({ hash: setHash });

    const dest = '0x000000000000000000000000000000000000dEaD' as Address;
    const before = await publicClient.getBalance({ address: dest });
    const epWallet = createWalletClient({ chain: foundry, transport: http(anvil.rpc), account: ENTRY_POINT });
    const spendHash = await epWallet.writeContract({
      address: onChain, abi: accountArt.abi, functionName: 'executeFrame', args: [1n, dest, parseEther('0.1'), '0x'], gas: 30_000_000n,
    });
    const spendRcpt = await publicClient.waitForTransactionReceipt({ hash: spendHash });
    assert.equal(spendRcpt.status, 'success');
    assert.equal(await publicClient.getBalance({ address: dest }) - before, parseEther('0.1'));
    console.log(`    executeFrame (tx-level, incl. calldata): ${spendRcpt.gasUsed}`);

    // wrong digest: the account refuses (no state change)
    const badSet = await wallet.writeContract({ address: ctx.address, abi: ctxArt.abi, functionName: 'set', args: [fx.other_digest as Hex, 1n, payload] });
    await publicClient.waitForTransactionReceipt({ hash: badSet });
    await assert.rejects(publicClient.simulateContract({
      address: onChain, abi: accountArt.abi, functionName: 'executeFrame', args: [1n, dest, parseEther('0.1'), '0x'], account: ENTRY_POINT,
    }), /NotAuthorized/);
  } finally {
    anvil.stop();
  }
});
