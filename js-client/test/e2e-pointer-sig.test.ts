/**
 * Pointer signatures with SPHINCS- C13 (docs/pointer-signatures-poc.md, D-018):
 * the (v, r, s) ABI kept, `v` a version, and — because a C13 public key is one
 * word — `r` IS the key (0x52) or a hiding commitment to it (0x53). No key
 * table, no registration transaction.
 *
 * On a fresh anvil, from dev account #0, in the order the Python fixture pins
 * (CREATE nonces 0..3: C13 verifier, ML-DSA verifier, registry, vault):
 *
 *   1. classic path untouched (viem ECDSA, v = 27/28)
 *   2. 0x52: publish the 3,688-B C13 sig (SSTORE2), withdraw with
 *      r = key, s = index; the owner is keccak256(key)[12:]
 *   3. 0x53: publish pk || opener || sig, withdraw with r = commitment; the
 *      owner is keccak256(commitment)[12:] — the address a stealth SENDER can
 *      compute (pk from the meta-address, opener from the KEM shared secret)
 *   4. negatives: signature bound to its digest (replay for a different
 *      amount fails), wrong commitment, bad index, unknown version
 *   5. 0x50 / 0x51 (ML-DSA key table, PKContract form of the vendored
 *      df999ed) at `recover` level with the ML-DSA 7913 fixture
 *
 * The value sits INSIDE the vault (depositFor). That is the point the doc now
 * makes explicit: pointer signatures authorize spends of value held by
 * contracts that adopted `recover`; keccak256(r)[12:] itself cannot hold ETH.
 *
 * Requires `npm run build-contracts` and `anvil` on PATH.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  createPublicClient, createWalletClient, http, parseEther, keccak256, toHex,
  decodeAbiParameters, encodeAbiParameters, getContractAddress,
  type Hex, type Address,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';

import { startAnvil } from './util/anvil.ts';
import { sphincsC13Commitment } from '../src/sphincs.ts';

const PORT = 8552;
const ANVIL_KEY =
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const CLASSIC_KEY = keccak256(toHex('pointer-sig classic demo key'));

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const OUT = here('../contracts/out');
const artifact = (rel: string) => JSON.parse(readFileSync(`${OUT}/${rel}`, 'utf8'));

const demo = JSON.parse(
  readFileSync(here('../../python/scripts/sphincs_c13_7913_demo.json'), 'utf8'));
const mldsaDemo = JSON.parse(
  readFileSync(here('../../python/scripts/zknox_7913_demo.json'), 'utf8'));

const pqAddressOf = (word: Hex): Address => ('0x' + keccak256(word).slice(26)) as Address;

test('SPHINCS- C13 as pointer signatures: r is the key (0x52) or its commitment (0x53)', {
  skip: !existsSync(OUT) ? 'contracts not built (npm run build-contracts)' : false,
}, async () => {
  const c13Art = artifact('SPHINCs-C13Asm.sol/SphincsC13Asm.json');
  const mldsaArt = artifact('ZKNOX_dilithium.sol/ZKNOX_dilithium.json');
  const pkContractArt = artifact('ZKNOX_PKContract.sol/PKContract.json');
  const registryArt = artifact('PointerSig.sol/PointerSigRegistry.json');
  const vaultArt = artifact('PointerSig.sol/PointerSigVault.json');
  const P = demo.pointer;

  const anvil = await startAnvil(PORT);
  try {
    const publicClient = createPublicClient({ chain: foundry, transport: http(anvil.rpc) });
    const deployer = privateKeyToAccount(ANVIL_KEY);
    assert.equal(deployer.address.toLowerCase(), P.deployer, 'fixture pins anvil account #0');
    const wallet = createWalletClient({ chain: foundry, transport: http(anvil.rpc), account: deployer });
    const deploy = async (art: { abi: unknown; bytecode: { object: Hex } },
      args: unknown[] = []): Promise<{ address: Address; gas: bigint }> => {
      const hash = await wallet.deployContract({
        abi: art.abi as [], bytecode: art.bytecode.object, args, gas: 30_000_000n });
      const rcpt = await publicClient.waitForTransactionReceipt({ hash });
      assert.equal(rcpt.status, 'success');
      return { address: rcpt.contractAddress!, gas: rcpt.gasUsed };
    };
    const read = (address: Address, abi: unknown, functionName: string, args: unknown[]) =>
      publicClient.readContract({ address, abi: abi as [], functionName, args });
    const write = async (address: Address, abi: unknown, functionName: string,
      args: unknown[], value = 0n) => {
      const hash = await wallet.writeContract({
        address, abi: abi as [], functionName, args, value, gas: 30_000_000n });
      const rcpt = await publicClient.waitForTransactionReceipt({ hash });
      assert.equal(rcpt.status, 'success', `${functionName} must succeed`);
      return rcpt.gasUsed;
    };
    const expectRevert = async (fn: () => Promise<unknown>, what: string) => {
      await assert.rejects(fn, (e: unknown) => e instanceof Error, what);
    };

    // -- deploy in the fixture's order; the vault digest depends on its address
    const c13 = await deploy(c13Art);
    const mldsa = await deploy(mldsaArt);
    const registry = await deploy(registryArt, [mldsa.address, c13.address]);
    const vault = await deploy(vaultArt, [registry.address]);
    assert.equal(vault.address.toLowerCase(), P.vault,
      'deploy order changed — regenerate the fixture (sphincs_c13_7913_demo.py)');
    assert.equal(getContractAddress({ from: deployer.address, nonce: BigInt(P.deploy_nonces.vault) })
      .toLowerCase(), P.vault);
    console.log(`    registry deploy gas: ${registry.gas}, vault: ${vault.gas}`);

    const to = P.to as Address;
    const amount = BigInt(P.amount);
    const V_SPHINCS = P.v_sphincs as number;
    const V_SPHINCS_COMMIT = P.v_sphincs_commit as number;
    assert.equal(await read(registry.address, registryArt.abi, 'V_SPHINCS', []), V_SPHINCS);
    assert.equal(await read(registry.address, registryArt.abi, 'V_SPHINCS_COMMIT', []), V_SPHINCS_COMMIT);

    // -- 1. classic path, unchanged ------------------------------------------
    const classic = privateKeyToAccount(CLASSIC_KEY);
    await write(vault.address, vaultArt.abi, 'depositFor', [classic.address], parseEther('1'));
    const cDigest = await read(vault.address, vaultArt.abi, 'withdrawDigest',
      [classic.address, to, parseEther('0.4'), 0n]) as Hex;
    const cSig = await classic.sign({ hash: cDigest });
    const cr = cSig.slice(0, 66) as Hex;
    const cs = ('0x' + cSig.slice(66, 130)) as Hex;
    const cv = parseInt(cSig.slice(130, 132), 16);
    const classicGas = await write(vault.address, vaultArt.abi, 'withdrawWithSig',
      [classic.address, to, parseEther('0.4'), cv, cr, cs]);
    assert.equal(await publicClient.getBalance({ address: to }), parseEther('0.4'));
    console.log(`    withdrawWithSig classic gas: ${classicGas}`);

    // -- 2. 0x52: r = the C13 key, owner = keccak256(key)[12:] ---------------
    const rawOwner = pqAddressOf(P.raw.r as Hex);
    assert.equal(rawOwner.toLowerCase(), P.raw.owner, 'TS/Python agree on keccak(key)[12:]');
    assert.equal((await read(registry.address, registryArt.abi, 'pqAddressOf', [P.raw.r]) as string)
      .toLowerCase(), P.raw.owner, 'contract agrees');
    await write(vault.address, vaultArt.abi, 'depositFor', [rawOwner], parseEther('1'));
    assert.equal(await read(vault.address, vaultArt.abi, 'withdrawDigest', [rawOwner, to, amount, 0n]),
      P.raw.digest, 'Python reproduced the vault digest');

    const pubRawGas = await write(registry.address, registryArt.abi, 'publishSignature', [P.raw.blob]);
    const rawIdx = (await read(registry.address, registryArt.abi, 'signatureCount', []) as bigint) - 1n;
    console.log(`    publishSignature (3,688-B C13 sig, SSTORE2) gas: ${pubRawGas}`);
    assert.equal((await read(registry.address, registryArt.abi, 'recover',
      [P.raw.digest, V_SPHINCS, P.raw.r, toHex(rawIdx, { size: 32 })]) as string).toLowerCase(),
      rawOwner.toLowerCase(), 'recover returns keccak(key)[12:]');
    const rawGas = await write(vault.address, vaultArt.abi, 'withdrawWithSig',
      [rawOwner, to, amount, V_SPHINCS, P.raw.r, toHex(rawIdx, { size: 32 })]);
    console.log(`    withdrawWithSig 0x52 (r = C13 key, no key table) gas: ${rawGas}`);
    assert.equal(await publicClient.getBalance({ address: to }), parseEther('0.4') + amount);
    assert.equal(await read(vault.address, vaultArt.abi, 'balanceOf', [rawOwner]), parseEther('1') - amount);

    // -- 3. 0x53: r = commitment, owner = keccak256(commitment)[12:] ---------
    assert.equal(P.commit.r, demo.commitment);
    assert.equal(sphincsC13Commitment(demo.key as Hex, demo.opener as Hex), P.commit.r);
    const commitOwner = pqAddressOf(P.commit.r as Hex);
    assert.equal(commitOwner.toLowerCase(), P.commit.owner);
    await write(vault.address, vaultArt.abi, 'depositFor', [commitOwner], parseEther('1'));
    assert.equal(await read(vault.address, vaultArt.abi, 'withdrawDigest', [commitOwner, to, amount, 0n]),
      P.commit.digest);
    const pubCommitGas = await write(registry.address, registryArt.abi, 'publishSignature', [P.commit.blob]);
    const commitIdx = (await read(registry.address, registryArt.abi, 'signatureCount', []) as bigint) - 1n;
    console.log(`    publishSignature (pk || opener || sig, 3,752 B) gas: ${pubCommitGas}`);
    const commitGas = await write(vault.address, vaultArt.abi, 'withdrawWithSig',
      [commitOwner, to, amount, V_SPHINCS_COMMIT, P.commit.r, toHex(commitIdx, { size: 32 })]);
    console.log(`    withdrawWithSig 0x53 (r = commitment) gas: ${commitGas}`);
    assert.equal(await read(vault.address, vaultArt.abi, 'balanceOf', [commitOwner]), parseEther('1') - amount);

    // -- 4. negatives ----------------------------------------------------------
    // bound to its digest: the published sig authorizes (owner, to, 0.25, nonce 0) only
    await expectRevert(() => publicClient.simulateContract({
      address: vault.address, abi: vaultArt.abi, functionName: 'withdrawWithSig',
      args: [rawOwner, to, parseEther('0.5'), V_SPHINCS, P.raw.r, toHex(rawIdx, { size: 32 })],
      account: deployer }), 'replay for a different amount');
    // nonce advanced: the same tuple no longer verifies
    await expectRevert(() => publicClient.simulateContract({
      address: vault.address, abi: vaultArt.abi, functionName: 'withdrawWithSig',
      args: [rawOwner, to, amount, V_SPHINCS, P.raw.r, toHex(rawIdx, { size: 32 })],
      account: deployer }), 'replay after nonce advanced');
    // commit form with the raw-form blob: not an opening
    await expectRevert(() => read(registry.address, registryArt.abi, 'recover',
      [P.commit.digest, V_SPHINCS_COMMIT, P.commit.r, toHex(rawIdx, { size: 32 })]), 'commit: bare sig');
    // raw form with a wrong key word: root mismatch
    const wrongKey = (P.raw.r.slice(0, -2) + '00') as Hex;
    await expectRevert(() => read(registry.address, registryArt.abi, 'recover',
      [P.raw.digest, V_SPHINCS, wrongKey, toHex(rawIdx, { size: 32 })]), 'wrong key');
    // commitment that does not match the opening
    await expectRevert(() => read(registry.address, registryArt.abi, 'recover',
      [P.commit.digest, V_SPHINCS_COMMIT, wrongKey, toHex(commitIdx, { size: 32 })]), 'wrong commitment');
    await expectRevert(() => read(registry.address, registryArt.abi, 'recover',
      [P.raw.digest, V_SPHINCS, P.raw.r, toHex(99n, { size: 32 })]), 'bad index');
    await expectRevert(() => read(registry.address, registryArt.abi, 'recover',
      [P.raw.digest, 5, P.raw.r, toHex(rawIdx, { size: 32 })]), 'unknown version');

    // -- 5. ML-DSA paths (0x50 / 0x51) at recover level, df999ed PKContract form
    const [aHatEnc, tr, t1Enc] = decodeAbiParameters(
      [{ type: 'bytes' }, { type: 'bytes' }, { type: 'bytes' }], mldsaDemo.public_key_data as Hex);
    const [aHat] = decodeAbiParameters([{ type: 'uint256[][][]' }], aHatEnc);
    const [t1] = decodeAbiParameters([{ type: 'uint256[][]' }], t1Enc);
    const pkc = await deploy(pkContractArt, [aHat, tr, t1]);
    const regGas = await write(registry.address, registryArt.abi, 'registerKey', [pkc.address]);
    const keyIdx = (await read(registry.address, registryArt.abi, 'keyCount', []) as bigint) - 1n;
    const [, pqAddr, classicAddr] = await read(registry.address, registryArt.abi, 'keys', [keyIdx]) as
      [Address, Address, Address];
    assert.equal(classicAddr, deployer.address);
    console.log(`    ML-DSA registerKey (PKContract already deployed: ${pkc.gas}) gas: ${regGas}`);
    await write(registry.address, registryArt.abi, 'publishSignature', [mldsaDemo.sig]);
    const mIdx = (await read(registry.address, registryArt.abi, 'signatureCount', []) as bigint) - 1n;
    assert.equal(await read(registry.address, registryArt.abi, 'recover',
      [mldsaDemo.challenge, 0x50, toHex(keyIdx, { size: 32 }), toHex(mIdx, { size: 32 })]), pqAddr);
    const mGas = await publicClient.estimateContractGas({
      address: registry.address, abi: registryArt.abi as [], functionName: 'recover',
      args: [mldsaDemo.challenge, 0x50, toHex(keyIdx, { size: 32 }), toHex(mIdx, { size: 32 })],
      account: deployer });
    console.log(`    recover 0x50 (ML-DSA, key table) gas: ~${mGas}`);
    // hybrid: registering EOA co-signs the same digest
    const hSig = await deployer.sign({ hash: mldsaDemo.challenge as Hex });
    const blob = encodeAbiParameters([{ type: 'bytes' }, { type: 'bytes' }], [hSig, mldsaDemo.sig as Hex]);
    await write(registry.address, registryArt.abi, 'publishSignature', [blob]);
    const hIdx = (await read(registry.address, registryArt.abi, 'signatureCount', []) as bigint) - 1n;
    assert.equal(await read(registry.address, registryArt.abi, 'recover',
      [mldsaDemo.challenge, 0x51, toHex(keyIdx, { size: 32 }), toHex(hIdx, { size: 32 })]), deployer.address);
    await expectRevert(() => read(registry.address, registryArt.abi, 'recover',
      [mldsaDemo.challenge, 0x51, toHex(keyIdx, { size: 32 }), toHex(mIdx, { size: 32 })]),
      'hybrid needs both halves');
  } finally {
    anvil.stop();
  }
});
