/**
 * SPHINCS- C13 hash-based spend through ERC-7913 signers (D-018), on a local anvil:
 *
 *   1. deploy the vendored Verity-Labs-verified C13 verifier (SphincsC13Asm @
 *      lfglabs-dev/SPHINCS- 2a40d0a, byte-identical) once, stateless
 *   2. deploy the two ERC-7913 wrappers over it: raw-key (`key` = 32-byte pk)
 *      and commit (`key` = keccak(DOMAIN || pk || opener), opened in the sig)
 *   3. for each, form `verifier || key` (52 bytes — no key contract, nothing
 *      stored at key setup), deploy a minimal SignerERC7913 account with it,
 *      and check the signature through the ERC-7913 entrypoint (0x024ad318)
 *      and the account's ERC-1271 surface (0x1626ba7e); negatives must fail
 *      with 0xffffffff, never a revert
 *   4. cross-check the TypeScript conventions (sphincs.ts) against the Python
 *      fixture generator: opener and commitment byte-identical
 *
 * Inputs come from python/scripts/sphincs_c13_7913_demo.json (generated with
 * the upstream Rust signer; see the script's docstring). Requires
 * `npm run build-contracts` and `anvil` on PATH.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  createPublicClient, createWalletClient, http, hexToBytes, type Hex, type Address,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';

import { startAnvil } from './util/anvil.ts';
import {
  SPHINCS_C13, erc7913Signer, sphincsC13Commitment, sphincsC13CommitSignature,
  sphincsC13Key, sphincsC13Opener, splitSphincsC13Key,
} from '../src/sphincs.ts';

const PORT = 8551;
const ANVIL_KEY =
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const EIP3860_INITCODE_CAP = 49_152;
const ERC7913_MAGIC = SPHINCS_C13.erc7913Magic;
const ERC1271_MAGIC = '0x1626ba7e';
const FAIL = '0xffffffff';

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const OUT = here('../contracts/out');

function artifact(rel: string) {
  return JSON.parse(readFileSync(`${OUT}/${rel}`, 'utf8'));
}

const demo = JSON.parse(
  readFileSync(here('../../python/scripts/sphincs_c13_7913_demo.json'), 'utf8'));

/** Flip one byte at `at` of a hex string. */
function flipByte(h: Hex, at: number): Hex {
  const b = hexToBytes(h);
  b[at] ^= 0x01;
  return ('0x' + Buffer.from(b).toString('hex')) as Hex;
}

test('SPHINCS- C13 key spends through ERC-7913 signers: raw key and commitment', {
  skip: !existsSync(OUT) ? 'contracts not built (npm run build-contracts)' : false,
}, async () => {
  const c13Art = artifact('SPHINCs-C13Asm.sol/SphincsC13Asm.json');
  const rawSignerArt = artifact('SphincsC13Signer7913.sol/SphincsC13Signer7913.json');
  const commitSignerArt = artifact('SphincsC13Signer7913.sol/SphincsC13CommitSigner7913.json');
  const accountArt = artifact('Stealth7913Account.sol/Stealth7913Account.json');

  // -- 0. conventions: TS agrees with the Python generator byte for byte -----
  const key = sphincsC13Key(demo.pk_seed as Hex, demo.pk_root as Hex);
  assert.equal(key, demo.key, 'key = pkSeed[0:16] || pkRoot[0:16]');
  assert.deepEqual(splitSphincsC13Key(key), { pkSeed: demo.pk_seed, pkRoot: demo.pk_root });
  const opener = sphincsC13Opener(hexToBytes(demo.shared_secret_DEMO_ONLY as Hex));
  assert.equal(opener, demo.opener, 'opener = SHA-256(openDomain || ss)');
  const commitment = sphincsC13Commitment(key, opener);
  assert.equal(commitment, demo.commitment, 'commitment = keccak(commitDomain || pk || opener)');
  const commitSig = sphincsC13CommitSignature(key, opener, demo.sig as Hex);
  assert.equal(commitSig, demo.commit_signature);
  assert.equal((demo.sig.length - 2) / 2, SPHINCS_C13.signatureLength);

  const anvil = await startAnvil(PORT);
  try {
    const publicClient = createPublicClient({ chain: foundry, transport: http(anvil.rpc) });
    const wallet = createWalletClient({
      chain: foundry, transport: http(anvil.rpc),
      account: privateKeyToAccount(ANVIL_KEY),
    });
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
    const gasOf = (address: Address, abi: unknown, functionName: string, args: unknown[]) =>
      publicClient.estimateContractGas({
        address, abi: abi as [], functionName, args, account: wallet.account });

    // -- 1. one shared stateless verifier, verbatim upstream bytecode ---------
    const verifier = await deploy(c13Art);
    console.log(`    C13 verifier deploy gas: ${verifier.gas}`);
    const { pkSeed, pkRoot } = splitSphincsC13Key(key);
    assert.equal(await read(verifier.address, c13Art.abi, 'verify',
      [pkSeed, pkRoot, demo.challenge, demo.sig]), true, 'raw C13 verify');
    const rawGas = await gasOf(verifier.address, c13Art.abi, 'verify',
      [pkSeed, pkRoot, demo.challenge, demo.sig]);
    console.log(`    raw C13 verify gas (tx-level, 3,688 B sig): ~${rawGas}`);

    // -- 2. the two ERC-7913 wrappers -----------------------------------------
    const rawSigner = await deploy(rawSignerArt, [verifier.address]);
    const commitSigner = await deploy(commitSignerArt, [verifier.address]);

    // -- 3a. raw-key form: signer = verifier || pk, 52 bytes, nothing stored --
    const signerRaw = erc7913Signer(rawSigner.address, key);
    assert.equal((signerRaw.length - 2) / 2, 52, 'raw signer must be 52 bytes');
    const accountRaw = await deploy(accountArt, [signerRaw]);
    const initcodeBytes = (accountArt.bytecode.object.length - 2) / 2 + 96;
    console.log(`    account initcode ~${initcodeBytes} B (EIP-3860 cap ${EIP3860_INITCODE_CAP} B), deploy gas: ${accountRaw.gas}`);
    assert.ok(initcodeBytes < EIP3860_INITCODE_CAP / 4);

    assert.equal(await read(rawSigner.address, rawSignerArt.abi, 'verify',
      [key, demo.challenge, demo.sig]), ERC7913_MAGIC, 'ERC-7913 raw-key verify');
    const rawWrapGas = await gasOf(rawSigner.address, rawSignerArt.abi, 'verify',
      [key, demo.challenge, demo.sig]);
    console.log(`    ERC-7913 raw-key verify gas: ~${rawWrapGas}`);
    assert.equal(await read(accountRaw.address, accountArt.abi, 'isValidSignature',
      [demo.challenge, demo.sig]), ERC1271_MAGIC, 'account ERC-1271 accepts');
    const acct1271Gas = await gasOf(accountRaw.address, accountArt.abi, 'isValidSignature',
      [demo.challenge, demo.sig]);
    console.log(`    account isValidSignature gas: ~${acct1271Gas}`);

    // negatives: uniform 0xffffffff, no reverts
    const wrongHash = ('0x' + 'ab'.repeat(32)) as Hex;
    assert.equal(await read(rawSigner.address, rawSignerArt.abi, 'verify',
      [key, wrongHash, demo.sig]), FAIL, 'wrong hash');
    assert.equal(await read(accountRaw.address, accountArt.abi, 'isValidSignature',
      [wrongHash, demo.sig]), FAIL, 'account rejects wrong hash');
    // byte 0 sits in R: changes H_msg, hence every index -> root mismatch or grinding fail
    assert.equal(await read(rawSigner.address, rawSignerArt.abi, 'verify',
      [key, demo.challenge, flipByte(demo.sig as Hex, 0)]), FAIL, 'tampered R');
    // last byte sits in the top-layer auth path -> root mismatch
    assert.equal(await read(rawSigner.address, rawSignerArt.abi, 'verify',
      [key, demo.challenge, flipByte(demo.sig as Hex, SPHINCS_C13.signatureLength - 1)]),
      FAIL, 'tampered auth path');
    assert.equal(await read(rawSigner.address, rawSignerArt.abi, 'verify',
      [key, demo.challenge, (demo.sig as string).slice(0, -2) as Hex]), FAIL, 'short sig');
    assert.equal(await read(rawSigner.address, rawSignerArt.abi, 'verify',
      [flipByte(key, 20), demo.challenge, demo.sig]), FAIL, 'wrong root');
    assert.equal(await read(rawSigner.address, rawSignerArt.abi, 'verify',
      [key + '00', demo.challenge, demo.sig]), FAIL, 'wrong key length');

    // -- 3b. commit form: signer = verifier || commitment; the sender can form
    //        this (pk from the meta-address, opener from ss), so the account
    //        initcode -- and its CREATE2 address -- is sender-derivable.
    assert.equal(await read(commitSigner.address, commitSignerArt.abi, 'commitment',
      [key, opener]), commitment, 'on-chain commitment matches TS/Python');
    const signerCommit = erc7913Signer(commitSigner.address, commitment);
    assert.equal((signerCommit.length - 2) / 2, 52);
    const accountCommit = await deploy(accountArt, [signerCommit]);

    assert.equal(await read(commitSigner.address, commitSignerArt.abi, 'verify',
      [commitment, demo.challenge, commitSig]), ERC7913_MAGIC, 'ERC-7913 commit verify');
    const commitWrapGas = await gasOf(commitSigner.address, commitSignerArt.abi, 'verify',
      [commitment, demo.challenge, commitSig]);
    console.log(`    ERC-7913 commit verify gas: ~${commitWrapGas}`);
    assert.equal(await read(accountCommit.address, accountArt.abi, 'isValidSignature',
      [demo.challenge, commitSig]), ERC1271_MAGIC, 'commit account ERC-1271 accepts');

    assert.equal(await read(commitSigner.address, commitSignerArt.abi, 'verify',
      [commitment, wrongHash, commitSig]), FAIL, 'commit: wrong hash');
    const wrongOpener = flipByte(opener, 31);
    assert.equal(await read(commitSigner.address, commitSignerArt.abi, 'verify',
      [commitment, demo.challenge, sphincsC13CommitSignature(key, wrongOpener, demo.sig as Hex)]),
      FAIL, 'commit: wrong opener');
    assert.equal(await read(commitSigner.address, commitSignerArt.abi, 'verify',
      [commitment, demo.challenge, demo.sig]), FAIL, 'commit: bare C13 sig (no opening)');
    assert.equal(await read(accountRaw.address, accountArt.abi, 'isValidSignature',
      [demo.challenge, commitSig]), FAIL, 'raw account rejects the commit-form sig');
    assert.equal(await read(accountCommit.address, accountArt.abi, 'isValidSignature',
      [demo.challenge, demo.sig]), FAIL, 'commit account rejects the raw-form sig');
  } finally {
    anvil.stop();
  }
});
