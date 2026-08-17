/**
 * ERC-7913 spend-route e2e (D-014), on a local anvil:
 *
 *   1. deploy the vendored ZKNOX_dilithium verifier (ETHDILITHIUM @ df999ed,
 *      ERC-7913-native: verify(bytes key, bytes32 hash, bytes sig) -> bytes4)
 *   2. deploy a PKContract holding the blinded stealth key's expanded pk
 *      (SSTORE2; the ERC-7913 `key` is the 20-byte pointer to it)
 *   3. form the signer bytes `verifier || pkPointer` (40 bytes), deploy a
 *      minimal OpenZeppelin SignerERC7913 account with it, and assert the
 *      initcode is far below the EIP-3860 cap (the D-005 wall dissolves)
 *   4. verify the blinded-key possession signature both directly through the
 *      ERC-7913 entrypoint (magic value 0x024ad318) and through the account's
 *      ERC-1271 isValidSignature (0x1626ba7e); negative case must fail
 *
 * Inputs come from python/scripts/zknox_7913_demo.json (a 32-byte challenge:
 * the 3-arg verify hardcodes M' = 0x00 || 0x00 || m). Requires
 * `npm run build-contracts` and `anvil` on PATH.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  createPublicClient, createWalletClient, http, concatHex,
  decodeAbiParameters, type Hex, type Address,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';

import { startAnvil } from './util/anvil.ts';

const PORT = 8549;
const ANVIL_KEY =
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const EIP3860_INITCODE_CAP = 49_152;
const ERC7913_MAGIC = '0x024ad318';   // IERC7913SignatureVerifier.verify.selector
const ERC1271_MAGIC = '0x1626ba7e';   // IERC1271.isValidSignature.selector

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const OUT = here('../contracts/out');

function artifact(rel: string) {
  return JSON.parse(readFileSync(`${OUT}/${rel}`, 'utf8'));
}

const demo = JSON.parse(
  readFileSync(here('../../python/scripts/zknox_7913_demo.json'), 'utf8'));

test('blinded stealth key spends through an ERC-7913 signer (verifier || key)', {
  skip: !existsSync(OUT) ? 'contracts not built (npm run build-contracts)' : false,
}, async () => {
  const dilithiumArt = artifact('ZKNOX_dilithium.sol/ZKNOX_dilithium.json');
  const pkContractArt = artifact('ZKNOX_PKContract.sol/PKContract.json');
  const accountArt = artifact('Stealth7913Account.sol/Stealth7913Account.json');

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

    // -- 1. one shared stateless verifier ---------------------------------
    const verifier = await deploy(dilithiumArt);

    // -- 2. the stealth key's PKContract (the ERC-7913 `key` points here) --
    const [aHatEnc, tr, t1Enc] = decodeAbiParameters(
      [{ type: 'bytes' }, { type: 'bytes' }, { type: 'bytes' }],
      demo.public_key_data as Hex);
    const [aHat] = decodeAbiParameters([{ type: 'uint256[][][]' }], aHatEnc);
    const [t1] = decodeAbiParameters([{ type: 'uint256[][]' }], t1Enc);
    const pk = await deploy(pkContractArt, [aHat, tr, t1]);
    console.log(`    PKContract deploy gas (22.4 kB expanded pk): ${pk.gas}`);

    // -- 3. signer = verifier || key: 40 bytes, initcode nowhere near 3860 --
    const signer = concatHex([verifier.address, pk.address]);
    assert.equal((signer.length - 2) / 2, 40, 'signer must be 40 bytes');
    const account = await deploy(accountArt, [signer]);
    const initcodeBytes = (accountArt.bytecode.object.length - 2) / 2 + 64; // + abi-encoded signer
    console.log(`    account initcode ~${initcodeBytes} B (EIP-3860 cap ${EIP3860_INITCODE_CAP} B), deploy gas: ${account.gas}`);
    assert.ok(initcodeBytes < EIP3860_INITCODE_CAP / 4,
      'ERC-7913 account initcode must be far below the EIP-3860 cap');

    // -- 4a. direct ERC-7913 verify: magic value on the blinded signature --
    const key = pk.address as Hex;
    const ok = await publicClient.readContract({
      address: verifier.address, abi: dilithiumArt.abi, functionName: 'verify',
      args: [key, demo.challenge as Hex, demo.sig as Hex],
    });
    assert.equal(ok, ERC7913_MAGIC,
      'ERC-7913 verify must return its magic value for the blinded signature');
    const verifyGas = await publicClient.estimateContractGas({
      address: verifier.address, abi: dilithiumArt.abi, functionName: 'verify',
      args: [key, demo.challenge as Hex, demo.sig as Hex],
      account: wallet.account,
    });
    console.log(`    ERC-7913 verify gas: ~${verifyGas}`);

    // -- 4b. through the account's ERC-1271 surface -----------------------
    const acct1271 = await publicClient.readContract({
      address: account.address, abi: accountArt.abi,
      functionName: 'isValidSignature',
      args: [demo.challenge as Hex, demo.sig as Hex],
    });
    assert.equal(acct1271, ERC1271_MAGIC,
      'account isValidSignature must accept the blinded signature');

    // -- 4c. negative: a different hash must not verify -------------------
    const wrongHash = ('0x' + 'ab'.repeat(32)) as Hex;
    const bad = await publicClient.readContract({
      address: verifier.address, abi: dilithiumArt.abi, functionName: 'verify',
      args: [key, wrongHash, demo.sig as Hex],
    });
    assert.equal(bad, '0xffffffff', 'wrong hash must not verify');
    const bad1271 = await publicClient.readContract({
      address: account.address, abi: accountArt.abi,
      functionName: 'isValidSignature',
      args: [wrongHash, demo.sig as Hex],
    });
    assert.equal(bad1271, '0xffffffff', 'account must reject the wrong hash');
  } finally {
    anvil.stop();
  }
});
