/**
 * ERC-7913 spend-route e2e for the classical-spend hybrid, on a local anvil.
 *
 * The counterpart to e2e-7913.test.ts. The ML-DSA scheme's signer is
 * `verifier || pkPointer` (over 20 bytes, dispatched to an on-chain PQ
 * verifier); this scheme's signer is the 20-byte stealth address with an
 * empty key. OpenZeppelin's SignatureChecker resolves a 20-byte signer
 * through `ecrecover`, so:
 *
 *   1. deploy the same OpenZeppelin SignerERC7913 account (Stealth7913Account,
 *      unchanged) with a 20-byte signer: the blinded stealth address
 *   2. verify the blinded key's ECDSA signature through the account's ERC-1271
 *      isValidSignature (magic 0x1626ba7e); a wrong hash must fail
 *   3. record the cost: no verifier, no PKContract, and account initcode far
 *      below the EIP-3860 cap. Contrast the ML-DSA route (D-014): a PKContract
 *      deploy (~5.3 M gas) plus a ~15 M gas verify. This leaf spends via
 *      ecrecover.
 *
 * Inputs come from python/scripts/classical_7913_demo.json (signer, a 32-byte
 * challenge, and an `r || s || v` signature with v in {27, 28}). Requires
 * `npm run build-contracts` and `anvil` on PATH.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  createPublicClient, createWalletClient, http, type Hex, type Address,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';

const PORT = 8550;
const RPC = `http://127.0.0.1:${PORT}`;
const ANVIL_KEY =
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const EIP3860_INITCODE_CAP = 49_152;
const ERC1271_MAGIC = '0x1626ba7e';   // IERC1271.isValidSignature.selector
const FAIL = '0xffffffff';

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const OUT = here('../contracts/out');

function artifact(rel: string) {
  return JSON.parse(readFileSync(`${OUT}/${rel}`, 'utf8'));
}

const demo = JSON.parse(
  readFileSync(here('../../python/scripts/classical_7913_demo.json'), 'utf8'));

test('blinded stealth key spends through a 20-byte ERC-7913 signer (ecrecover base case)', {
  skip: !existsSync(OUT) ? 'contracts not built (npm run build-contracts)' : false,
}, async () => {
  const accountArt = artifact('Stealth7913Account.sol/Stealth7913Account.json');

  const anvil = spawn('anvil', ['--port', String(PORT), '--silent'],
    { stdio: 'ignore' });
  try {
    const publicClient = createPublicClient({ chain: foundry, transport: http(RPC) });
    for (let i = 0; ; i++) {
      try { await publicClient.getBlockNumber(); break; }
      catch (e) {
        if (i > 50) throw new Error(`anvil did not start: ${(e as Error).message}`);
        await new Promise((r) => setTimeout(r, 100));
      }
    }
    const wallet = createWalletClient({
      chain: foundry, transport: http(RPC),
      account: privateKeyToAccount(ANVIL_KEY),
    });

    // -- 1. the account: signer is just the 20-byte stealth address ---------
    const signer = demo.signer as Hex;
    assert.equal((signer.length - 2) / 2, 20, 'signer must be 20 bytes (empty key)');
    const hash = await wallet.deployContract({
      abi: accountArt.abi, bytecode: accountArt.bytecode.object as Hex,
      args: [signer], gas: 30_000_000n,
    });
    const rcpt = await publicClient.waitForTransactionReceipt({ hash });
    assert.equal(rcpt.status, 'success');
    const account = rcpt.contractAddress as Address;
    const initcodeBytes = (accountArt.bytecode.object.length - 2) / 2 + 32; // + abi-encoded 20-byte signer
    console.log(`    account initcode ~${initcodeBytes} B (EIP-3860 cap ${EIP3860_INITCODE_CAP} B), deploy gas: ${rcpt.gasUsed}`);
    console.log(`    no verifier, no PKContract (contrast D-014: PKContract ~5.3 M + verify ~15 M gas)`);
    assert.ok(initcodeBytes < EIP3860_INITCODE_CAP / 4,
      'account initcode must be far below the EIP-3860 cap');

    // -- 2a. the account accepts the blinded key's ECDSA signature ----------
    const ok = await publicClient.readContract({
      address: account, abi: accountArt.abi, functionName: 'isValidSignature',
      args: [demo.challenge as Hex, demo.sig as Hex],
    });
    assert.equal(ok, ERC1271_MAGIC,
      'account isValidSignature must accept the blinded ECDSA signature');
    const verifyGas = await publicClient.estimateContractGas({
      address: account, abi: accountArt.abi, functionName: 'isValidSignature',
      args: [demo.challenge as Hex, demo.sig as Hex],
      account: wallet.account,
    });
    console.log(`    isValidSignature (ecrecover) gas: ~${verifyGas}`);

    // -- 2b. negative: a different hash must not verify ---------------------
    const wrongHash = ('0x' + 'ab'.repeat(32)) as Hex;
    const bad = await publicClient.readContract({
      address: account, abi: accountArt.abi, functionName: 'isValidSignature',
      args: [wrongHash, demo.sig as Hex],
    });
    assert.equal(bad, FAIL, 'account must reject the wrong hash');
  } finally {
    anvil.kill();
  }
});
