/**
 * Stretch-goal e2e: the stealth address as a counterfactual CREATE2
 * ERC-4337 account address (kohaku / ZKNOX route), on a local anvil.
 *
 *   1. deploy the ZKNOX verifiers + account factory
 *   2. compute the account address OFF-CHAIN from the blinded stealth key's
 *      expanded pk (CREATE2 formula only — this is what a stealth sender
 *      would name as the recipient address, no chain access needed)
 *   3. cross-check with factory.getAddress, deploy via factory.createAccount,
 *      assert the deployed address matches the prediction (gas recorded)
 *   4. verify the blinded-key possession signature through the on-chain
 *      ZKNOX_dilithium verifier (gas recorded)
 *
 * Inputs come from python/scripts/zknox_demo.json (see
 * zknox_counterfactual_demo.py — construction A at the ZKNOX profile).
 * Requires `forge build` in kohaku/packages/pq-account and `anvil` on PATH.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  createPublicClient, createWalletClient, http, keccak256, getCreate2Address,
  encodeAbiParameters, encodePacked, concatHex, stringToHex,
  type Hex, type Address,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';

const PORT = 8548;
const RPC = `http://127.0.0.1:${PORT}`;
const ANVIL_KEY =
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const VERSION = 'pq-stealth-demo-v0';
const DUMMY_ENTRYPOINT = '0x000000000000000000000000000000000000dEaD' as Address;
const PRE_QUANTUM_PUBKEY = '0x1111111111111111111111111111111111111111' as Hex;

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const KOHAKU_OUT = process.env.KOHAKU_OUT
  ?? '/private/tmp/claude-501/-Users-skas-Ethereum-git-erc-5567/3bbf0a8c-f678-4091-af33-dbab7934a47e/scratchpad/kohaku/packages/pq-account/out';

function artifact(rel: string) {
  return JSON.parse(readFileSync(`${KOHAKU_OUT}/${rel}`, 'utf8'));
}

const demo = JSON.parse(
  readFileSync(here('../../python/scripts/zknox_demo.json'), 'utf8'));

test('stealth address as counterfactual CREATE2 account (ZKNOX factory)', {
  skip: !existsSync(KOHAKU_OUT) ? 'kohaku artifacts not built' : false,
}, async () => {
  const factoryArt = artifact('ZKNOX_PQFactory.sol/ZKNOX_AccountFactory.json');
  const accountArt = artifact('ZKNOX_ERC4337_account.sol/ZKNOX_ERC4337_account.json');
  const dilithiumArt = artifact('ZKNOX_dilithium.sol/ZKNOX_dilithium.json');
  const ecdsaArt = artifact('VerifierECDSAk1.sol/ECDSAk1Verifier.json');

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
    const deploy = async (art: { abi: unknown; bytecode: { object: Hex } },
      args: unknown[] = []): Promise<Address> => {
      const hash = await wallet.deployContract({
        abi: art.abi as [], bytecode: art.bytecode.object, args });
      const rcpt = await publicClient.waitForTransactionReceipt({ hash });
      return rcpt.contractAddress!;
    };

    const ecdsaVerifier = await deploy(ecdsaArt);
    const dilithiumVerifier = await deploy(dilithiumArt);
    const factory = await deploy(factoryArt,
      [DUMMY_ENTRYPOINT, ecdsaVerifier, dilithiumVerifier, VERSION]);

    const postQuantumPubKey = demo.public_key_data as Hex;

    // -- 2. pure off-chain prediction (the sender's computation) ----------
    const salt = keccak256(encodePacked(['bytes', 'bytes', 'string'],
      [PRE_QUANTUM_PUBKEY, postQuantumPubKey, VERSION]));
    const initCode = concatHex([accountArt.bytecode.object, encodeAbiParameters(
      [{ type: 'address' }, { type: 'bytes' }, { type: 'bytes' },
       { type: 'address' }, { type: 'address' }],
      [DUMMY_ENTRYPOINT, PRE_QUANTUM_PUBKEY, postQuantumPubKey,
       ecdsaVerifier, dilithiumVerifier])]);
    const predicted = getCreate2Address(
      { from: factory, salt, bytecodeHash: keccak256(initCode) });

    // -- 3. cross-check on-chain, then deploy and compare -----------------
    const onchainPredicted = await publicClient.readContract({
      address: factory, abi: factoryArt.abi, functionName: 'getAddress',
      args: [PRE_QUANTUM_PUBKEY, postQuantumPubKey],
    }) as Address;
    assert.equal(predicted.toLowerCase(), onchainPredicted.toLowerCase(),
      'off-chain CREATE2 prediction must match factory.getAddress');

    const createHash = await wallet.writeContract({
      address: factory, abi: factoryArt.abi, functionName: 'createAccount',
      args: [PRE_QUANTUM_PUBKEY, postQuantumPubKey], gas: 30_000_000n,
    });
    const createRcpt = await publicClient.waitForTransactionReceipt(
      { hash: createHash });
    assert.equal(createRcpt.status, 'success');
    const code = await publicClient.getCode({ address: predicted });
    assert.ok(code && code.length > 2,
      'account must exist at the predicted stealth address');
    console.log(`    counterfactual address: ${predicted}`);
    console.log(`    account deployment gas: ${createRcpt.gasUsed}`);

    // -- 4. on-chain verification of the blinded-key possession sig -------
    const { result: pkPointer } = await publicClient.simulateContract({
      address: dilithiumVerifier, abi: dilithiumArt.abi,
      functionName: 'setKey', args: [postQuantumPubKey],
      account: wallet.account,
    }) as { result: Hex };
    const setKeyHash = await wallet.writeContract({
      address: dilithiumVerifier, abi: dilithiumArt.abi,
      functionName: 'setKey', args: [postQuantumPubKey], gas: 30_000_000n,
    });
    await publicClient.waitForTransactionReceipt({ hash: setKeyHash });

    const ok = await publicClient.readContract({
      address: dilithiumVerifier, abi: dilithiumArt.abi,
      functionName: 'verify',
      args: [pkPointer, demo.challenge as Hex, demo.sig as Hex, '0x'],
    });
    assert.equal(ok, true,
      'blinded-key signature must verify through the on-chain ZKNOX verifier');
    const verifyGas = await publicClient.estimateContractGas({
      address: dilithiumVerifier, abi: dilithiumArt.abi,
      functionName: 'verify',
      args: [pkPointer, demo.challenge as Hex, demo.sig as Hex, '0x'],
      account: wallet.account,
    });
    console.log(`    on-chain blinded-sig verify gas: ~${verifyGas}`);
  } finally {
    anvil.kill();
  }
});
