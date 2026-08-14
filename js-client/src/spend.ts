/**
 * ERC-4337 spend path for the ZKNOX hybrid stealth account.
 *
 * Builds a v0.7 PackedUserOperation calling account.execute(dest, value, ""),
 * signs the userOpHash with BOTH keys (hybrid AND):
 *   - pre-quantum: raw secp256k1 over the hash, r||s||v
 *   - post-quantum: the blinded stealth key, via the Python demo script
 * and submits it self-bundled through EntryPoint.handleOps.
 *
 * The pre-quantum demo key is DETERMINISTIC AND PUBLIC (testnet only!) —
 * anyone can recompute it; do not send real value to accounts using it.
 */

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  parseAbi, keccak256, stringToHex, encodeFunctionData, toHex, concatHex,
  encodeAbiParameters,
  type Hex, type Address, type PublicClient,
} from 'viem';
import { privateKeyToAccount, sign } from 'viem/accounts';

export const ENTRYPOINT_V07 =
  '0x0000000071727De22E5E9d8BAf0edAc6f37da032' as Address;

export const ENTRYPOINT_ABI = parseAbi([
  'struct PackedUserOperation { address sender; uint256 nonce; bytes initCode; bytes callData; bytes32 accountGasLimits; uint256 preVerificationGas; bytes32 gasFees; bytes paymasterAndData; bytes signature; }',
  'function getUserOpHash(PackedUserOperation userOp) view returns (bytes32)',
  'function getNonce(address sender, uint192 key) view returns (uint256)',
  'function handleOps(PackedUserOperation[] ops, address beneficiary)',
  'function balanceOf(address account) view returns (uint256)',
  'error FailedOp(uint256 opIndex, string reason)',
  'error FailedOpWithRevert(uint256 opIndex, string reason, bytes inner)',
]);

export const ACCOUNT_ABI = parseAbi([
  'function execute(address target, uint256 value, bytes data)',
]);

/** Deterministic, PUBLIC throwaway key for the pre-quantum half. */
export function preQuantumDemoKey() {
  const priv = keccak256(stringToHex('pq-stealth spend demo prequantum key v0'));
  const account = privateKeyToAccount(priv);
  return { priv, address: account.address };
}

const packPair = (hi: bigint, lo: bigint): Hex =>
  toHex((hi << 128n) | lo, { size: 32 });

export interface UserOp {
  sender: Address; nonce: bigint; initCode: Hex; callData: Hex;
  accountGasLimits: Hex; preVerificationGas: bigint; gasFees: Hex;
  paymasterAndData: Hex; signature: Hex;
}

/** maxFeePerGas × total gas limits — what the account must hold (beyond
 *  the transfer value) to pass the EntryPoint's AA21 prefund check. */
export function requiredPrefund(op: UserOp): bigint {
  const maxFee = BigInt(op.gasFees) & ((1n << 128n) - 1n);
  const verification = BigInt(op.accountGasLimits) >> 128n;
  const call = BigInt(op.accountGasLimits) & ((1n << 128n) - 1n);
  return maxFee * (verification + call + op.preVerificationGas);
}

export async function buildSpendUserOp(
  publicClient: PublicClient, account: Address, dest: Address, value: bigint,
  opts: { verificationGas?: bigint } = {},
): Promise<UserOp> {
  const nonce = await publicClient.readContract({
    address: ENTRYPOINT_V07, abi: ENTRYPOINT_ABI,
    functionName: 'getNonce', args: [account, 0n],
  });
  const gasPrice = await publicClient.getGasPrice();
  const maxFee = gasPrice * 2n < 1_500_000_000n ? 1_500_000_000n : gasPrice * 2n;
  // one ML-DSA verify is ~8M gas; a dual-PQ account needs headroom for two
  const verificationGas = opts.verificationGas ?? 12_000_000n;
  return {
    sender: account,
    nonce,
    initCode: '0x',
    callData: encodeFunctionData({
      abi: ACCOUNT_ABI, functionName: 'execute', args: [dest, value, '0x'],
    }),
    accountGasLimits: packPair(verificationGas, 200_000n), // verification | call
    preVerificationGas: 150_000n,
    gasFees: packPair(1_000_000_000n, maxFee),          // priority | max
    paymasterAndData: '0x',
    signature: '0x',
  };
}

const PY = process.env.PQ_PYTHON
  ?? '/private/tmp/claude-501/-Users-skas-Ethereum-git-erc-5567/3bbf0a8c-f678-4091-af33-dbab7934a47e/scratchpad/pqvenv/bin/python';
const PYTHONREF = process.env.ZKNOX_PYTHONREF
  ?? '/private/tmp/claude-501/-Users-skas-Ethereum-git-erc-5567/3bbf0a8c-f678-4091-af33-dbab7934a47e/scratchpad/kohaku/packages/pq-account/lib/ETHDILITHIUM/pythonref';
const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));

/** Sign a 32-byte hash with the blinded stealth key (Python, deterministic
 *  seeds — same key as public_key_data in zknox_demo.json). */
export function signWithBlindedKey(userOpHash: Hex): Hex {
  const out = `${process.env.TMPDIR ?? '/tmp'}/zknox_spend_sig.json`;
  const r = spawnSync(PY, [
    here('../../python/scripts/zknox_counterfactual_demo.py'),
    '--pythonref', PYTHONREF, '--sign-challenge', userOpHash, '-o', out,
  ], { encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`blinded signing failed: ${r.stderr}`);
  const { sig, challenge } = JSON.parse(readFileSync(out, 'utf8'));
  if (challenge !== userOpHash.toLowerCase())
    throw new Error('signed challenge mismatch');
  return sig as Hex;
}

export async function signUserOp(userOpHash: Hex): Promise<Hex> {
  const { priv } = preQuantumDemoKey();
  const ecdsa = await sign({ hash: userOpHash, privateKey: priv });
  const preSig = concatHex([
    ecdsa.r, ecdsa.s,
    toHex(Number(ecdsa.v ?? BigInt((ecdsa.yParity ?? 0) + 27)), { size: 1 }),
  ]);
  const postSig = signWithBlindedKey(userOpHash);
  return encodeAbiParameters(
    [{ type: 'bytes' }, { type: 'bytes' }], [preSig, postSig]);
}
