/**
 * Conformance: replay python/vectors/v0/native_key.json through the TS
 * EIP-8164 crafted-authorization derivation. The Python reference produced
 * r / msg_hash / address from the stealth pk; the port must agree byte for byte.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { hexToBytes } from 'viem';

import {
  craftAuthorization, craftedR, isValidX, nativeKeyCode, nativeKeyStealthAddress,
  ML_DSA_44_PK_BYTES, SECP_N, SECP_P,
} from '../src/native-key.ts';

const VECTORS_PATH = fileURLToPath(
  new URL('../../python/vectors/v0/native_key.json', import.meta.url));

interface Case {
  chain_id: number; nonce: number; y_parity: number;
  r: string; s: string; msg_hash: string; address: string; code_prefix: string;
}
interface Doc { stealth_pk: string; cases: Case[] }

const doc = JSON.parse(readFileSync(VECTORS_PATH, 'utf8')) as Doc;
const pk = hexToBytes(doc.stealth_pk as `0x${string}`);

test('vector pk is an ML-DSA-44 public key', () => {
  assert.equal(pk.length, ML_DSA_44_PK_BYTES);
});

for (const c of doc.cases) {
  test(`chain ${c.chain_id}: crafted tuple and address match the Python reference`, async () => {
    const auth = await craftAuthorization(pk, BigInt(c.chain_id), BigInt(c.nonce));
    assert.equal(auth.yParity, c.y_parity);
    assert.equal(`0x${auth.r.toString(16).padStart(64, '0')}`, c.r);
    assert.equal(`0x${auth.s.toString(16).padStart(64, '0')}`, c.s);
    assert.equal(auth.msgHash, c.msg_hash);
    assert.equal(auth.address.toLowerCase(), c.address);
    assert.equal(await nativeKeyStealthAddress(pk, BigInt(c.chain_id)), auth.address);
    assert.equal(`0x${Buffer.from(nativeKeyCode(pk).subarray(0, 3)).toString('hex')}`, c.code_prefix);
  });
}

test('r is the smallest valid x-coordinate at or above r_seed mod p', () => {
  const { rSeed, r } = craftedR(1n, pk);
  let start = 0n;
  for (const b of rSeed) start = (start << 8n) | BigInt(b);
  start %= SECP_P;
  assert.ok(r >= start && r < SECP_N && isValidX(r));
  for (let x = start; x < r; x++) assert.ok(!(x < SECP_N && isValidX(x)));
});

test('rejects a non-44 key', async () => {
  await assert.rejects(craftAuthorization(new Uint8Array(1952), 1n));
});
