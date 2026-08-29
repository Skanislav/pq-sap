/**
 * Conformance checks: the UI's in-browser crypto must reproduce the Python
 * reference vectors byte-identically. Run with node >= 22 (type stripping):
 *
 *   npm run check-keygen
 *
 *  1. ML-DSA-65 scheme keygen (python/vectors/v0): meta-address + viewing key
 *  2. classical-spend hybrid (python/vectors/classical/v0): keygen, sender
 *     derivation, scanner detection, and the derived spending key
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';

import { deriveMetaAddress } from '../src/lib/keygen.ts';
import {
  deriveClassicalKeys, decodeClassicalMeta, deriveStealthPubkey,
  deriveStealthPrivkey, ethAddressOfPoint, classicalViewTag,
  checkClassicalAnnouncement, encodeCompactMeta, decodeCompactMeta,
} from '../src/lib/classical.ts';
import { fromHex, toHex } from '../src/lib/hex.ts';

const load = (rel: string) => JSON.parse(readFileSync(
  fileURLToPath(new URL(rel, import.meta.url)), 'utf8'));

// ---------------------------------------------------------------------------
// 1. ML-DSA-65 scheme keygen
// ---------------------------------------------------------------------------
const vectors = load('../../python/vectors/v0/vectors.json');
for (const [name, rec] of Object.entries<{
  seeds: { zeta: string; kem_d: string; kem_z: string };
  meta_address: string; kem_dk: string;
}>(vectors.recipients)) {
  const keys = deriveMetaAddress({
    zeta: fromHex(rec.seeds.zeta),
    kemD: fromHex(rec.seeds.kem_d),
    kemZ: fromHex(rec.seeds.kem_z),
  });
  assert.equal(toHex(keys.metaAddress), rec.meta_address,
    `recipient ${name}: meta-address mismatch`);
  assert.equal(toHex(keys.kemDk), rec.kem_dk,
    `recipient ${name}: viewing key mismatch`);
  console.log(`ml-dsa-65 recipient ${name}: meta-address + viewing key byte-identical ✓`);
}

// ---------------------------------------------------------------------------
// 2. classical-spend hybrid
// ---------------------------------------------------------------------------
const cv = load('../../python/vectors/classical/v0/vectors.json');
const classicalKeys: Record<string, ReturnType<typeof deriveClassicalKeys>> = {};
for (const [name, rec] of Object.entries<{
  seeds: { spend_seed: string; kem_d: string; kem_z: string };
  meta_address: string; spend_priv: string; kem_dk: string;
}>(cv.recipients)) {
  const keys = deriveClassicalKeys({
    spendSeed: fromHex(rec.seeds.spend_seed),
    kemD: fromHex(rec.seeds.kem_d),
    kemZ: fromHex(rec.seeds.kem_z),
  });
  assert.equal(toHex(keys.metaAddress), rec.meta_address,
    `classical ${name}: meta-address mismatch`);
  assert.equal(toHex(keys.kemDk), rec.kem_dk,
    `classical ${name}: viewing key mismatch`);
  assert.equal(toHex(keys.seeds.spendSeed), rec.spend_priv,
    `classical ${name}: spend seed is the spending secret`);
  classicalKeys[name] = keys;
  console.log(`classical recipient ${name}: meta-address + viewing key byte-identical ✓`);
}

for (const c of cv.cases as Array<{
  name: string; recipient: string; encaps_m?: string;
  announcement: { stealth_address: string; ephemeral_pub_key: string; view_tag: string };
  stealth_pub?: string; expect: 'match' | 'no_match' | 'valid_proof';
  challenge?: string; signature?: string; spend_key?: string;
}>) {
  const keys = classicalKeys[c.recipient]!;
  const meta = decodeClassicalMeta(keys.metaAddress);
  const ann = {
    stealthAddress: fromHex(c.announcement.stealth_address),
    ephemeralPubKey: fromHex(c.announcement.ephemeral_pub_key),
    viewTag: fromHex(c.announcement.view_tag),
  };

  if (c.encaps_m) {
    // sender side: deterministic encapsulation must reproduce the announcement
    const { cipherText, sharedSecret } =
      ml_kem768.encapsulate(meta.kemEk, fromHex(c.encaps_m));
    assert.equal(toHex(cipherText), c.announcement.ephemeral_pub_key,
      `${c.name}: ciphertext mismatch`);
    assert.equal(toHex(classicalViewTag(sharedSecret)), c.announcement.view_tag,
      `${c.name}: view tag mismatch`);
    const P = deriveStealthPubkey(meta.spendPub, sharedSecret);
    if (c.stealth_pub)
      assert.equal(toHex(P.toBytes(true)), c.stealth_pub,
        `${c.name}: stealth pubkey mismatch`);
    assert.equal(toHex(ethAddressOfPoint(P)), c.announcement.stealth_address,
      `${c.name}: stealth address mismatch`);
    // recipient side: derived private key must control the same EOA
    const priv = deriveStealthPrivkey(keys.seeds.spendSeed, sharedSecret);
    const PfromPriv = secp256k1.Point.BASE.multiply(BigInt(toHex(priv)));
    assert.equal(toHex(ethAddressOfPoint(PfromPriv)), c.announcement.stealth_address,
      `${c.name}: derived spending key does not control the stealth EOA`);
  }

  if (c.expect === 'valid_proof') {
    // possession: the derived spending key signs (RFC 6979) and verifies
    const payment = checkClassicalAnnouncement(meta, keys.kemDk, ann);
    assert.ok(payment, `${c.name}: possession announcement must be detected`);
    const priv = deriveStealthPrivkey(keys.seeds.spendSeed, payment.sharedSecret);
    assert.equal(toHex(priv), c.spend_key!, `${c.name}: spend key mismatch`);
    const rs = fromHex(c.signature!).slice(0, 64);
    assert.ok(secp256k1.verify(rs, fromHex(c.challenge!), payment.stealthPk, { prehash: false }),
      `${c.name}: ECDSA possession signature must verify under the stealth pubkey`);
  } else {
    const detected = checkClassicalAnnouncement(meta, keys.kemDk, ann) !== null;
    assert.equal(detected, c.expect === 'match', `${c.name}: detection mismatch`);
  }
  console.log(`classical case ${c.name}: ${c.expect} ✓`);
}

// compact 65-byte meta-address (the "ecrecover trick" format) round-trips,
// and the spend pubkey it carries matches the full meta-address's
{
  const keys = classicalKeys.A!;
  const meta = decodeClassicalMeta(keys.metaAddress);
  for (const index of [0n, 1n, 42n, (1n << 255n) + 7n]) {
    const compact = encodeCompactMeta(meta.spendPub, index);
    assert.equal(compact.length, 65, 'compact meta must be 65 bytes');
    const decoded = decodeCompactMeta(compact);
    assert.equal(decoded.index, index, `compact index ${index} round-trip`);
    assert.equal(toHex(decoded.spendPub), toHex(meta.spendPub),
      'compact meta must carry the same spend pubkey inline');
    assert.ok(compact[0] === 0x02 || compact[0] === 0x03,
      'version byte is the SEC1 parity prefix');
  }
  console.log('compact 65-byte meta-address: encode/decode round-trip ✓');
}

console.log('keygen + classical conformance: OK');
