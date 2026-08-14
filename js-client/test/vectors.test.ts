/**
 * Conformance: replay python/vectors/v0/vectors.json through the TS client.
 * This is the cross-implementation check the vectors exist for — the
 * Python reference produced them, an independent port must agree.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

import {
  decodeMetaAddress, checkAnnouncement, stealthAddressOf,
  META_ADDRESS_BYTES,
  type AnnouncementData,
} from '../src/scheme.ts';

const VECTORS_PATH = fileURLToPath(
  new URL('../../python/vectors/v0/vectors.json', import.meta.url));

interface VectorAnnouncement {
  stealth_address: string;
  ephemeral_pub_key: string;
  view_tag: string;
}

interface VectorCase {
  name: string;
  recipient: string;
  announcement: VectorAnnouncement;
  expect: 'match' | 'no_match' | 'valid_proof';
  stealth_pk?: string;
  challenge?: string;
  proof?: string;
}

interface VectorDoc {
  params: string;
  sizes: { meta_address: number; stealth_pk: number };
  recipients: Record<string, { meta_address: string; kem_dk: string }>;
  cases: VectorCase[];
}

const doc: VectorDoc = JSON.parse(readFileSync(VECTORS_PATH, 'utf8'));

const unhex = (s: string): Uint8Array =>
  Uint8Array.from(Buffer.from(s.slice(2), 'hex'));

const recipients = Object.fromEntries(
  Object.entries(doc.recipients).map(([name, rec]) => [name, {
    meta: decodeMetaAddress(unhex(rec.meta_address)),
    kemDk: unhex(rec.kem_dk),
  }]));

const toAnn = (a: VectorAnnouncement): AnnouncementData => ({
  stealthAddress: unhex(a.stealth_address),
  ephemeralPubKey: unhex(a.ephemeral_pub_key),
  viewTag: unhex(a.view_tag),
});

test('vector metadata matches the client constants', () => {
  assert.equal(doc.params, 'ML-KEM-768+ML-DSA-65');
  assert.equal(doc.sizes.meta_address, META_ADDRESS_BYTES);
  assert.equal(doc.sizes.stealth_pk, 1952);
});

for (const vcase of doc.cases) {
  test(`case ${vcase.name}`, () => {
    const { meta, kemDk } = recipients[vcase.recipient]!;
    const payment = checkAnnouncement(meta, kemDk, toAnn(vcase.announcement));

    if (vcase.expect === 'no_match') {
      assert.equal(payment, null);
      return;
    }

    assert.notEqual(payment, null, 'expected a match');
    if (vcase.stealth_pk) {
      assert.deepEqual(payment!.stealthPk, unhex(vcase.stealth_pk),
        'derived stealth pk must equal the Python reference');
    }
    assert.deepEqual(stealthAddressOf(payment!.stealthPk),
      toAnn(vcase.announcement).stealthAddress);

    if (vcase.expect === 'valid_proof') {
      // possession proof: standard ML-DSA-65 signature over the challenge
      // with ctx = "pq-stealth/pop/v0" || stealth_address
      const ctx = Uint8Array.from([
        ...new TextEncoder().encode('pq-stealth/pop/v0'),
        ...toAnn(vcase.announcement).stealthAddress,
      ]);
      const ok = ml_dsa65.verify(unhex(vcase.proof!), unhex(vcase.challenge!),
        payment!.stealthPk, { context: ctx });
      assert.equal(ok, true, 'possession proof must verify under noble');
    }
  });
}
