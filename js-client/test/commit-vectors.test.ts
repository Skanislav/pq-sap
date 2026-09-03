/**
 * Conformance: replay python/vectors/v0/commit_vectors.json through the TS
 * commitment-scheme client — encoding, opener/commitment derivation, CREATE2
 * binding, and the viewing-key scan must agree with the Python reference.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { hexToBytes, type Address, type Hex } from 'viem';

import {
  accountAddress, checkCommitAnnouncement, decodeCommitMetaAddress, deriveCommitment, deriveOpener,
  encodeCommitMetaAddress, scanCommit, sendCommit, COMMIT_META_ADDRESS_BYTES, type CommitAnnouncementData, type Deployment,
} from '../src/commit-scheme.ts';

const VECTORS_PATH = fileURLToPath(new URL('../../python/vectors/v0/commit_vectors.json', import.meta.url));

interface Ann { stealth_address: string; ephemeral_pub_key: string; view_tag: string }
interface Case {
  name: string; recipient: 'a' | 'b'; expect: 'match' | 'no_match'; announcement: Ann;
  shared_secret?: string; opener?: string; commitment?: string;
}
interface Doc {
  deployment: { factory: string; creation_code: string; verifier: string; frame_ctx: string; salt: string };
  recipients: Record<'a' | 'b', { spend_key: string; meta_address: string; kem_dk: string }>;
  cases: Case[];
}

const doc = JSON.parse(readFileSync(VECTORS_PATH, 'utf8')) as Doc;
const dep: Deployment = {
  factory: doc.deployment.factory as Address, creationCode: doc.deployment.creation_code as Hex,
  verifier: doc.deployment.verifier as Address, frameCtx: doc.deployment.frame_ctx as Address, salt: doc.deployment.salt as Hex,
};
const toAnn = (a: Ann): CommitAnnouncementData => ({
  stealthAddress: a.stealth_address as Address, ephemeralPubKey: hexToBytes(a.ephemeral_pub_key as Hex), viewTag: hexToBytes(a.view_tag as Hex),
});

test('meta-address encodes to 1,217 bytes and round-trips', () => {
  for (const r of Object.values(doc.recipients)) {
    const bytes = hexToBytes(r.meta_address as Hex);
    assert.equal(bytes.length, COMMIT_META_ADDRESS_BYTES);
    const meta = decodeCommitMetaAddress(bytes);
    assert.equal(meta.spendKey, r.spend_key);
    assert.deepEqual(encodeCommitMetaAddress(meta.spendKey, meta.kemEk), bytes);
  }
});

for (const c of doc.cases) {
  test(`${c.name}: ${c.expect}`, () => {
    const r = doc.recipients[c.recipient];
    const meta = decodeCommitMetaAddress(hexToBytes(r.meta_address as Hex));
    const hit = checkCommitAnnouncement(meta, hexToBytes(r.kem_dk as Hex), toAnn(c.announcement), dep);
    if (c.expect === 'no_match') {
      assert.equal(hit, null);
      return;
    }
    assert.ok(hit);
    assert.equal(`0x${Buffer.from(hit.sharedSecret).toString('hex')}`, c.shared_secret);
    assert.equal(hit.opener, c.opener);
    assert.equal(hit.commitment, c.commitment);
    assert.equal(deriveCommitment(meta.spendKey, deriveOpener(hit.sharedSecret)), c.commitment);
    assert.equal(accountAddress(hit.commitment, dep).toLowerCase(), c.announcement.stealth_address);
    // sender side with the same shared secret reproduces the announcement
    const sent = sendCommit(meta, dep, { cipherText: hexToBytes(c.announcement.ephemeral_pub_key as Hex), sharedSecret: hit.sharedSecret });
    assert.equal(sent.announcement.stealthAddress.toLowerCase(), c.announcement.stealth_address);
    assert.deepEqual(sent.announcement.viewTag, hexToBytes(c.announcement.view_tag as Hex));
  });
}

test('scan finds exactly the matching announcements', () => {
  const r = doc.recipients.a;
  const meta = decodeCommitMetaAddress(hexToBytes(r.meta_address as Hex));
  // the no_match case re-uses a-1's announcement, so scan the distinct announcements
  const seen = new Set<string>();
  const anns = doc.cases.filter((c) => !seen.has(c.announcement.stealth_address) && seen.add(c.announcement.stealth_address))
    .map((c) => toAnn(c.announcement));
  const hits = scanCommit(meta, hexToBytes(r.kem_dk as Hex), anns, dep);
  assert.equal(hits.length, doc.cases.filter((c) => c.recipient === 'a' && c.expect === 'match').length);
  assert.deepEqual(hits.map((h) => h.commitment).sort(), doc.cases.filter((c) => c.recipient === 'a' && c.expect === 'match').map((c) => c.commitment!).sort());
});
