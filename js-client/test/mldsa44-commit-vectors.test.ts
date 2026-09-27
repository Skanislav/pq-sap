/**
 * Conformance: replay python/vectors/v0/mldsa44_commit_vectors.json through the TS
 * profile layer — explicit profile selection, ML-DSA-44 key commitment, opener /
 * commitment / view tag / CREATE2 address, viewing-key scan, and every authorization
 * payload re-verified with an independent ML-DSA-44 implementation (@noble/post-quantum),
 * positives and negatives alike.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { hexToBytes, keccak256, type Address, type Hex } from 'viem';

import { accountAddress, decodeCommitMetaAddress, deriveCommitment, deriveOpener, type CommitAnnouncementData, type Deployment } from '../src/commit-scheme.ts';
import {
  bindingForChain, buildAuthorization, checkWithProfile, mlDsa44Recipient, parseAuthorization, profileName, selectProfile,
  sendWithProfile, spendKeyFromMlDsaPk, verifyAuthorization, ML_DSA_44_COMMIT_V0, ML_DSA_44_DOMAINS, ML_DSA_44_KEY_DOMAIN,
  PROFILES, ProfileError,
} from '../src/profiles.ts';

const VECTORS_PATH = fileURLToPath(new URL('../../python/vectors/v0/mldsa44_commit_vectors.json', import.meta.url));

interface Ann { stealth_address: string; ephemeral_pub_key: string; view_tag: string }
interface Case { name: string; recipient: 'm' | 'n'; expect: 'match' | 'no_match'; announcement: Ann; shared_secret?: string; opener?: string; commitment?: string }
interface Auth { name: string; commitment: string; digest: string; payload: string; expect: boolean; note: string }
interface Recipient { zeta: string; ml_dsa_pk: string; spend_key: string; meta_address: string; kem_dk: string }
interface Doc {
  profile: { name: string; pk_bytes: number; sig_bytes: number; payload_bytes: number; domains: { key: string; open: string; commit: string } };
  binding: { chain_id: number; factory: string; creation_code: string; verifier: string; frame_ctx: string; salt: string };
  recipients: Record<'m' | 'n', Recipient>;
  cases: Case[];
  authorizations: Auth[];
  linkage: { revealed_spend_key: string };
}

const doc = JSON.parse(readFileSync(VECTORS_PATH, 'utf8')) as Doc;
const dep: Deployment = {
  factory: doc.binding.factory as Address, creationCode: doc.binding.creation_code as Hex,
  verifier: doc.binding.verifier as Address, frameCtx: doc.binding.frame_ctx as Address, salt: doc.binding.salt as Hex,
};
const binding = selectProfile(doc.profile.name, doc.binding.chain_id, dep);
const toAnn = (a: Ann): CommitAnnouncementData => ({
  stealthAddress: a.stealth_address as Address, ephemeralPubKey: hexToBytes(a.ephemeral_pub_key as Hex), viewTag: hexToBytes(a.view_tag as Hex),
});

test('profile constants agree with the Python reference', () => {
  assert.equal(profileName(ML_DSA_44_COMMIT_V0), 'ml-dsa-44-commit/v0');
  assert.deepEqual([...PROFILES.keys()].sort(), ['ml-dsa-44-commit/v0', 'preimage/v0', 'sphincs-c13-commit/v0']);
  assert.equal(ML_DSA_44_KEY_DOMAIN, doc.profile.domains.key);
  assert.equal(ML_DSA_44_DOMAINS.open, doc.profile.domains.open);
  assert.equal(ML_DSA_44_DOMAINS.commit, doc.profile.domains.commit);
  assert.equal(ML_DSA_44_COMMIT_V0.authorization.pkBytes, doc.profile.pk_bytes);
  assert.equal(ML_DSA_44_COMMIT_V0.authorization.sigBytes, doc.profile.sig_bytes);
  assert.equal(ml_dsa44.lengths.publicKey, doc.profile.pk_bytes);
  assert.equal(ml_dsa44.lengths.signature, doc.profile.sig_bytes);
});

test('profile selection fails closed', () => {
  assert.throws(() => selectProfile('ml-dsa-65-commit/v0', 1, dep), ProfileError);
  assert.throws(() => selectProfile('ml-dsa-44-commit/v1', 1, dep), ProfileError);
  assert.throws(() => selectProfile('ml-dsa-44-commit/v0', 0, dep), ProfileError);
  assert.throws(() => selectProfile('ml-dsa-44-commit/v0', 1, { ...dep, factory: '0x12' as Address }), ProfileError);
  assert.throws(() => selectProfile('ml-dsa-44-commit/v0', 1, { ...dep, creationCode: '0x' }), ProfileError);
  assert.throws(() => bindingForChain(binding, doc.binding.chain_id + 1), ProfileError);
  assert.equal(bindingForChain(binding, doc.binding.chain_id), binding);
});

test('recipient keys: spend key is one keccak over the domain and the canonical pk', () => {
  for (const r of Object.values(doc.recipients)) {
    const pk = hexToBytes(r.ml_dsa_pk as Hex);
    assert.equal(pk.length, 1312);
    assert.equal(spendKeyFromMlDsaPk(pk), r.spend_key);
    const dom = new TextEncoder().encode(ML_DSA_44_KEY_DOMAIN);
    const buf = new Uint8Array(dom.length + pk.length); buf.set(dom); buf.set(pk, dom.length);
    assert.equal(keccak256(buf), r.spend_key);
    // noble's FIPS 204 keygen from the same seed yields the same key as dilithium-py
    const rec = mlDsa44Recipient(hexToBytes(r.zeta as Hex));
    assert.deepEqual(rec.publicKey, pk);
    assert.equal(rec.spendKey, r.spend_key);
    const meta = decodeCommitMetaAddress(hexToBytes(r.meta_address as Hex));
    assert.equal(meta.spendKey, r.spend_key);
  }
  assert.throws(() => spendKeyFromMlDsaPk(new Uint8Array(1952)), ProfileError); // ML-DSA-65 size
});

for (const c of doc.cases) {
  test(`${c.name}: ${c.expect}`, () => {
    const r = doc.recipients[c.recipient];
    const meta = decodeCommitMetaAddress(hexToBytes(r.meta_address as Hex));
    const hit = checkWithProfile(meta, hexToBytes(r.kem_dk as Hex), toAnn(c.announcement), binding);
    if (c.expect === 'no_match') { assert.equal(hit, null); return; }
    assert.ok(hit);
    assert.equal(`0x${Buffer.from(hit.sharedSecret).toString('hex')}`, c.shared_secret);
    assert.equal(hit.opener, c.opener);
    assert.equal(hit.commitment, c.commitment);
    assert.equal(deriveCommitment(meta.spendKey, deriveOpener(hit.sharedSecret, ML_DSA_44_DOMAINS), ML_DSA_44_DOMAINS), c.commitment);
    assert.equal(accountAddress(hit.commitment, dep).toLowerCase(), c.announcement.stealth_address);
    const sent = sendWithProfile(meta, binding, { cipherText: hexToBytes(c.announcement.ephemeral_pub_key as Hex), sharedSecret: hit.sharedSecret }, );
    assert.equal(sent.announcement.stealthAddress.toLowerCase(), c.announcement.stealth_address);
    assert.deepEqual(sent.announcement.viewTag, hexToBytes(c.announcement.view_tag as Hex));
    // the same announcement is not a payment under another profile's domains
    const c13 = selectProfile('sphincs-c13-commit/v0', doc.binding.chain_id, dep);
    assert.equal(checkWithProfile(meta, hexToBytes(r.kem_dk as Hex), toAnn(c.announcement), c13), null);
  });
}

for (const a of doc.authorizations) {
  test(`authorization ${a.name}: ${a.expect} (${a.note})`, () => {
    const payload = hexToBytes(a.payload as Hex);
    const digest = hexToBytes(a.digest as Hex);
    assert.equal(verifyAuthorization(a.commitment as Hex, digest, payload), a.expect);
    if (a.expect) {
      // independent verifier on the signature itself, and the parts agree with the vector
      const { pk, opener, sig } = parseAuthorization(payload);
      assert.ok(ml_dsa44.verify(sig, digest, pk));
      assert.equal(deriveCommitment(spendKeyFromMlDsaPk(pk), opener, ML_DSA_44_DOMAINS), a.commitment);
      // the TS signer reproduces the deterministic Python signature byte for byte
      const rec = mlDsa44Recipient(hexToBytes(doc.recipients.m.zeta as Hex));
      assert.deepEqual(buildAuthorization(rec.secretKey, rec.publicKey, opener, digest, ML_DSA_44_COMMIT_V0, true), payload);
    }
  });
}

test('two direct spends reveal the same pk, whose hash is the published spend key (linkable)', () => {
  const valid = doc.authorizations.filter((a) => a.expect);
  assert.equal(valid.length, 2);
  const [p1, p2] = valid.map((a) => parseAuthorization(hexToBytes(a.payload as Hex)));
  assert.deepEqual(p1!.pk, p2!.pk);
  assert.notEqual(p1!.opener, p2!.opener);
  assert.equal(spendKeyFromMlDsaPk(p1!.pk), doc.recipients.m.spend_key);
  assert.equal(doc.linkage.revealed_spend_key, doc.recipients.m.spend_key);
});

test('sender-known values cannot authorize: a key derived from ss signs but does not open the commitment', () => {
  const c = doc.cases[0]!;
  const ss = hexToBytes(c.shared_secret as Hex);
  const digest = new Uint8Array(32).fill(7);
  const attacker = ml_dsa44.keygen(keccak256(ss, 'bytes'));
  const payload = buildAuthorization(attacker.secretKey, attacker.publicKey, c.opener as Hex, digest);
  assert.ok(ml_dsa44.verify(parseAuthorization(payload).sig, digest, attacker.publicKey));
  assert.equal(verifyAuthorization(c.commitment as Hex, digest, payload), false);
});
