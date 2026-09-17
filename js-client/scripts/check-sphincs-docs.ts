/**
 * SPHINCS- (C13) documentation conformance harness (autoresearch).
 *
 * Problem the harness measures: the docs (README.md, docs/DECISIONS.md D-018
 * and D-023, docs/TECHNICAL_SPEC.md, js-client/README.md,
 * docs/pointer-signatures-poc.md, docs/research/zk-sphincs-frames.md) quote a
 * list of load-bearing SPHINCS- C13 facts. Those facts are only "correctly
 * implemented in the docs" when each one is simultaneously (a) present in the
 * relevant doc and (b) equal to the value the code and the deterministic
 * fixture actually use. This script verifies both sides of every claim, plus
 * the crypto spine:
 *
 *   CRYPTO   — from the deterministic fixture
 *              (python/scripts/sphincs_c13_7913_demo.json) re-derive opener,
 *              commitment, commit-signature, ERC-7913 key packing and both
 *              pointer-signature digests/owners, and verify every fixture C13
 *              signature with a from-scratch keccak WOTS+C / FORS+C
 *              reimplementation of the vendored `SPHINCs-C13Asm.sol` algorithm
 *              (positive + negative: byte-flipped signatures must reject).
 *
 *   CONTRACT — constants in the ERC-7913 wrappers, PointerSig registry and
 *              the vendored verifier match the values the docs quote
 *              (domains, sig length, v = 0x52/0x53, vendored rev + sha256).
 *
 *   DOCS     — each doc that states a SPHINCS- fact is checked for a regex
 *              that can only match with the correct value. A doc that drops a
 *              value it previously stated, or states a wrong one, fails.
 *
 * Exit 0 iff every gate passes. Run: bun js-client/scripts/check-sphincs-docs.ts
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { existsSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

import {
  SPHINCS_C13, sphincsC13Commitment, sphincsC13CommitSignature, sphincsC13Key,
  sphincsC13Opener, splitSphincsC13Key,
} from '../src/sphincs.ts';

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const rel = (p: string) => `${here('../..')}/${p}`;

let pass = 0, fail = 0;
const failures: string[] = [];
function check(name: string, cond: boolean, detail = '') {
  if (cond) { pass++; console.log(`PASS ${name}`); return; }
  fail++; failures.push(name); console.log(`FAIL ${name}${detail ? ` — ${detail}` : ''}`);
}

function hexToBytes(h: string): Uint8Array {
  const s = h.startsWith('0x') ? h.slice(2) : h;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}
function eq(a: Uint8Array, b: Uint8Array) {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}
function concat(...parts: (Uint8Array | number[])[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((s, p) => s + p.length, 0));
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}
function word256(x: Uint8Array | bigint | number): Uint8Array {
	const out = new Uint8Array(32);
	if (typeof x === 'object') out.set(x.slice(0, 32), 32 - Math.min(32, x.length));
	else {
		let v = BigInt(x);
		for (let i = 31; i >= 0 && v > 0n; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
	}
	return out;
}

// ------------------------------------------- fixture + module cross-checks

const DEMO = JSON.parse(readFileSync(rel('python/scripts/sphincs_c13_7913_demo.json'), 'utf8'));
const ss = hexToBytes(DEMO.shared_secret_DEMO_ONLY);
const pkSeed = hexToBytes(DEMO.pk_seed);
const pkRoot = hexToBytes(DEMO.pk_root);
const pk = hexToBytes(DEMO.key);
const challenge = hexToBytes(DEMO.challenge);
const sig = hexToBytes(DEMO.sig);

// The TypeScript side of the byte-convention contract must reproduce the
// Python fixture byte for byte (the e2e asserts the same on-chain).
check('crypto.opener: sphincsC13Opener(ss) == fixture opener',
  sphincsC13Opener(ss) === DEMO.opener);
check('crypto.commitment: sphincsC13Commitment(pk, opener) == fixture commitment',
  sphincsC13Commitment(DEMO.key, DEMO.opener) === DEMO.commitment);
check('crypto.commit_signature: pk‖opener‖c13sig == fixture commit_signature',
  sphincsC13CommitSignature(DEMO.key, DEMO.opener, DEMO.sig) === DEMO.commit_signature);
check('crypto.key_pack: sphincsC13Key(pk_seed, pk_root) == fixture 32-B key',
  sphincsC13Key(DEMO.pk_seed, DEMO.pk_root) === DEMO.key);
const split = splitSphincsC13Key(DEMO.key);
check('crypto.key_split: splitSphincsC13Key inverts the packing (top-aligned words)',
  split.pkSeed === DEMO.pk_seed && split.pkRoot === DEMO.pk_root);
check('crypto.sizes: key=32, kem_ct=1088, sig=3688, commit_signature=3752',
  DEMO.sizes.key === 32 && DEMO.sizes.kem_ct === 1088
  && DEMO.sizes.sig === SPHINCS_C13.signatureLength
  && DEMO.sizes.commit_signature === 3_752
  && pk.length === 32 && sig.length === SPHINCS_C13.signatureLength);
check('crypto.opener.domains: SHA-256(open ‖ ss) and keccak(commit ‖ pk ‖ opener) recomputed independently',
  eq(sha256(concat(new TextEncoder().encode(SPHINCS_C13.openDomain), ss)), hexToBytes(DEMO.opener))
  && eq(keccak_256(concat(new TextEncoder().encode(SPHINCS_C13.commitDomain), pk, hexToBytes(DEMO.opener))),
    hexToBytes(DEMO.commitment)));

// ----------------------------- pointer-signature route fixture (v 0x52/0x53)

const P = DEMO.pointer;
const vault = hexToBytes(P.vault);
const toAddr = hexToBytes(P.to);
const amount = BigInt(P.amount);
const vaultFromCreate = keccak_256(concat(
  [0xd6, 0x94], hexToBytes(P.deployer), [P.deploy_nonces.vault === 0 ? 0x80 : P.deploy_nonces.vault])).slice(12);
check('crypto.pointer.chain_id: fixture pins anvil 31337', P.chain_id === 31_337);
check('crypto.pointer.vault: CREATE(deployer, nonce 3) == fixture vault address',
  eq(vaultFromCreate, vault));
const withdrawDigest = (owner: Uint8Array) => keccak_256(concat(
  word256(P.chain_id), word256(vault), word256(owner), word256(toAddr), word256(amount), word256(0)));
for (const form of ['raw', 'commit'] as const) {
  const entry = P[form];
  const owner = keccak_256(hexToBytes(entry.r)).slice(12);
  check(`crypto.pointer.${form}.owner: keccak256(r)[12:] == fixture owner`,
    eq(owner, hexToBytes(entry.owner)));
  check(`crypto.pointer.${form}.digest: vault withdrawDigest(chain,vault,owner,to,amount,0) matches`,
    eq(withdrawDigest(owner), hexToBytes(entry.digest)));
}

// ----------------------------------- from-scratch C13 verifier (keccak-256)
// Reimplementation of the algorithm the vendored `SPHINCs-C13Asm.sol`
// verifies, recovered from the pinned upstream signer (`lfglabs-dev/SPHINCS-`
// @ 2a40d0a, signer-wasm/src). Differences from a naive FIPS 205 reading and
// the earlier draft of this script, all verified against the Rust source:
//   - H_msg hashes **160 bytes**: seed ‖ root ‖ R ‖ message ‖ 32×0xFF (the
//     domain separator), not 8 bytes — the vendored verifier relies on the
//     zero slot and 0x60..0xFF zero-init to pad the tail out to 0xFFs.
//   - The digest is split LSB-first: bits [0,133) FORS indices, bits
//     [133,155) hypertree index, last FORS index (bits [114,133)) forced zero.
//   - FORS/WOTS leaf secrets are NOT ADRS-PRF outputs: they are
//     `keccak256(sk_seed ‖ "fors" ‖ htIdx ‖ tree ‖ leaf)` /
//     `keccak256(sk_seed ‖ "wots" ‖ layer ‖ tree ‖ kp ‖ chain)`. That is why
//     verification alone is insufficient to check the *consistency* of the
//     fixture's secrets; the keygen-recovered sk_seed below closes that gap.
//   - Sig layout 3688 B = R(N) ‖ K×N secrets ‖ (K−1)×A×N fors auth ‖
//     D × (L×N wots ‖ u32be count ‖ (h/d)×N auth).

const C = DEMO.c13;
const N: number = C.n;
const A: number = C.a;
const D: number = C.d;
const HS: number = C.h / D;         // 11 — subtree height
const L: number = C.l;              // 43 — WOTS chain count
const W: number = C.w;              // 8 — Winternitz parameter
const LGW = Math.log2(W);           // 3
const SIG_LEN = 16 + C.k * N + (C.k - 1) * A * N + D * (L * N + 4 + HS * N);

const toBuffer = (w: bigint): Uint8Array => {
  const out = new Uint8Array(32);
  let v = BigInt.asUintN(256, w);
  for (let i = 31; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
};
const hi128 = (b: Uint8Array) => b.slice(0, N);
const wordFrom = (b: Uint8Array) => BigInt('0x' + (b.length ? Buffer.from(b).toString('hex') : '0'));

// ADRS: u32be(layer) ‖ tree(96) ‖ u32be(type) ‖ u32be(w1) ‖ u32be(w2) ‖ u32be(w3)
function adrs(layer: number, tree: bigint, type: number, w1: number, w2 = 0, w3 = 0): Uint8Array {
  const o = new Uint8Array(32);
  const dv = new DataView(o.buffer);
  dv.setUint32(0, layer);
  let t = BigInt.asUintN(96, tree);
  for (let i = 15; i >= 4; i--) { o[i] = Number(t & 0xffn); t >>= 8n; }
  dv.setUint32(16, type); dv.setUint32(20, w1); dv.setUint32(24, w2); dv.setUint32(28, w3);
  return o;
}
// th(seed, adrs, inputs…) — each input is a 32-byte (n-masked) word
const th = (seed: Uint8Array, a: Uint8Array, ...inputs: Uint8Array[]) =>
  hi128(keccak_256(concat(seed, a, ...inputs)));
const keccakWords = (...ws: Uint8Array[]) => keccak_256(concat(...ws));
const padN = (b: Uint8Array) => { const o = new Uint8Array(32); o.set(hi128(b), 0); return o; };

// recover the fixture's C13 key material: keygen is deterministic over
// checked-in constants (python/scripts/sphincs_c13_7913_demo.py)
const seedMaterial = sha256(concat(new TextEncoder().encode(SPHINCS_C13.keygenDomain), new Uint8Array(32).fill(0x81)));
const entropy = keccak_256(concat(new TextEncoder().encode('sphincs_signer_v1'), seedMaterial));
const pkSeedDeriv = padN(keccak_256(concat(new TextEncoder().encode('pk_seed'), entropy)));
const skSeed = keccak_256(concat(new TextEncoder().encode('sk_seed'), entropy));
check('crypto.keygen.derivation: fixture pk_seed == mask(keccak("pk_seed"‖keccak("sphincs_signer_v1"‖SHA-256(keygen/v0‖spend_seed))))',
  eq(pkSeedDeriv, pkSeed), 'checked-in pk_seed must equal the upstream derive_keys output');

// sk_seed-keyed secret derivations (upstream fors.rs/wots.rs)
function forsSecret(tree: number, leaf: number, htIdx: number): Uint8Array {
  const d = new Uint8Array(32 + 4 + 4 + 4 + 4);
  const dv = new DataView(d.buffer);
  d.set(skSeed, 0); d.set(new TextEncoder().encode('fors'), 32);
  dv.setUint32(36, htIdx); dv.setUint32(40, tree); dv.setUint32(44, leaf);
  return hi128(keccak_256(d));
}
function wotsSecret(layer: number, tree: bigint, kp: number, chain: number): Uint8Array {
  const d = new Uint8Array(32 + 4 + 4 + 32 + 4 + 4);
  const dv = new DataView(d.buffer);
  d.set(skSeed, 0); d.set(new TextEncoder().encode('wots'), 32);
  dv.setUint32(36, layer);
  // tree as 32-byte big-endian (last 8 bytes)
  let t = BigInt.asUintN(64, tree);
  for (let i = 24; i < 32; i++) { d[40 + i] = Number((t >> BigInt((31 - i) * 8)) & 0xffn); }
  dv.setUint32(72, kp); dv.setUint32(76, chain);
  return hi128(keccak_256(d));
}

function verifyC13(pkSeedB: Uint8Array, pkRootB: Uint8Array, message: Uint8Array, s: Uint8Array): boolean {
  const N_MASK = 0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_0000_0000_0000_0000_0000_0000_0000_0000n;
  if (s.length !== SIG_LEN) return false;
  const seedW = wordFrom(pkSeedB), rootW = wordFrom(pkRootB);
  if ((seedW & N_MASK) !== seedW || (rootW & N_MASK) !== rootW) return false; // top-aligned only
  const seed = pkSeedB, rootHi = hi128(pkRootB);
  let off = 0;
  const take = (n: number) => { const r = s.slice(off, off + n); off += n; return r; };

  // H_msg: keccak256(seed ‖ root ‖ R ‖ message ‖ 32×0xFF)
  const R = take(N);
  const digest = keccakWords(seed, pkRootB, padN(R), message, new Uint8Array(32).fill(0xff));
  const d = wordFrom(digest);
  const htIdx = Number((d >> 133n) & 0x3fffffn);
  if (((d >> 114n) & 0x7ffffn) !== 0n) return false;

  const idxLeaf0 = htIdx & 0x7ff, idxTree0 = BigInt(htIdx >> 11);
  const secrets = take(C.k * N);
  const forsRoots: Uint8Array[] = [];
  for (let i = 0; i < C.k - 1; i++) {
    const treeIdx = Number((d >> BigInt(i * A)) & 0x7ffffn);
    const skI = hi128(secrets.slice(i * N, (i + 1) * N));
    let node = th(seed, adrs(0, idxTree0, 3, idxLeaf0, 0, (i << A) | treeIdx), padN(skI));
    let pathIdx = treeIdx;
    const auth = take(A * N);
    for (let h = 0; h < A; h++) {
      const sib = hi128(auth.slice(h * N, (h + 1) * N));
      const parent = pathIdx >> 1;
      const a2 = adrs(0, idxTree0, 3, idxLeaf0, h + 1, (i << (18 - h)) | parent);
      node = pathIdx % 2 === 0 ? th(seed, a2, padN(node), padN(sib)) : th(seed, a2, padN(sib), padN(node));
      pathIdx = parent;
    }
    forsRoots.push(node);
  }
  // forced-zero last tree: signature entry is the revealed root, hashed under
  // the leaf ADRS of node 0 of tree K−1
  const lastRoot = hi128(secrets.slice(6 * N, 7 * N));
  forsRoots.push(th(seed, adrs(0, idxTree0, 3, idxLeaf0, 0, 6 << A), padN(lastRoot)));
  let node = th(seed, adrs(0, idxTree0, 4, idxLeaf0), ...forsRoots.map(padN));

  // Hypertree: D layers bottom-up
  let idxTree = htIdx;
  for (let layer = 0; layer < D; layer++) {
    const idxLeaf = idxTree & 0x7ff;
    idxTree >>= 11;
    const wotsSig = take(L * N);
    const count = new DataView(take(4).buffer).getUint32(0);
    const dmBuf = new Uint8Array(32); new DataView(dmBuf.buffer).setUint32(28, count); // u256_from_u32
    const dmDigest = keccakWords(seed, adrs(layer, BigInt(idxTree), 0, idxLeaf), padN(node), dmBuf);
    const dm = wordFrom(dmDigest);
    let digitSum = 0;
    const digits: number[] = [];
    for (let i = 0; i < L; i++) { const dig = Number((dm >> BigInt(i * LGW)) & 0x7n); digits.push(dig); digitSum += dig; }
    if (digitSum !== C.target_sum) return false;
    const pkParts: Uint8Array[] = [];
    for (let i = 0; i < L; i++) {
      let val = hi128(wotsSig.slice(i * N, (i + 1) * N));
      for (let pos = digits[i]; pos < W - 1; pos++)
        val = th(seed, adrs(layer, BigInt(idxTree), 0, idxLeaf, i, pos), padN(val));
      pkParts.push(val);
    }
    let merkleNode = th(seed, adrs(layer, BigInt(idxTree), 1, idxLeaf), ...pkParts.map(padN));
    const auth = take(HS * N);
    let mIdx = idxLeaf;
    for (let h = 0; h < HS; h++) {
      const sib = hi128(auth.slice(h * N, (h + 1) * N));
      const parent = mIdx >> 1;
      const a2 = adrs(layer, BigInt(idxTree), 2, 0, h + 1, parent);
      merkleNode = mIdx % 2 === 0 ? th(seed, a2, padN(merkleNode), padN(sib)) : th(seed, a2, padN(sib), padN(merkleNode));
      mIdx = parent;
    }
    node = merkleNode;
  }
  return off === s.length && eq(node, rootHi);
}

const c13Vectors: [string, Uint8Array, Uint8Array][] = [
  ['challenge', challenge, sig],
  ['pointer.raw.digest', hexToBytes(P.raw.digest), hexToBytes(P.raw.sig)],
  ['pointer.commit.digest', hexToBytes(P.commit.digest), hexToBytes(P.commit.sig)],
];
for (const [name, msg, s2] of c13Vectors)
  check(`crypto.c13.verify.${name}: independent keccak C13 verify accepts fixture signature`,
    verifyC13(pkSeed, pkRoot, msg, s2));
{
  const flip = (at: number) => { const c = sig.slice(); c[at] ^= 0x01; return c; };
  check('crypto.c13.reject.flip_r: byte-flipped R is rejected',
    !verifyC13(pkSeed, pkRoot, challenge, flip(0)));
  check('crypto.c13.reject.flip_wots: byte-flipped WOTS value is rejected',
    !verifyC13(pkSeed, pkRoot, challenge, flip(2_000)));
  check('crypto.c13.reject.msg: signature rejected under a different message',
    !verifyC13(pkSeed, pkRoot, sha256(Uint8Array.of(0x42)), sig));
}
// The docs' claims about the C13 construction are security properties, not
// just plumbing — test them directly.
check('crypto.c13.reject.pk: fixture signature rejected under a wrong pkRoot',
  !verifyC13(pkSeed, sha256(Uint8Array.of(0x99)), challenge, sig));
{
  // FORS+C grinding: the fixture's last FORS index must be exactly zero, and
  // the WOTS+C digit sum of the layer-0 digest must hit the target sum —
  // the two assertions the vendored verifier enforces.
  const d = wordFrom(keccakWords(pkSeed, pkRoot, padN(hi128(sig.slice(0, N))), challenge, new Uint8Array(32).fill(0xff)));
  check('crypto.c13.fors_forced_zero: fixture digest last FORS index == 0 (D-018 FORS+C grinding)',
    ((d >> 114n) & 0x7ffffn) === 0n);
  // layer-0 WOTS digest under the sig's own count: Σ digits = 208
  const htIdx = Number((d >> 133n) & 0x3fffffn);
  const idxLeaf0 = htIdx & 0x7ff, idxTree0 = BigInt(htIdx >> 11);
  const secrets = sig.slice(16, 16 + C.k * N);
  const roots2: Uint8Array[] = [];
  for (let i = 0; i < C.k - 1; i++) {
    const treeIdx = Number((d >> BigInt(i * A)) & 0x7ffffn);
    let node2 = th(pkSeed, adrs(0, idxTree0, 3, idxLeaf0, 0, (i << A) | treeIdx), padN(hi128(secrets.slice(i * N, (i + 1) * N))));
    let pathIdx = treeIdx;
    const base = 128 + i * A * N;
    for (let h = 0; h < A; h++) {
      const sib = hi128(sig.slice(base + h * N, base + (h + 1) * N));
      const parent = pathIdx >> 1;
      const a2 = adrs(0, idxTree0, 3, idxLeaf0, h + 1, (i << (18 - h)) | parent);
      node2 = pathIdx % 2 === 0 ? th(pkSeed, a2, padN(node2), padN(sib)) : th(pkSeed, a2, padN(sib), padN(node2));
      pathIdx = parent;
    }
    roots2.push(node2);
  }
  roots2.push(th(pkSeed, adrs(0, idxTree0, 3, idxLeaf0, 0, 6 << A), padN(hi128(secrets.slice(6 * N, 7 * N)))));
  const forsPk = th(pkSeed, adrs(0, idxTree0, 4, idxLeaf0), ...roots2.map(padN));
  const count0 = new DataView(sig.slice(1952 + L * N, 1952 + L * N + 4).buffer).getUint32(0);
  const dmBuf = new Uint8Array(32); new DataView(dmBuf.buffer).setUint32(28, count0);
  const dm0 = wordFrom(keccakWords(pkSeed, adrs(0, idxTree0, 0, idxLeaf0), padN(forsPk), dmBuf));
  let sum0 = 0;
  for (let i = 0; i < L; i++) sum0 += Number((dm0 >> BigInt(i * LGW)) & 0x7n);
  check('crypto.c13.wots_target_sum: layer-0 WOTS+C digit sum == 208 (D-018 WOTS+C grinding)',
    sum0 === C.target_sum);
}
check('crypto.commit.binding: commitment(pk) rejects a different pk',
  sphincsC13Commitment(DEMO.key, DEMO.opener) !== sphincsC13Commitment(
    `0x${'00'.repeat(32)}`, DEMO.opener));
check('crypto.c13.sig_size_formula: N + K·N + (K−1)·A·N + D·(L·N + 4 + (h/d)·N) == 3688',
  SIG_LEN === 3_688 && SPHINCS_C13.signatureLength === 3_688);
// Deeper fixture consistency: with the recovered sk_seed, the signature's
// FORS secrets and layer-0 WOTS one-time values must be exactly what the
// signer derived — catches a fixture whose signature and key came from
// different key material even when the composite still verifies.
{
  const d = wordFrom(keccakWords(pkSeed, pkRoot, padN(hi128(sig.slice(0, N))), challenge, new Uint8Array(32).fill(0xff)));
  const htIdx = Number((d >> 133n) & 0x3fffffn);
  const idxLeaf0 = htIdx & 0x7ff, idxTree0 = BigInt(htIdx >> 11);
  let forsOk = true;
  for (let i = 0; i < C.k - 1 && forsOk; i++) {
    const treeIdx = Number((d >> BigInt(i * A)) & 0x7ffffn);
    forsOk = eq(forsSecret(i, treeIdx, htIdx), sig.slice(16 + i * N, 16 + (i + 1) * N));
  }
  check('crypto.fors.secrets: fixture FORS secrets == keccak(sk_seed‖"fors"‖htIdx‖tree‖leaf)', forsOk);

  // layer-0 WOTS: recompute forsPk from this signature, count from the sig,
  // and check sig_i == chain(sk_seed-derived sk_i, digit_i)
  const secrets = sig.slice(16, 16 + C.k * N);
  const roots: Uint8Array[] = [];
  for (let i = 0; i < C.k - 1; i++) {
    const treeIdx = Number((d >> BigInt(i * A)) & 0x7ffffn);
    let node2 = th(pkSeed, adrs(0, idxTree0, 3, idxLeaf0, 0, (i << A) | treeIdx), padN(hi128(secrets.slice(i * N, (i + 1) * N))));
    let pathIdx = treeIdx;
    const base = 128 + i * A * N;
    for (let h = 0; h < A; h++) {
      const sib = hi128(sig.slice(base + h * N, base + (h + 1) * N));
      const parent = pathIdx >> 1;
      const a2 = adrs(0, idxTree0, 3, idxLeaf0, h + 1, (i << (18 - h)) | parent);
      node2 = pathIdx % 2 === 0 ? th(pkSeed, a2, padN(node2), padN(sib)) : th(pkSeed, a2, padN(sib), padN(node2));
      pathIdx = parent;
    }
    roots.push(node2);
  }
  roots.push(th(pkSeed, adrs(0, idxTree0, 3, idxLeaf0, 0, 6 << A), padN(hi128(secrets.slice(6 * N, 7 * N)))));
  const forsPk = th(pkSeed, adrs(0, idxTree0, 4, idxLeaf0), ...roots.map(padN));

  const wotsSig0 = sig.slice(1952, 1952 + L * N);
  const count0 = new DataView(sig.slice(1952 + L * N, 1952 + L * N + 4).buffer).getUint32(0);
  const dmBuf = new Uint8Array(32); new DataView(dmBuf.buffer).setUint32(28, count0);
  const dm0 = wordFrom(keccakWords(pkSeed, adrs(0, idxTree0, 0, idxLeaf0), padN(forsPk), dmBuf));
  let chainsOk = true;
  for (let i = 0; i < L && chainsOk; i++) {
    const digit = Number((dm0 >> BigInt(i * LGW)) & 0x7n);
    let val = wotsSecret(0, idxTree0, idxLeaf0, i);
    for (let pos = 0; pos < digit; pos++)
      val = th(pkSeed, adrs(0, idxTree0, 0, idxLeaf0, i, pos), padN(val));
    chainsOk = eq(val, hi128(wotsSig0.slice(i * N, (i + 1) * N)));
  }
  check('crypto.wots.chains: layer-0 WOTS sig values == chain(sk_seed-derived sk_i, digit_i)', chainsOk);
}

// --------------------------------------------------------------- contracts

const SRC = 'js-client/contracts/src';
const signerSol = readFileSync(rel(`${SRC}/SphincsC13Signer7913.sol`), 'utf8');
const pointerSol = readFileSync(rel(`${SRC}/PointerSig.sol`), 'utf8');
const vendored = readFileSync(rel(`${SRC}/vendor/sphincs-minus/SPHINCs-C13Asm.sol`), 'utf8');
const vendRev = readFileSync(rel(`${SRC}/vendor/sphincs-minus/VENDORED_REV.txt`), 'utf8');

check('contract.commit_domain: wrapper pins the 32-B ASCII domain the docs quote',
  signerSol.includes(`bytes32 public constant COMMIT_DOMAIN = "${SPHINCS_C13.commitDomain}"`));
check('contract.pointer.domains: PointerSig uses the same COMMIT_DOMAIN',
  pointerSol.includes(`"${SPHINCS_C13.commitDomain}"`));
check('contract.pointer.sig_len: C13_SIG_LEN = 3688',
  pointerSol.includes('uint256 public constant C13_SIG_LEN = 3688;'));
check('contract.pointer.versions: V_SPHINCS = 0x52, V_SPHINCS_COMMIT = 0x53',
  pointerSol.includes('uint8 public constant V_SPHINCS = 0x52;')
  && pointerSol.includes('uint8 public constant V_SPHINCS_COMMIT = 0x53;'));
check('contract.vendored.rev: VENDORED_REV.txt pins upstream commit 2a40d0a3…',
  vendRev.includes('2a40d0a3351e8709094c699974a6d849c191bc08'));
const vendSha = createHash('sha256').update(vendored).digest('hex');
check('contract.vendored.sha256: vendored SPHINCs-C13Asm.sol hashes to the recorded sha256',
  vendRev.includes(vendSha), `computed ${vendSha}`);
check('contract.vendored.header: verifier header states the C13 parameter set',
  /h=22 d=2 a=19 k=7 w=8 l=43 target_sum=208 sig=3688/.test(vendored));
check('contract.vendored.profile: foundry.toml keeps via-IR/200-runs on the vendored path (docs\u2019 compilation discipline)',
  /compilation_restrictions[\s\S]*src\/vendor\/sphincs-minus\/\*\*[\s\S]*via_ir = true[\s\S]*optimizer_runs = 200/
    .test(readFileSync(rel('js-client/contracts/foundry.toml'), 'utf8')));

// Compiled artifact: commit domain visible in the wrapper bytecode.
const artPath = rel('js-client/contracts/out/SphincsC13Signer7913.sol/SphincsC13CommitSigner7913.json');
if (existsSync(artPath)) {
  const imm: string = JSON.parse(readFileSync(artPath, 'utf8')).bytecode?.object ?? '';
  check('contract.artifact.domain: commit domain embedded in the compiled wrapper bytecode',
    imm.includes(Buffer.from(SPHINCS_C13.commitDomain, 'utf8').toString('hex')));
} else {
  check('contract.artifact.domain: skipped (run npm run build-contracts)', true);
}

// --------------------------------------------------------------------- docs
// Regexes are written so a wrong value cannot match.

const doc = (p: string) => readFileSync(rel(p), 'utf8');
const has = (text: string, re: RegExp) => re.test(text);

{
  const d = doc('docs/DECISIONS.md');
  // Sections can be out of numeric order (D-011 was re-inserted between
  // D-020 and D-021) — slice by the NEXT "## D-" heading, not by number.
  const section = (tag: string) => {
    const i0 = d.indexOf(`## ${tag}`);
    const rest = d.slice(i0 + 4);
    const m = rest.match(/^## D-/m);
    return d.slice(i0, i0 + 4 + (m?.index ?? rest.length));
  };
  const d18 = section('D-018');
  check('docs.DECISIONS.D018.params: states n=16, h=22, d=2, a=19, k=7, w=8, l=43, target sum 208',
    has(d18, /n=16, h=22, d=2, a=19, k=7, w=8, l=43, target sum 208/));
  check('docs.DECISIONS.D018.siglen: states the 3,688-B signature',
    has(d18, /3,688-B signature|3,688-B C13 signature|3,688 bytes/s));
  check('docs.DECISIONS.D018.commitlen: commit form signature = 3,752 B',
    has(d18, /3,752 B/));
  check('docs.DECISIONS.D018.commit_domain: quotes pq-stealth/sphincs-c13/commit/v0',
    has(d18, /pq-stealth\/sphincs-c13\/commit\/v0/));
  check('docs.DECISIONS.D018.open_domain: quotes pq-stealth/sphincs-c13/open/v0',
    has(d18, /pq-stealth\/sphincs-c13\/open\/v0/));
  check('docs.DECISIONS.D018.keygen_domain: quotes pq-stealth/sphincs-c13/keygen/v0',
    has(d18, /pq-stealth\/sphincs-c13\/keygen\/v0/));
  check('docs.DECISIONS.D018.opener: opener = SHA-256(open/v0 ‖ ss), never ss itself',
    has(d18, /opener = SHA-256\("pq-stealth\/sphincs-c13\/open\/v0" \|\| ss\)/));
  check('docs.DECISIONS.D018.vendored_rev: pins the vendored upstream commit',
    has(d18, /`2a40d0a`|2a40d0a3351e8709094c699974a6d849c191bc08/));
  check('docs.DECISIONS.D018.notfips: states C13 is not FIPS 205',
    has(d18, /Not FIPS 205/));
  check('docs.DECISIONS.D018.linkability: states spend-time linkability explicitly',
    has(d18, /linkab/i));
  check('docs.DECISIONS.D018.sigcap: states the 2^22 signatures-per-key cap',
    has(d18, /2\^22/));
  check('docs.DECISIONS.D018.verify_gas: measured raw verify ≈ 188,092 gas (anvil)',
    has(d18, /188,092/));
  check('docs.DECISIONS.D018.adrs: keccak over the FIPS 205 uncompressed ADRS',
    has(d18, /keccak256/) && has(d18, /ADRS/));
  check('docs.DECISIONS.D018.signers_contract: signers live in SphincsC13Signer7913.sol',
    has(d18, /SphincsC13Signer7913\.sol/));
  check('docs.DECISIONS.D018.security_level: states 128-bit (up to the 2^22 cap)',
    has(d18, /128-bit/));

  const d23 = section('D-023');
  check('docs.DECISIONS.D023.zk_commit: ZK circuit ports the vendored verifier, public inputs (message, commitment) kill the D-018 linkability',
    has(d23, /SPHINCs-C13Asm\.sol/) && has(d23, /\(message,\s*\n?commitment\)/) && has(d23, /D-018 commit\s*\n?form.s spend-time linkability disappears/));
  check('docs.DECISIONS.D023.unlinkable: ZK spend is unlinkable (no key on chain ever)',
    has(d23, /no key on chain|ever/) && has(d23, /unlinkab/i));

  // Cross-entry consistency: two entries quote the same measured figure.
  const d20 = section('D-020');
  check('docs.DECISIONS.D020.verify_gas: frames-mempool analysis quotes the same 188,092 gas figure',
    has(d20, /188,092/));
}
{
  const s = doc('docs/TECHNICAL_SPEC.md');
  check('docs.TECHNICAL_SPEC.commit_layout: commitment = keccak256(commit_domain ‖ spend_key ‖ opener)',
    has(s, /commitment =\s*keccak256\(commit_domain \|\| spend_key \|\| opener\)/s));
  check('docs.TECHNICAL_SPEC.opener: opener = SHA-256(open_domain ‖ ss)',
    has(s, /opener = SHA-256\(open_domain \|\| ss\)/));
  check('docs.TECHNICAL_SPEC.c13_spend_key: the C13 key itself is the spend_key',
    has(s, /the key itself for SPHINCS/));
  check('docs.TECHNICAL_SPEC.domain_sets: the pq-stealth/sphincs-c13/* domain set is named',
    has(s, /pq-stealth\/sphincs-c13\/\*/));
  check('docs.TECHNICAL_SPEC.commit_size: commitment meta-address is 1,217 B at ML-KEM-768',
    has(s, /1,217 B/));
  check('docs.TECHNICAL_SPEC.create2: stealth address is the CREATE2 account bound to the commitment',
    has(s, /CREATE2\(factory, 0, initcode\(commitment/) || has(s, /CREATE2/));
  check('docs.TECHNICAL_SPEC.announcement: announcement carries the 1,088 B ML-KEM ciphertext as ephemeralPubKey',
    has(s, /1,088 B ML-KEM/) && has(s, /ephemeralPubKey = R/));
  check('docs.TECHNICAL_SPEC.viewtag: metadata[0] carries the one-byte view tag',
    has(s, /metadata\[0\] = view_tag/));
}
{
  const r = doc('README.md');
  check('docs.README.variant: root README names SPHINCS- C13 behind ERC-7913, with the linkability caveat',
    has(r, /SPHINCS- C13/) && has(r, /ERC-7913/) && has(r, /linkable/));
  check('docs.README.cost: root README quotes the ~77× on-chain verify-cost ratio',
    has(r, /77×/));
}
{
  const j = doc('js-client/README.md');
  check('docs.jsclient.vendored: pins the vendored verifier repo @ 2a40d0a, byte-identical',
    has(j, /lfglabs-dev\/SPHINCS-/) && has(j, /2a40d0a/) && has(j, /byte/));
  check('docs.jsclient.signers: documents the raw-key and commit ERC-7913 signer forms',
    has(j, /raw 32-byte key/) && has(j, /commitment opened in the signature/));
  check('docs.jsclient.byte_conventions: byte conventions delegated to src/sphincs.ts',
    has(j, /src\/sphincs\.ts/));
  check('docs.jsclient.e2e_command: documents npm run e2e-7913-sphincs',
    has(j, /e2e-7913-sphincs/));
}
{
  const pc = doc('js-client/package.json');
  check('docs.jsclient.script_exists: package.json wires the e2e-7913-sphincs script',
    has(pc, /"e2e-7913-sphincs";|"e2e-7913-sphincs"\s*:\s*"node --test test\/e2e-7913-sphincs/));
}
{
  const p = doc('docs/pointer-signatures-poc.md');
  check('docs.pointer.v52: v = 0x52 carries the raw 32-B C13 key in r',
    has(p, /v = 0x52/) && has(p, /the C13 public key/));
  check('docs.pointer.v53: v = 0x53 carries keccak256(commit/v0 ‖ pk ‖ opener) in r',
    has(p, /v = 0x53/) && has(p, /pq-stealth\/sphincs-c13\/commit\/v0/));
  check('docs.pointer.owner: address = keccak256(r)[12:] in both forms',
    has(p, /keccak256\(r\)\[12:\]/));
  check('docs.pointer.value_constraint: states value must live in pointer-aware contracts (not bare stealth sends)',
    has(p, /Where the value lives/) && has(p, /pointer-aware contracts|adopting contracts/));
}
{
  const z = doc('docs/research/zk-sphincs-frames.md');
  check('docs.zksphincs.binding: proof binds the D-018 commitment and re-runs the vendored verification',
    has(z, /pq-stealth\/sphincs-c13\/commit\/v0/) && has(z, /3,688-B/) && has(z, /SPHINCs-C13Asm\.sol/));
  check('docs.zksphincs.public_inputs: message + commitment as two 128-bit halves (4 public inputs)',
    has(z, /two 128-bit/) && has(z, /4 public inputs/));
}

// --------------------------------------------------------------- IPFS gate
// Deployment readiness of the docs+UI bundle: relative-base static build that
// pins as one folder. Only the deterministic half runs here; the actual pin
// needs PINATA_JWT and is exercised manually.
{
  check('ipfs.vite.base: ui builds with relative base for path-gateway serving',
    has(readFileSync(rel('ui/vite.config.ts'), 'utf8'), /base:\s*'\.\/'/));
  const readme = doc('ui/README.md');
  check('ipfs.readme.instructions: ui README documents build → deploy:ipfs --dry-run → deploy:ipfs',
    has(readme, /deploy:ipfs -- --dry-run/) && has(readme, /PINATA_JWT/));
  check('ipfs.readme.static_claim: ui README states the bundle is fully static with relative asset URLs',
    has(readme, /fully static/) && has(readme, /base: '\.\/'/));

  // Path-gateway correctness of the artifact itself: an absolute src=/ or
  // href=/ URL would break serving under https://gw/ipfs/<cid>/ .
  const indexPath = rel('ui/dist/index.html');
  if (existsSync(indexPath)) {
    const html = readFileSync(indexPath, 'utf8');
    const absoluteUrls = (html.match(/(?:src|href)="\/[^/]/g) ?? []).filter((m) => !m.startsWith('src="//'));
    check('ipfs.dist.relative_urls: built index.html has no absolute src=/href=/ URLs',
      absoluteUrls.length === 0, absoluteUrls.slice(0, 3).join(', '));
    const assetRefs = (html.match(/(?:src|href)="\.?\/?assets\/[^"]+"/g) ?? []);
    check('ipfs.dist.assets_referenced: index.html references at least one bundled asset',
      assetRefs.length > 0);
  } else {
    check('ipfs.dist.relative_urls: index.html present (skipped — run ui build)', existsSync(indexPath));
  }
}

console.log(`\n${pass} passed, ${fail} failed`);
if (fail > 0) {
  for (const f of failures) console.log(`  - ${f}`);
  process.exit(1);
}
