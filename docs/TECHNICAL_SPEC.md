# Technical Spec (working draft): Post-Quantum ERC-5564 Stealth Addresses

Status: pre-freeze working draft, backed by the executable spec in
[`python/`](../python/) and the conformance vectors in
[`python/vectors/v0/`](../python/vectors/v0/). Everything stated here is
implemented and tested; open questions are marked as such.

## 1. Scheme overview

Construction A from [plan.md](../plan.md): ML-KEM (FIPS 203) establishes the
shared secret; the stealth key is an additively blinded ML-DSA (FIPS 204) key.
Compared to the `pq-sap` `v2` prototype this draft (a) adds a fresh error term
per stealth key, (b) specifies all encodings, and (c) adds the signing path,
which produces signatures accepted by any stock FIPS 204 verifier.

```
Recipient setup
    spending key:  zeta -> (rho, s1, s2),  t = A*s1 + s2      (FULL precision)
    viewing key:   (ek, dk) = ML-KEM.keygen()
    meta-address:  version || rho || pack23(t) || ek

Sender
    (ss, R) = ML-KEM.encaps(ek)
    (s', e') = ExpandS(SHAKE256(ss, 64))
    t' = A*s' + e' + t
    (t1', t0') = Power2Round(t', 13)          # t0' discarded by sender
    stealth_pk = pack_pk(rho, t1')            # genuine ML-DSA public key
    stealth_address = keccak256(stealth_pk)[12:32]
    view_tag = SHA-256(ss)[0 : VIEW_TAG_BYTES]
    announce(SCHEME_ID, stealth_address, R, view_tag);  send assets

Recipient scan (viewing key dk suffices)
    ss = ML-KEM.decaps(dk, R)
    view_tag mismatch -> skip (cheap path); else re-derive and compare address

Spend / prove possession (requires spending secrets s1, s2)
    blinded key: s1' = s1 + s', s2' = s2 + e', t0'
    sign per FIPS 204 Alg. 7 with widened bounds (Section 4.2)
```

Correctness identity (the Lean 4 target in plan.md):
`t' = A*s' + e' + t = A*(s1 + s') + (s2 + e')`, so `(s1', s2', t0')` is a
working secret key for `stealth_pk` under the spec's rounding.

## 2. Parameters and sizes

Default pairing ML-KEM-768 + ML-DSA-65 (NIST level 3); the spec is
parameter-agile across `{512+44, 768+65, 1024+87}` (`pq_stealth/params.py`).
All sizes below are measured by the test suite (`test_encoding.py`) and
recorded in the vectors' `sizes` field.

| Object | Size (default set) | Notes |
|---|---|---|
| Meta-address | **5,633 B** | `1 + 32 + 4416 + 1184`; one-time registry/ENS cost |
| Ephemeral pubkey `R` | 1,088 B | the ML-KEM ciphertext (33 B in EC DKSAP) |
| View tag | 1 B | longer tags safe in this family; default stays 1 |
| Stealth address | 20 B | Ethereum-style, `keccak256(pk)[12:]` |
| Stealth public key | 1,952 B | standard ML-DSA-65 pk |
| Signature / possession proof | 3,309 B | standard ML-DSA-65 signature |

`VIEW_TAG_BYTES = 1`. `Q = 8380417`, `Q_BITS = 23`, `d = 13`.

## 3. Encodings (normative)

**Meta-address** (`pq_stealth/encoding.py`): `version(1) || rho(32) ||
pack23(t) || kem_ek`. `version = 0x01`. `pack23` packs each of the `k*256`
coefficients of `t` (reduced to `[0, q)`) in 23 bits, little-endian bit
order, matching FIPS 204's packing conventions. The meta-address MUST carry
full-precision `t`, not the rounded `t1` of a standard public key:
`Power2Round(A*s' + e' + t)` is only well-defined on the unrounded value.
(The Rust `v2` prototype also keeps full `t` but never defined an encoding.)

**Announcement**: ERC-5564 `Announcement` event fields with
`ephemeralPubKey = R` (1,088 B ML-KEM ciphertext) and
`metadata[0] = view_tag` byte, per the existing convention.

**Blinded secret key** (optional persistence format): `rho || bitpack(s1',
s2', 5 bits/coeff over [-2η, 2η]) || bitpack(t0', 14 bits/coeff)`. The FIPS
204 secret-key encoding CANNOT hold a blinded key: `bit_pack_s` assumes
coefficients in `[-η, η]`, but `‖s1'‖∞, ‖s2'‖∞ ≤ 2η`. Alternatively store
nothing and re-derive from `(zeta seeds, ss)`.

## 4. Derivation and signing (normative)

### 4.1 Blinding

`(s', e') = ExpandS(SHAKE256(ss, 64))` — the standard FIPS 204 eta-sampler
over a 64-byte seed, producing the `l`-vector `s'` and `k`-vector `e'` with
domain-separated nonces (`pq_stealth/blinding.py`).

**Fresh error term (departure from pq-sap v2):** v2 reuses the recipient's
`s2` in every stealth key, a potential linkability vector once any stealth
key is revealed. Here each stealth key gets `e'` derived alongside `s'`; the
sender still computes everything from public data. Cost: `‖s2'‖∞ ≤ 2η`
enters the `r0` bound below. The formal unlinkability analysis (Fellow A)
still owes a proof for both variants.

### 4.2 Signing with the blinded key

FIPS 204 Algorithm 7 over `(s1', s2', t0')` with the rejection bounds
widened to `β' = τ·2η` (392 for ML-DSA-65, vs. standard `β = 196`):

* `‖z‖∞ < γ₁ − β'` — stricter than the verifier's `γ₁ − β`, so signatures
  pass a stock verifier; acceptance probability drops accordingly. Measured
  cost is real, not cosmetic: the blinded signer runs ~6× the rejection
  rounds of stock ML-DSA-65 (mean ≈ 30 vs ≈ 5 at N=200,
  `benchmarks/op_bench.py`), dominated by the `r0` check since both secret
  vectors are now `2η`-normed. `2η` is a worst-case bound on `‖s1+s'‖∞`;
  a tighter (probabilistic) bound in the analysis would recover most of
  this, since the sum of two `η`-bounded terms rarely reaches `2η`.
* `‖r0‖∞ < γ₂ − β'` — accounts for `‖c·s2'‖∞ ≤ β'`.
* `‖c·t0'‖∞ < γ₂` and the ω hint bound are unchanged.

Signatures are byte-identical in format to standard ML-DSA-65 and verify
under dilithium-py, liboqs (tested), and any conformant on-chain verifier.
**Open question for the security analysis:** the `z` distribution under the
widened secret (leakage beyond the standard proof's assumptions), and
whether `s'` should instead be sampled from a narrower distribution.

### 4.3 Message formatting (load-bearing)

FIPS 204 external functions hash `M' = 0x00 || len(ctx) || ctx || M`. Any
signer that hashes the raw message produces signatures that fail stock
verification (this bug was hit and fixed during prototyping). Possession
proofs bind the address via `ctx = "pq-stealth/pop/v0" || stealth_address`
over the raw challenge; plain signatures use `ctx = ""`.

### 4.4 Signer randomization key

`K' = SHAKE256("pq-stealth/sign-key/v0" || ss, 32)` replaces the keygen-time
`K`; the deterministic variant sets `rnd = 0^32` (used for vectors).

## 5. Conformance vectors

`python/vectors/v0/vectors.json`, deterministic (byte-identical on
regeneration): recipient seeds, meta-addresses, viewing keys, announcements,
expected stealth pk, and a deterministic possession proof. Negative cases:
wrong view tag, wrong recipient, truncated ciphertext (MUST reject without
raising), bit-flipped ciphertext (ML-KEM implicit rejection), plus a
distinct-address unlinkability sanity case. Regenerate with
`python vectors/generate_vectors.py`; the generator replays every case
through the library before writing.

## 6. Library landscape (verified 2026-07)

### Python (reference implementation — this repo)

| Library | Version | Role | Verdict |
|---|---|---|---|
| `kyber-py` | 1.2.0 | ML-KEM, pure Python | Top-level + derandomized internals (`_keygen_internal(d,z)`, `_encaps_internal(ek,m)`) — used for deterministic vectors |
| `dilithium-py` | 1.4.0 | ML-DSA, pure Python | **Exposes every internal construction A needs**: `_expand_matrix_from_seed`, `_expand_vector_from_seed`, `power_2_round`, NTT `Matrix`/`Vector` algebra, `sample_in_ball`, `_pack_pk`/`_pack_sig`. No fork needed. |
| `liboqs-python` | 0.16.0 | audited C backend | Opaque API only; used as cross-check verifier (test suite) and future fast-scanning backend |
| `pqcrypto` | 0.4.0 | PQClean wrappers | Opaque API only; alternative cross-check |
| `pycryptodome` | 3.23.0 | keccak256 | — |
| `coincurve` | 21.0.0 | secp256k1 | DKSAP baseline for benchmarks (later phase) |

Division of labor: pure-Python is the executable spec and vector generator;
audited backends verify outputs; a production binding is future work.

### JavaScript (frontend — implemented in `js-client/`)

* `@noble/post-quantum` 0.6.x (audited, pure TS/JS): ML-KEM-768 decaps and
  stock `ml_dsa65.verify` cover the scanning hot path and proof checking
  out of the box. The blinding layer is NOT expressible over its public
  API (the `internal` export is only FIPS 204's raw-`M'` interface; the
  NTT/ExpandA machinery lives in module closures).
* `js-client/src/mldsa65.js` therefore hand-ports the required FIPS 204
  polynomial layer (~200 lines: ExpandA, ExpandS, NTT, Power2Round, pk
  packing; plain-Number arithmetic — products stay under 2^47). The
  conformance test replays all v0 vectors and asserts the JS-derived
  stealth pk is **byte-identical** to the Python reference; the vectors'
  possession proof verifies under noble.
* End-to-end on-chain path (`npm run e2e`): a local ERC-5564 announcer on
  anvil (forge-built), vector announcements emitted as real transactions,
  logs fetched and scanned via viem — recipient A finds exactly the
  genuine payments, recipient B nothing.

## 7. The kohaku / ZKNOX spend route (stretch goal): compatibility finding

Verified hands-on (2026-07-25, `ethereum/kohaku` `packages/pq-account` +
`ETHDILITHIUM` at HEAD): the deployed ZKNOX verifiers implement a
**level-2 Dilithium2 profile** (32-byte `c_tilde`, 2,420-byte signatures,
round-3 `Dilithium2` from their vendored dilithium-py with FIPS-204-style
`M' = 0x00‖len(ctx)‖ctx‖m` formatting and 64-byte `tr`) — **not FIPS 204
ML-DSA-65**, and not byte-exact ML-DSA-44 either. Measured on their own
KAT vectors (forge, optimizer on, cancun):

| Verifier | Gas per verify |
|---|---|
| `ZKNOX_dilithium` ("MLDSA" profile, SHAKE XOFs) | 8,176,453 |
| `ZKNOX_ethdilithium` (keccak-PRNG XOFs, ETH-optimized) | 4,926,456 |

Consequences for construction A: our blinding algebra carries over to
their profile unchanged (same module structure; level-2 params η = 2,
τ = 39, d = 13 — β' = 2τη = 156), but a spend demo through kohaku today
requires instantiating the scheme at their profile, not at ML-DSA-65, and
the ETH-optimized variant additionally swaps the XOFs (keccak-PRNG), which
changes `ExpandA`/`ExpandS` and therefore the derived stealth keys. The
pk is stored expanded (SSTORE2 via `PKContract`: `A_hat` + `tr` + `t1`,
measured 22,400 B encoded) — one more reason the scheme ID stays
parameter-agile.

**Counterfactual CREATE2 demo (implemented and passing).** Construction A
was instantiated at the ZKNOX profile
(`python/scripts/zknox_counterfactual_demo.py`: master key with full `t`,
ML-KEM-512 encapsulation, fresh-`e'` blinding, blinded possession
signature — 31 rejection rounds at β' = 156, verified by their stock
Python verifier) and driven on-chain
(`js-client/test/e2e-counterfactual.test.ts`):

* the account address is computed **fully off-chain** from the blinded
  key's expanded pk (CREATE2 over the factory's salt/initcode — the
  sender-names-the-address property Native UTXOs need), matches
  `factory.getAddress`, and matches the address actually deployed by
  `createAccount`;
* the blinded-key signature **verifies through the on-chain
  `ZKNOX_dilithium` verifier**.

| Operation (anvil, their artifacts) | Gas |
|---|---|
| Account deployment via factory (incl. 22.4 kB pk via SSTORE2) | 6,167,566 |
| Blinded-signature verification (`ZKNOX_dilithium`) | ~8,151,911 |

This upgrades the stretch goal from "route exists" to "route demonstrated
end-to-end with construction A keys": receiving today, spending gated only
on the account being funded/operated as a normal ERC-4337 account.

**ERC-7913 update (2026-08-10, D-014).** Upstream ETHDILITHIUM at HEAD
(`df999ed`) has replaced the `setKey` flow entirely: the verifiers now
implement ERC-7913's
`verify(bytes key, bytes32 hash, bytes signature) → bytes4`, where `key` is
a 20-byte pointer to a deployed `PKContract` — a full ERC-7913 signer is
`verifier || pkPointer` = 40 bytes. Two implications: (a) the 3-arg
entrypoint hardcodes `M' = 0x00 || 0x00 || m` with `m` a `bytes32`, so
fixtures signed over longer or ctx-bearing messages (like the possession
proof's ctx) do not verify through it — the message binding must live in
the 32-byte hash; (b) per-account `setKey` (5.2 M gas on the deployed
Sepolia v0.0.10) is superseded by one `PKContract` deployment per key.
Demonstrated end-to-end in `js-client/test/e2e-7913.test.ts` against an
OpenZeppelin `SignerERC7913` account (anvil, 2026-08-10):

| Operation (vendored ETHDILITHIUM @ df999ed) | Gas |
|---|---|
| PKContract deploy (22.4 kB expanded pk, SSTORE2) | 5,324,168 |
| `Stealth7913Account` deploy (signer = 40 B; initcode 2,952 B vs 49,152 B cap) | 620,750 |
| ERC-7913 `verify` (blinded sig) | ~14,968,387 |

Note the verify gas is ~1.8× the old table above: df999ed stores `t1`
plain and recomputes `NTT(t1·2^d)` inside every `verify` — work the old
`setKey` flow did once at key-setup time.

## 7b. Threat model, scheme variants, and the ZK direction

The locked decisions and empirical findings from the design work — threat
model (HNDL confidentiality vs. ownership, per pq.ethereum.org), the three
scheme variants and what each protects, the EIP-3860 dual-PQ-account blocker,
the ZKNOX level-2 key-size constraint, the cheap-vs-PQ on-chain tension, and
the decode-in-reverse ZK ownership proof — are recorded as a dated ADR log in
[`DECISIONS.md`](./DECISIONS.md). Headlines:

- **Detection (ML-KEM) is the urgent, non-negotiable core** (HNDL protects
  confidentiality); spend-side PQ is configurable future-proofing that rides
  the account-abstraction rails Ethereum's own roadmap is building.
- **On-chain today you get cheap OR post-quantum verification, not both** —
  Groth16 ~300k gas (classical), STARK ~5M (PQ), direct ML-DSA ~8M (PQ). The
  EF's J\* vector-math precompile closes this at the protocol level (~2029+).
- **ZK ownership PoC** (`noir/`): prove the MLWE relation `A·s + e = t`, not a
  full ML-DSA signature — proved+verified in UltraHonk at 2.17M gates (full
  ML-DSA-65, schoolbook; ~100–200k projected with NTT). Cheap enough to be
  practical, but classical soundness until a PQ backend exists.

## 8. Scope warning

Receiving, detection, and proof of possession work today against the
ERC-5564/6538 contracts. **Value sent to these stealth addresses is
unspendable on-chain until protocol-level PQ signature support (e.g.
EIP-8141) or an ERC-4337 PQ account route exists.** The library ships no
send-value flow.
