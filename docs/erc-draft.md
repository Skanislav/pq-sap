---
eip: TBD
title: Post-Quantum Stealth Addresses
description: An ERC-5564 stealth address scheme using ML-KEM-768 key encapsulation for detection and additively blinded ML-DSA-65 keys for spending
author: Skas Merkushin <skas.merkushin@gmail.com>
discussions-to: TBD  (to be updated once the Ethereum Magicians thread is opened; draft post prepared in `docs/magicians-thread-draft.md`)
status: Draft
type: Standards Track
category: ERC
created: 2026-08-01
requires: 5564, 6538
---

## Abstract

This ERC registers a post-quantum stealth address scheme for [ERC-5564](./eip-5564.md). Detection uses ML-KEM-768 (FIPS 203): the announcement's ephemeral public key is an ML-KEM ciphertext, and the shared secret drives a one-byte view tag and the address derivation. The spending key is an ML-DSA-65 (FIPS 204) key additively blinded by values derived from the shared secret; the stealth address is the Keccak-256 address of the blinded verification key, so the sender computes the recipient's address without learning any secret, exactly as in the SECP256K1 scheme. Signatures produced with the blinded key are byte-identical in format to standard ML-DSA-65 and verify under any stock FIPS 204 verifier.

The scheme works against the deployed ERC-5564/[ERC-6538](./eip-6538.md) contracts and requires no protocol changes.

## Motivation

ERC-5564 announcements are public and permanent. The SECP256K1 scheme's key exchange can be recorded today and broken later by a quantum computer running Shor's algorithm, revealing the recipient of every stealth payment ever made ("harvest now, decrypt later", NIST IR 8547). This is a confidentiality problem, not an ownership one: recording announcements does not enable retroactive theft, but it does enable retroactive deanonymization. Detection therefore needs a post-quantum key exchange *now*, while spend-side quantum safety is expected to migrate later through account abstraction following the Hegotá hard fork and EIP-8141 (ethereum.org/roadmap/security/quantum-resistance, April 2026).

This scheme replaces the elliptic-curve key exchange with ML-KEM and keeps the ERC-5564 flow unchanged: senders announce through the same contract, recipients scan the same logs, and the sender still names the address (a property that key-only recipient designs such as Native UTXOs require).

## Specification

The key words "MUST", "MUST NOT", "SHOULD", and "MAY" in this document are to be interpreted as described in RFC 2119.

### Notation

ML-KEM and ML-DSA operations are as defined in FIPS 203 and FIPS 204. `A`, `s1`, `s2`, `t`, `rho`, `Power2Round`, `ExpandA`, and the eta-sampler `ExpandS` are FIPS 204 objects; `q = 8380417`, `d = 13`. `H(x)` is SHA-256. `keccak256` is Ethereum's Keccak-256. `||` is byte concatenation.

### Scheme ID

The scheme ID is `2`, the next unassigned identifier in the ERC-5564 scheme registry (to be confirmed on inclusion). Earlier prototypes used the placeholder `0x5567`.

### Parameter sets

The default pairing is ML-KEM-768 + ML-DSA-65 (NIST security level 3). Implementations MUST support the default set. The scheme is parameter-agile; the pairings ML-KEM-512 + ML-DSA-44 (level 1) and ML-KEM-1024 + ML-DSA-87 (level 5) are defined identically and MAY be supported. All sizes below are for the default set.

| Object | Size | Notes |
|---|---|---|
| Meta-address | 5,633 B | `1 + 32 + 4416 + 1184`, one-time registry cost |
| Ephemeral public key `R` | 1,088 B | the ML-KEM-768 ciphertext |
| View tag | 1 B | |
| Stealth address | 20 B | `keccak256(stealth_pk)[12:32]` |
| Stealth public key | 1,952 B | a standard ML-DSA-65 public key |
| Signature / possession proof | 3,309 B | a standard ML-DSA-65 signature |

#### Optional hybrid (PQ/T) parameter set

Implementations MAY additionally support a hybrid parameter set in which the discovery KEM is MLKEM768-X25519 (the X-Wing construction: one ML-KEM-768 encapsulation plus one X25519 exchange, combined with SHA3-256), with spending unchanged (ML-DSA-65). The substitution is confined to the KEM: `ss` is the X-Wing shared secret and every derivation downstream of `ss` — blinding, view tag, scanning — is identical to the default set.

Differences from the default set:

| Object | Size | Notes |
|---|---|---|
| Meta-address | 5,665 B | version `0x02`; `ek` is the 1,216-B X-Wing encapsulation key |
| Ephemeral public key `R` | 1,120 B | the X-Wing ciphertext |
| Viewing (decapsulation) key | 32 B | a seed, expanded per the X-Wing specification |

The decapsulation key MUST be generated, stored, and exchanged only in its 32-byte seed form; the expanded ML-KEM decapsulation key MUST NOT be exported (X-Wing's binding properties do not survive expanded-key transport). Senders MUST perform the ML-KEM encapsulation-key check required by the X-Wing specification. Scanning behavior on malformed ciphertexts is unchanged (implicit rejection; MUST NOT raise).

The security scope of this set is deliberately narrow and is stated in Security Considerations: it hedges detection privacy against a classical break of Module-LWE; it does not hedge announcement unlinkability, which rests on ML-KEM's ciphertext anonymity in both parameter sets.

### Meta-address

The recipient generates an ML-DSA spending key, retaining `t = A*s1 + s2` at **full precision**, and an ML-KEM viewing keypair `(ek, dk)`. The stealth meta-address is:

```
meta_address = version(1) || rho(32) || pack23(t) || ek
```

`version = 0x01`. `pack23` packs each of the `k*256` coefficients of `t`, reduced to `[0, q)`, in 23 bits, little-endian bit order, matching FIPS 204's packing conventions.

The meta-address MUST carry full-precision `t` and MUST NOT substitute the rounded `t1` of a standard ML-DSA public key: the sender-side blinding `Power2Round(A*s' + e' + t)` is only well-defined on the unrounded value.

The meta-address MAY be registered in the ERC-6538 registry or published by other means (e.g. ENS).

### Sender: address derivation and announcement

```
(ss, R)   = ML-KEM.encaps(ek)
(s', e')  = ExpandS(SHAKE256(ss, 64))          # FIPS 204 eta-sampler, domain-separated nonces
t'        = A*s' + e' + t
(t1', t0') = Power2Round(t', 13)                # sender discards t0'
stealth_pk      = pack_pk(rho, t1')             # a genuine ML-DSA public key
stealth_address = keccak256(stealth_pk)[12:32]
view_tag        = H(ss)[0:1]
```

The sender calls `announce(schemeId, stealth_address, R, metadata)` on the ERC-5564 announcer with `ephemeralPubKey = R` (the 1,088-byte ML-KEM ciphertext) and `metadata[0] = view_tag`, per the ERC-5564 metadata convention.

A fresh `(s', e')` pair MUST be derived per announcement from the encapsulated shared secret as above. In particular the error term `e'` MUST be fresh per stealth key; reusing the recipient's `s2` across stealth keys (as in earlier prototypes) is a linkability vector once any stealth key is revealed.

### Recipient: scanning

For each announcement under this scheme ID:

```
ss = ML-KEM.decaps(dk, R)
if H(ss)[0:1] != metadata[0]:  skip          # cheap rejection, ~1/256 false-positive rate
re-derive stealth_address from (rho, t, ss); compare
```

The viewing key `dk` alone suffices for detection and viewing. Scanning MUST NOT raise on malformed or truncated ciphertexts; ML-KEM's implicit rejection yields a non-matching shared secret and the announcement is skipped.

### Spending key and signing

The recipient's one-time secret key for a detected payment is the blinded triple:

```
s1' = s1 + s'      s2' = s2 + e'      t0'  (recomputed from t')
```

By the correctness identity `t' = A*s' + e' + t = A*(s1+s') + (s2+e')`, this is a working ML-DSA secret key for `stealth_pk`.

Signing follows FIPS 204 Algorithm 7 with the signer-side rejection bounds widened to `beta' = tau * 2*eta` (392 for ML-DSA-65):

* `||z||_inf < gamma1 - beta'`  -  stricter than the verifier's bound, so signatures verify under unmodified FIPS 204 verifiers;
* `||r0||_inf < gamma2 - beta'`  -  accounts for `||c*s2'||_inf <= beta'`;
* the `c*t0'` and hint-weight checks are unchanged.

The signer randomization key is `K' = SHAKE256("pq-stealth/sign-key/v0" || ss, 32)`. Message formatting MUST follow FIPS 204's external interface (`M' = 0x00 || len(ctx) || ctx || M`); a signer hashing the raw message produces signatures that fail stock verification.

The blinded secret does not fit the FIPS 204 secret-key encoding (coefficients reach `2*eta`). Implementations MAY persist it as `rho || bitpack(s1', s2', 5 bits/coeff) || bitpack(t0', 14 bits/coeff)`, or store nothing and re-derive from the master seeds and `ss`.

### Proof of possession

A holder of the blinded key proves control of a stealth address without a transaction by signing a challenge with `ctx = "pq-stealth/pop/v0" || stealth_address`. Verifiers MUST check the signature under the stealth public key and check `keccak256(stealth_pk)[12:32]` equals the claimed address.

Note that the bare [ERC-7913](./eip-7913.md) `verify(key, hash, signature)` interface carries no context string; a possession proof checked through it MUST instead bind the stealth address inside the signed hash (or use a wrapper verifier that injects the `ctx` above).

### Spending and on-chain verification (informative)

This section is informative; the scheme standardizes detection, and spend-side mechanisms may evolve independently (see Security Considerations).

On-chain verification of blinded-key signatures is best expressed with the [ERC-7913](./eip-7913.md) signer encoding: the spend key is represented as the byte string `verifier || key`, where `verifier` is a stateless signature-verifier contract shared by all accounts and `key` identifies the stealth public key. The `key` field can be the raw 1,952-byte stealth public key (a fully stateless verifier) or a 20-byte pointer to deployed key storage (the pattern used by existing on-chain ML-DSA verifiers, where the expanded key is written once and the signer string is 40 bytes).

Both spend modes fit this one interface: a blinded ML-DSA signature verifies under `verifier = ` an ML-DSA verifier with `key = ` the stealth public key, and a zero-knowledge ownership proof verifies under `verifier = ` a proof verifier with `key = ` a commitment to the key material. A hash-based spend key (SLH-DSA or a SPHINCS+ variant) also fits, with one structural difference worth stating: hash-based keys admit no blinding, so the sender cannot derive a per-payment public key from the meta-address. Such a key can still receive a sender-derived stealth address through a committed signer, `key = ` a hiding commitment to the recipient's hash-based public key under an opener derived from the shared secret, with the signature opening the commitment; the commitment hides the key while the address is unspent, but the first spend from any such address reveals the recipient's public key, so spent addresses of one recipient become linkable to that recipient. That trade buys verification roughly two orders of magnitude cheaper than direct ML-DSA verification (a 3,688-byte SPHINCS+ "+C" signature verifies in under 200,000 gas against a machine-checked verifier) and suits keys that are public anyway (registry authentication, co-signers) or a ZK-bound address; it is not a substitute for blinding where spend-time unlinkability is required. An account can switch or combine modes without changing its account standard. ERC-7913's empty-key fallback (plain ECDSA / ERC-1271) also gives hybrid accounts  -  post-quantum key alongside a classical co-signer  -  as a configuration rather than a custom contract, matching the account-abstraction migration path referenced in the Motivation.

## Rationale

**Why ML-KEM for detection.** Detection is the harvest-now-decrypt-later-exposed layer and runs one decapsulation per announcement, so the KEM is chosen for standardization, scan speed, and footprint. Measured against the alternatives (NTRU, unstructured LWE, code-based KEMs, isogenies), ML-KEM has the fastest decapsulation by roughly an order of magnitude over the nearest lattice alternative and three orders over code-based decoders; isogeny KEMs would shrink the meta-address ~55x but are orders of magnitude slower per scan and rest on contested parameters.

**Why additive blinding (construction A).** It preserves the ERC-5564 property that the sender computes the address, which sender-names-the-address designs require, and it lands on a *standard* ML-DSA public key, so every deployed FIPS 204 verifier accepts the resulting signatures. The alternative  -  deriving a fresh standardized keypair from the shared secret  -  uses only standardized operations but breaks sender-side address computation and was kept as a documented fallback.

**Why an ERC-7913 signer encoding for spending.** Every stealth address carries a distinct blinded key, so any design that bakes the key into account initcode pays per-account deployment and, for post-quantum key sizes, collides with the EIP-3860 initcode cap (measured: an account embedding two ML-DSA keys exceeds the 49,152-byte cap and cannot deploy). An [ERC-7913](./eip-7913.md) signer inverts this: one shared verifier serves every stealth account, the account stores only `verifier || key` (40 bytes in the pointer form), and the encoding itself adds no verification cost  -  ERC-7913 is an interface, not an accelerator; the underlying signature check still dominates.

**Why a classical-spend option is available (informative).** Because the detection layer derives the view tag and the address from the ML-KEM shared secret alone, it is indifferent to the group the spending key lives in, so blinding a secp256k1 spend key in place of the ML-DSA one (`P = K + KDF(ss)*G`, address `keccak256(uncompressed(P)[1:])[12:32]`) yields the ERC-7913 empty-key base case of the same account model: one that is spendable on-chain today with a plain ECDSA signature at `ecrecover` cost, at the price of a classical spend authorization deferred to the same migration. That price is narrower than it reads, since the stealth address is only a hash until it is spent from, so the secp256k1 public key surfaces just at spend time and a single-transaction full drain closes even that window, while confidentiality (which recipient received the payment) rests on ML-KEM and stays post-quantum throughout, the very harvest-now-decrypt-later split the Motivation draws. Sharing the recipient's ML-KEM viewing key and registering under its own scheme ID, the variant lets a wallet offer both, with a reference implementation and vectors published alongside.

**Why the hybrid set is X-Wing (informative).** Among assumption-diversity hedges, the hybrid is the cheapest measured: 2.8x the default set's scan cost yet faster than every non-Module-LWE KEM family (the nearest NTRU alternative included), +32 B on the meta-address and ciphertext, and a 32-byte seed as the whole viewing key. Its combiner shape is compatible with the NIST SP 800-227 hybrid recommendation, and the identical construction is being standardized at the IETF (MLKEM768-X25519) with production deployments. Code-based alternatives cannot fill this role in the same combiner: its proof requires ciphertext second-preimage resistance of the post-quantum leg, which HQC lacks. A hash-based alternative is ruled out by theorem (random-oracle key exchange is capped at a quadratic gap classically and has no gap against a quantum adversary, per Barak-Mahmoody and Brassard et al.), which is why a structured second assumption is the only hedge on offer.

**Why full-precision `t` in the meta-address.** `Power2Round` does not commute with the blinding addition; rounding before blinding makes the sender's and recipient's keys disagree. The ~4.4 kB cost is one-time per recipient.

**Future variant (informative).** A ZK ownership proof (Section 7b / D-008) could let the meta-address carry only a short commitment to the spending key instead of the full-precision `t`, shrinking it from 5,633 B to roughly 1,217 B for ML-KEM-768. That format is *not* normative in this ERC because the exact address-binding proof is still open; it is recorded as future work in `docs/DECISIONS.md` D-012 and the Lean development keeps a roundtrip for it as a documented variant.

**Why a 1-byte view tag.** Because the shared secret itself (not its hash) derives the address in this family, longer tags are safe, but measurements show the marginal scan-time benefit is negligible for native implementations; 1 byte matches the ERC-5564 convention.

**Fees.** A PQ announcement's calldata puts the transaction on the EIP-7623 calldata floor (measured 67,580 gas on the canonical announcer, about 2.5x the SECP256K1 scheme); as EIP-4844 blob data the marginal cost is sub-cent. These numbers are part of the reference cost report.

## Backwards Compatibility

No changes to ERC-5564 or ERC-6538 contracts or events. The scheme is additive: a new scheme ID with its own meta-address and `ephemeralPubKey` interpretation. Existing scanners ignore announcements under unknown scheme IDs.

## Test Cases

Deterministic conformance vectors (v0), including negative cases that MUST be rejected  -  wrong view tag, wrong recipient, truncated ciphertext (rejected without raising), bit-flipped ciphertext  -  are published with the reference implementation. Regeneration is byte-identical. An independent TypeScript implementation reproduces the vectors byte for byte.

## Reference Implementation

A pure-Python executable specification (protocol layer over spec-faithful FIPS 203/204 implementations, cross-checked against liboqs), a TypeScript scanning client, and the vector generator are published in the reference repository, together with a machine-checked Lean 4 core (the blinding correctness identity, the widened-bound invariant `beta' = 2*beta`, encoding round-trips, and the scheme's security games, built on VCVio).

## Security Considerations

**Threat model.** Harvest-now-decrypt-later attacks confidentiality, not ownership: a future quantum adversary replaying today's announcements can deanonymize recipients under the SECP256K1 scheme but cannot steal funds. This scheme's post-quantum guarantee is therefore strongest exactly where the urgency is: detection privacy. Spend-side authorization is a live-attacker problem and can migrate independently.

**Unlinkability reduces to KEM anonymity, not IND-CCA.** Recipient unlinkability is the property that a ciphertext does not reveal *which* public key it was encapsulated to (ANO-CCA / key privacy). This is not implied by IND-CCA and is not part of FIPS 203's design goals; it has been established for Kyber in the literature (Grubbs–Maram–Paterson, Eurocrypt 2022; Maram–Xagawa, PKC 2023), and the accompanying security analysis reduces the scheme's unlinkability to it, with the view tag and address derivation covered by the shared secret's pseudorandomness (KEM IND-CPA). Implementations MUST derive the view tag and blinding only from the encapsulated shared secret, never from recipient-identifying material.

**What the hybrid parameter set does and does not hedge.** The optional MLKEM768-X25519 set targets one scenario: a *classical* cryptanalytic break of Module-LWE. In that event the shared secret remains pseudorandom under the strong Diffie-Hellman assumption on Curve25519 (Barbosa et al., IACR CiC 2024), so view tags and derived stealth addresses — detection privacy — stay hiding. It does not extend to announcement unlinkability: a parallel hybrid concatenates both component ciphertexts, so its anonymity requires *both* components to be anonymous (an AND, unlike IND-CCA's OR), and since the X25519 component is an ephemeral public key carrying no recipient information, the hybrid's ciphertext anonymity equals ML-KEM's exactly (Bao-Pan, PKC 2026). Unlinkability therefore rests on ML-KEM ciphertext anonymity in both parameter sets, and wallets MUST NOT present the hybrid set as protecting unlinkability against a lattice break. Against a future quantum adversary the hybrid is neutral: the X25519 leg contributes nothing and security degrades to exactly the default set.

**Widened signature distribution (open analysis).** The blinded secret's coefficients reach `2*eta`, so the post-rejection `z` distribution differs from standard ML-DSA's. Signatures verify everywhere, but the leakage analysis of the widened distribution is the open item of the security analysis; until it closes, treat on-chain reuse of a single stealth key for many signatures conservatively.

**Fresh error term.** The per-key `e'` closes a linkability vector present in earlier prototypes (reused `s2` across all of a recipient's stealth keys links them once any one key is revealed).

**Registry authentication.** ERC-6538's `registerKeysOnBehalf` authenticates with ECDSA/ERC-1271 signatures, which are quantum-vulnerable. A quantum adversary could overwrite a victim's registered meta-address and redirect future payments. Recipients SHOULD treat registry entries as trusted-on-first-use and SHOULD publish meta-addresses through channels with post-quantum integrity where available; this is a registry limitation, not a scheme one. [ERC-7913](./eip-7913.md) provides the standardized remedy: a registry (or a successor) SHOULD accept registration and update authorizations from an ERC-7913 signer whose key is a post-quantum key controlled by the recipient, checked together with the proof of possession above. Trust-on-first-use plus "updates MUST be authorized by the initially registered post-quantum key" then becomes an enforceable ratchet instead of advice.

**Spending today.** Value at these stealth addresses is spendable on-chain today only via account-abstraction routes (e.g. an ERC-4337 account whose address is the counterfactual CREATE2 address of the derived key, demonstrated on Sepolia with a deployed level-2 Dilithium verifier and an ECDSA co-signer). The [ERC-7913](./eip-7913.md) signer encoding above standardizes that route, but does not reduce its cost: direct on-chain ML-DSA verification remains in the millions of gas until protocol-level support (vector-math precompiles or native post-quantum signatures) lands. Wallets MUST make this limitation clear before letting users receive value under this scheme.

**Do not roll the crypto.** Implementations SHOULD bind to audited FIPS 203/204 implementations for all primitive operations and validate any hand-written polynomial layer against the conformance vectors, negative cases included.

## Copyright

Copyright and related rights licensed under [MIT](../LICENSE).
