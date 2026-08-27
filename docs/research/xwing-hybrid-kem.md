# X-Wing as the discovery KEM: what a PQ/T hybrid buys us, and what it doesn't

*2026-08-27. Companion artifacts: `python/benchmarks/xwing_bench.py` (+
`xwing_20260827.json`), validated against the official draft test vectors.
Extends the D-012 discovery-KEM design space and the D-016 "lattice is
load-bearing" finding.*

## 1. Question

D-016 settled that discovery needs a structured PQ KEM — hash-only key
exchange is impossible beyond a polynomial (and quantumly, no) gap. That
leaves the residual risk D-012 priced with NTRU/HQC backups: **what if
Module-LWE falls to classical cryptanalysis?** The standard industry answer
is a PQ/T hybrid, and the standalone hybrid KEM is X-Wing
(X25519 + ML-KEM-768). This memo evaluates X-Wing as an alternative (or
additional parameter set) for the discovery KEM, on the three usual axes
plus the one that actually decides it for us: **which of our security terms
the hybrid hedges**.

## 2. What X-Wing is (spec status, August 2026)

- Construction (draft-connolly-cfrg-xwing-kem-10, 2026-03-02; eprint
  2024/039, IACR CiC 1(1)): one ML-KEM-768 encapsulation plus one X25519
  ECDH, combined as

  ```
  ss = SHA3-256( ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ "\.//^\" )
  ```

  pk = ek_M ‖ pk_X = **1216 B**; ct = ct_M ‖ ct_X = **1120 B**; decapsulation
  key = **32-B seed** (SHAKE256-expanded to d, z, and the X25519 scalar).
  The ML-KEM ciphertext is deliberately *not* hashed: ML-KEM's FO
  re-encryption check makes it C2PRI (ciphertext second-preimage resistant
  even given the secret key), which already binds ct_M through ss_M.
- Standards status: **not an RFC** and never adopted as a CFRG WG item, but
  the construction is being standardized bit-identically as
  **MLKEM768-X25519** in draft-irtf-cfrg-concrete-hybrid-kems and in the
  HPKE PQ draft (IANA HPKE KEM codepoint 0x647a). Don't confuse it with
  TLS's X25519MLKEM768 (RFC 10024) — that is a handshake-level
  concatenation into HKDF, not a standalone IND-CCA KEM.
- Deployment: Apple CryptoKit ships it (iOS 26 / macOS 26 PQ HPKE);
  BoringSSL, Cloudflare CIRCL, filippo.io/mlkem768/xwing, RustCrypto
  `x-wing`, libcrux. **Not in liboqs or upstream OpenSSL.** NIST SP 800-227
  (final, Sept 2025) blesses exactly this shape of hybrid (approved
  component + approved combiner), so it is FIPS-track-compatible.
- Formal verification: EasyCrypt proofs in `formosa-crypto/formosa-x-wing`
  (README still says WIP); the libjade Jasmin implementation has composed
  functional-correctness proofs (Jazzline, CCS 2025).

## 3. Measured (this machine, `xwing_bench.py`)

Implementation: kyber-py derandomized internals + `cryptography` X25519,
**all three official test vectors pass byte-identically** (pk, ct, encaps
ss, decaps ss). Timing composes the liboqs ML-KEM-768 figure with a native
X25519 (`openssl speed ecdhx25519`: 33,169 op/s = 30.2 µs) so the row is
apples-to-apples with `discovery_kem_20260801.json`.

| candidate | pk B | ct B | decaps µs | scan80k s | meta B | announce gas |
|---|---|---|---|---|---|---|
| ML-KEM-768 (reference) | 1184 | 1088 | 17.2 | 1.38 | 1217 | 67,670 |
| **X-Wing** (native comp.) | 1216 | 1120 | 48.0 | 3.84 | 1249 | 68,890 |
| X-Wing (py-wrapped x25519) | 1216 | 1120 | 177 | 14.2 | 1249 | 68,890 |

(Gas via the EIP-7623 floor model with random ciphertext bytes — ±~100 gas
run-to-run; the measured on-chain ML-KEM announce is 67,580.)

Components: ML-KEM-768 decaps 17.2 µs + X25519 30.2 µs + SHA3-256 combine
0.6 µs. Two observations:

1. **The classical leg dominates the hybrid's scan cost** (X25519 is ~1.8×
   the ML-KEM decaps — ML-KEM really is faster than curve arithmetic).
   Hybrid tax: **2.8× scan, +~1,220 gas (+1.8%), +32 B meta-address**.
2. Even so, X-Wing at 3.84 s/80k **beats the best NTRU hedge**
   (NTRU-HPS-2048-677: 4.19 s) and every non-lattice family by 1–3 orders
   of magnitude. As a "second assumption" play, the hybrid is cheaper than
   switching lattice families, and vastly cheaper than leaving lattices.

The 32-B seed decapsulation key is an operational win: the whole viewing
key backs up as one 32-byte secret (vs 64 B of (d,z) plus formats today).
Caveat that comes with it: X-Wing's MAL-BIND-K-{PK,CT} claims **hold only
if the key is stored/transmitted as the seed** — never the expanded ML-KEM
decapsulation key (Schmieg, eprint 2024/523; draft §Security).

## 4. The part that decides it: which terms does the hybrid hedge?

Our Lean chain decomposes unlinkability as

```
unlink  ≤  ssHiding(true) + auxKeyIndependence + anon + ssHiding(false)
```

(shared-secret hiding = real-or-random KEM IND-CPA; anon = ciphertext
key-privacy; aux = view tag + stealth address derived from ss and pk).
X-Wing treats these terms *differently*, and the recent literature states
the split exactly:

**Hedged (OR of assumptions): the ssHiding terms.** X-Wing's headline
theorems (eprint 2024/039): IND-CCA classically from strong-DH on Curve25519
(+ C2PRI of ML-KEM, ROM), and post-quantum from ML-KEM IND-CCA + SHA3 as
PRF (standard model). Either leg keeps ss pseudorandom. For us that means
**view tags and derived stealth addresses stay hiding even if Module-LWE
falls classically** — the scan-side detection privacy genuinely becomes
"MLWE OR strong-DH".

**NOT hedged (AND of assumptions): the anon term.** Bao–Pan, "Anonymity of
X-Wing and its Variants" (PKC 2026, eprint 2026/396 — the first anonymity
analysis; the original paper proves none) states it outright (Remark 1,
crediting Günther et al.): a parallel hybrid concatenates both ciphertexts,
so **if either component ciphertext leaks which public key it belongs to,
hybrid anonymity is broken** — anonymity is an AND, unlike IND-CCA's OR.
For X-Wing specifically the X25519 leg is unconditionally weakly anonymous
(ct_X is an ephemeral public key, independent of the recipient — their
Lemma 4), so the AND collapses to: **X-Wing's anonymity = ML-KEM's
anonymity, full stop**. The classical leg is an anonymity free-rider; it
cannot mask ct_M, which sits on-chain in every announcement. A classical
MLWE distinguisher that links ct_M to a candidate ek_M delinks X-Wing
announcements exactly as it would plain ML-KEM ones.

So the honest claim for the ERC is:

> A hybrid parameter set hedges *detection privacy* (view-tag and address
> pseudorandomness) and shared-secret confidentiality against a classical
> lattice break, but announcement–meta-address unlinkability still rests on
> ML-KEM's ciphertext anonymity alone. It is not "DKSAP-grade privacy if
> lattices fall."

Against the actual HNDL adversary (quantum, retroactive) the hybrid is
exactly neutral: Shor kills the X25519 leg and X-Wing degrades to
precisely our current ML-KEM-only scheme — no regression, no gain. The
hybrid's value is purely the *classical-cryptanalysis* hedge, which is
also the scenario (lattice estimates eroding) most analysts consider more
live than CRQCs this decade.

**What an OR-anonymity hybrid would take:** Günther–Rosenberg–Stebila–
Veitch (CRYPTO 2025, eprint 2025/408) get it with a *nested* combiner
(outer KEM encrypts/obfuscates the inner ciphertext), but that requires
uniform-looking outer ciphertexts (Elligator-encoded X25519 or
Kemeleon-encoded ML-KEM) plus extra primitives. Nonstandard, heavier, and
no deployed spec — noted as the research-grade option, not proposed.

### 4.1 Lean/model notes

- Instantiating our `ofKEMFull` chain at X-Wing is structurally easy (it is
  a KEM with the same ProbComp shape), and the AnonymityFromSPR route gets
  *simpler* in one respect: the anon term reduces to ML-KEM SPR alone,
  since a simulator can sample ct_X honestly (fresh ephemeral) — it carries
  no key information.
- One trap for SPR-style simulators: **honest ct_X is not uniform bytes**
  (a random 32-B string lands on the curve only ~half the time), so the
  `mlkem768UniformCiphertext`-style uniform-bytes simulator is wrong for
  the X25519 component — simulate with a random *curve point* (or Elligator
  if uniform bytes are wanted). Same subtlety Günther et al. handle with
  obfuscated encodings.
- Robustness/detection-soundness modeling carries over unchanged: X-Wing is
  implicit-rejecting (never ⊥), so scan-side detection must be
  tag-comparing, as our Soundness work already models for ML-KEM. Bao–Pan's
  WCPR-CCA assumption (wrong-key decapsulation is pseudorandom) is the
  false-positive-rate ingredient in hybrid form.

## 5. Fit with the rest of the design

- **Complementary to PR #1, not competing.** ivanmmurciaua's
  classical-spend hybrid hybridizes the *spend* side (secp256k1 key +
  ML-KEM discovery); X-Wing hybridizes the *discovery* side. A maximal
  PQ/T-conservative profile would be X-Wing discovery + 7913-signer spend.
- **Tag chains compose.** The §2.2 (poseidon2 memo) Aztec-style tag-chain
  design amortizes whatever KEM seeds the handshake; an X-Wing handshake
  seeds it identically, and repeat-sender announcements then avoid the
  +1.8% gas entirely.
- **Client story is easy.** js-client can compose X-Wing from
  @noble/post-quantum (ML-KEM-768) + @noble/curves (x25519) + SHA3 — ~30
  lines against the official vectors; no new vendored crypto. Python side
  as in `xwing_bench.py`. liboqs absence doesn't block us.
- **ERC integration**, if adopted: a sibling parameter set / scheme-ID row
  (meta-address 1 + 32 + 1216 = 1,249 B under ZK-spend; ct 1,120 B;
  announce ~68,890 gas at the EIP-7623 floor), with two normative MUSTs
  imported from the draft: store/exchange the decapsulation key only as
  the 32-B seed (binding), and run the ML-KEM encapsulation-key check.

## 6. Verdict — **adopted as optional (D-017, locked 2026-08-27)**

*User decision 2026-08-27: X-Wing is offered as an optional hybrid
parameter set; the default stays ML-KEM-768. Folded into the ERC draft
(Parameter sets `0x02` variant, Rationale, Security Considerations) and
`docs/DECISIONS.md` D-017. Original assessment below.*

X-Wing is the **best-value second-assumption play in the whole measured
design space**: cheaper on scan than any non-MLWE family including NTRU,
+32 B / +1.8% gas footprint, 32-B viewing-key backup, real deployments and
a near-RFC spec, and formal analysis (IND-CCA proofs, PKC 2026 anonymity
proofs, EasyCrypt WIP) that plugs directly into our Lean decomposition.
Its limit must be stated honestly: **it hedges detection privacy and
confidentiality, not ciphertext anonymity** — unlinkability keeps a
single point of failure in ML-KEM's SPR either way.

Recommendation: keep ML-KEM-768 as the default (scheme ID 2) and consider
X-Wing/MLKEM768-X25519 as an *optional hybrid parameter set* in the ERC,
replacing NTRU as the named hedge (D-012 shortlist update: NTRU's only
remaining edge is footprint, and it has no combiner spec, no anonymity
analysis, and slower scans). Adopted as D-017.

## Sources

Spec/impl: draft-connolly-cfrg-xwing-kem-10; draft-irtf-cfrg-concrete-
hybrid-kems; draft-ietf-hpke-pq (IANA 0x647a); RFC 10024 (TLS, distinct);
NIST SP 800-227; Apple WWDC25 session 314; github.com/dconnolly/
draft-connolly-cfrg-xwing-kem (test vectors). Proofs: eprint 2024/039
(+ CiC 1(1) journal), 2026/396 (Bao–Pan anonymity, PKC 2026), 2025/408
(Günther et al., OR-anonymity nested combiner), 2025/1397 (Starfighters:
QSF generality/C2PRI of FO KEMs — HQC fails C2PRI), 2025/1416 (binding of
real-world combiners), 2024/523 (Schmieg, ML-KEM ¬MAL-BIND), 2022/1696
(Maram–Xagawa, Kyber ANO-CCA ROM+QROM), 2021/708, 2021/1323. Verification:
formosa-crypto/formosa-x-wing (EasyCrypt, WIP); Jazzline (CCS 2025).
Caveat: no published ANO-CCA proof for final FIPS-203 ML-KEM specifically
(round-3 Kyber only) — Bao–Pan take component anonymity as assumption.
