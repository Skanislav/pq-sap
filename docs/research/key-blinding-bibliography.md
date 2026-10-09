# Key-blinding prior art — bibliography

Reviewed 2026-09-30. This closes the "key-blinding reading" item of the
[security-analysis deliverable](../SECURITY_ANALYSIS.md): a grounded survey of
key-blinding prior art from Tor v3 through the post-quantum line of work
this repository's Construction A blinding descends from. It is a literature
map, not a security claim; no theorem here changes
[the Construction A analysis](../construction-a-security.md).

## What "key blinding" names

Given a master keypair `(sk, pk)` and a public nonce `n`, a key-blinding
scheme provides:

- a derivation `(sk, n) ↦ sk_n` usable for signing, and `(pk, n) ↦ pk_n`
  computable without the secret;
- unlinkability: someone seeing many blinded public keys and their
  signatures cannot tell which derive from the same master keypair;
- unforgeability: blinding does not weaken signing.

This is exactly the shape of Tor v3's appendix
*[A. Signature scheme with key blinding [KEYBLIND]](https://gitweb.torproject.org/torspec.git/tree/rend-spec-v3.txt)*
(rend-spec-v3.txt, "Deriving blinded keys and subcredentials [SUBCRED]"):
per-period blinded Ed25519 keys `a' = h·a`, `A' = h·A` with
`h = H(BLIND_STRING | A | s | B | N)`, so descriptor lookup indexes and
signing keys rotate together without a trusted party. The Tor spec text
itself still carries its `[TODO: Insert a more rigorous definition and
better references.]` — the rigor arrived in the papers below.

## The classical baseline and why it dies

Tor v3's blinding is scalar-multiplication-homomorphic: blinding factor in
the exponent, same base point. That is a discrete-log assumption, and a
harvest-now-decrypt-later adversary breaks it. Every PQ replacement in the
list below keeps the two-derivation shape and swaps the algebra.

## The post-quantum line (the one we build on)

### Eaton, Stebila, Stracovsky — *Post-Quantum Key-Blinding for Authentication in Anonymity Networks*, Latincrypt 2021 (eprint [2021/963](https://eprint.iacr.org/2021/963))

Primary prior art for Construction A's blinded ML-DSA. Four fully PQ
key-blinding schemes (Dilithium, Picnic, CSI-FiSh, LegRoast), unlinkability
and unforgeability proven in the ROM, plus a **generic framework reducing
key-blinded unlinkability to two properties: signing with oracle
reprogramming, and independent blinding**. This is the same decomposition
this repository instantiates: the blinded key `(s₁+s', s₂+e')` is an
"independent blinding" added to the master key, and
`blindPointMassBound_mldsa` / the ROM bad-query bound
(`BlindingROM.lean`, `BlindingEntropy.lean`) are our oracle-reprogramming
side. Their Dilithium construction is the direct ancestor of our
`derive_blinding` → widened-key spend route at `β' = τ·2η`.

Caveat we inherit: ROM-only (no QROM), and their lattice blinding needs the
widened bound — exactly the `2·β` rejection-gate widening our
`WidenedSigning.lean` proves.

### Balumuri, Eaton, Lamontagne — *Quantum-Safe Public Key Blinding from MPC-in-the-Head Signature Schemes*, PQCrypto 2025 (eprint [2024/945](https://eprint.iacr.org/2024/945))

The direct follow-up: first **QROM** key-blinding proof, built from any
MPC-in-the-Head signature (instantiated with Helium). Explicitly names the
Eaton–Stebila–Stracovsky lattice schemes' shortcomings — large public keys,
ROM-only security — and closes the QROM gap on the symmetric side. Relevant
to us as the current frontier for QROM blinding: our Construction A
analysis remains ROM (classical oracle access), a boundary
[construction-a-security.md §7](../construction-a-security.md) already
records as an exclusion.

### Basso, Borin, Corte-Real Santos, Dartois, Invernizzi, Maino, Pedersen, Seck — *Isogeny-based Signatures with Randomizable Keys*, 2026 (eprint [2026/1169](https://eprint.iacr.org/2026/1169))

Randomizable (blinded) keys from higher-dimensional isogenies — compact
signatures, group-action-style blinding similar to CSI-FiSh's role in
Eaton et al. Tracked as an alternative PQ blinding family; not used in any
route here (no isogeny machinery in this repository).

## Adjacent but distinct (do not conflate with key blinding)

**Blind signatures** (lattice round-optimal [eprint 2023/077](https://eprint.iacr.org/2023/077),
Tanuki [2025/1100](https://eprint.iacr.org/2025/1100), and the older
lattice blind-signature line) blind the *message*, not the key: a signer
signs without seeing what it signs. Key blinding blinds the *key* — the
signer knows exactly what it signs, on a derived pseudonymous identity.
Tor's use case and ours are key blinding; blind signatures are a different
primitive with a different security game.

**Anonymous credentials / Privacy Pass** ([eprint 2023/414](https://eprint.iacr.org/2023/414)):
multi-show unlinkable credential presentations. Overlapping vocabulary,
different trust model (issuer-held attributes).

## What this means for the ERC security write-up

1. The bibliography line is closed: Tor v3 spec → Eaton et al. 2021 (our
   direct ancestor, ROM) → Balumuri et al. 2025 (QROM frontier) is the
   complete key-blinding spine, plus isogeny randomization as the
   alternative family.
2. The widened-z write-up in
   [construction-a-security.md §1.2a/§8](../construction-a-security.md)
   is the Eaton-framework "independent blinding" side instantiated at
   ML-DSA-65: cube-uniform mask, widened gates, exact acceptance
   probability `(1047791/1048576)^1280`, independent of the secret. The
   two-property decomposition gives the write-up its citation anchor: our
   blinding analysis is an instantiation of their generic framework, not
   an ad-hoc construction.
3. The ROM/QROM boundary is the honest frontier statement for the ERC:
   classical-ROM decomposition proven in-repo; QROM blinding exists in the
   literature (2024/945) but only for symmetric (MPCitH) schemes — a
   QROM proof for lattice blinding remains open, and we should say so
   rather than imply it.