# Key-blinding prior art — bibliography

Reviewed 2026-09-30. This closes the "key-blinding reading" item of the
project roadmap ([original-project-plan.md](original-project-plan.md)): a
grounded survey of key-blinding prior art from Tor v3 through the
post-quantum line of work this repository's Construction A blinding descends
from. It is a literature map, not a security claim; no theorem here changes
[the Construction A analysis](../construction-a-security.md), and the
current claim boundaries stay in
[SECURITY_ANALYSIS.md](../SECURITY_ANALYSIS.md).

Scope: key blinding. Blind signatures appear only to keep the vocabularies
apart; zk-login / social-recovery key custody and proxy re-encryption are not
surveyed here.

## What "key blinding" names

Given a master keypair `(sk, pk)` and a public nonce `n`, a key-blinding
scheme provides:

- a derivation `(sk, n) ↦ sk_n` usable for signing, and `(pk, n) ↦ pk_n`
  computable without the secret;
- unlinkability: someone seeing many blinded public keys and their
  signatures cannot tell which derive from the same master keypair;
- unforgeability: blinding does not weaken signing.

This is exactly the shape of Tor v3's appendix
*[A. Signature scheme with key blinding [KEYBLIND]](https://raw.githubusercontent.com/torproject/torspec/main/rend-spec-v3.txt)*
(rend-spec-v3.txt, appendix A.2 for the derivation, §2.1 "Deriving blinded
keys and subcredentials [SUBCRED]" for the mechanism):
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
key-blinding schemes in the ePrint revision (Dilithium, Picnic, CSI-FiSh,
LegRoast); the LATINCRYPT 2021 proceedings version has three, without Picnic,
so cite the revision meant. Unlinkability and unforgeability proven in the
ROM, plus a **generic framework reducing key-blinded unlinkability to two
properties: signing with oracle reprogramming, and independent blinding**.
This is the same decomposition this repository instantiates: the blinded key
`(s₁+s', s₂+e')` is an "independent blinding" added to the master key, and
`blindPointMassBound_mldsa` / the ROM bad-query bound
(`BlindingROM.lean`, `BlindingEntropy.lean`) are our oracle-reprogramming
side. Their Dilithium construction is the direct ancestor of our
`derive_blinding` → widened-key spend route at `β' = 2·β = τ·2η`.

Boundary on that mapping: our ROM work is the **announcement/address** side.
`BlindingROM.lean` records the identification of its idealized game with
`auxKeyIndependence` as assumed, not proved, and there is no blinded-signature
unlinkability game in the tree at all (issue #34: a direct ML-DSA spend
reveals `pk`, whose hash is the published `spend_key`). The framework citation
therefore anchors the address argument, not a signing-side result. The
related-key unforgeability leg does have an in-repo anchor:
`relatedSpendAdvantage_le_mul_spendForgery` (`SpendSecurity.lean`).

Caveat we inherit: ROM-only (no QROM), and their lattice blinding needs the
widened bound — exactly the `2·β` rejection-gate widening our
`WidenedSigning.lean` proves.

### Balumuri, Eaton, Lamontagne — *Quantum-Safe Public Key Blinding from MPC-in-the-Head Signature Schemes*, ACNS 2025, LNCS pp. 369–397 (eprint [2024/945](https://eprint.iacr.org/2024/945))

The direct follow-up: first **QROM** key-blinding proof, built from any
MPC-in-the-Head signature (instantiated with Helium). Explicitly names the
Eaton–Stebila–Stracovsky lattice schemes' shortcomings — large public keys,
ROM-only security — and closes the QROM gap on the symmetric side. Relevant
to us as the current frontier for QROM blinding: our Construction A
analysis remains ROM (classical oracle access), a boundary
[construction-a-security.md §7](../construction-a-security.md) already
records as an exclusion.

### Basso, Borin, Corte-Real Santos, Dartois, Invernizzi, Maino, Pedersen, Seck — *Isogeny-based Signatures with Randomizable Keys*, 2026 (eprint [2026/1169](https://eprint.iacr.org/2026/1169))

Randomizable (blinded) keys for SQIsign, PRISM and DeuringVUF — deliberately
*outside* the class-group-action setting, whose signatures "suffer from a
subexponential quantum attack", and so the opposite of the CSI-FiSh route in
Eaton et al. Works in the randomizable-key notion of Celi et al. below and
proves unlinkability against unbounded adversaries for all three
instantiations. Tracked as an alternative PQ blinding family; not used in any
route here (no isogeny machinery in this repository).

### Celi, Griffy, Hanzlik, Perez Kempner, Slamanig — *SoK: Signatures with Randomizable Keys*, FC 2025, LNCS pp. 160–187 (eprint [2023/1524](https://eprint.iacr.org/2023/1524))

The systematization this note would otherwise reinvent: unified vocabulary
across Derler–Slamanig, Backes et al. and Eaton et al., the security-property
taxonomy, and the gaps. Key blinding is one flavour of randomizable keys, and
it is the notion Basso et al. build on. Read this before adding entries.

## Adjacent but distinct (do not conflate with key blinding)

**Blind signatures** (lattice round-optimal [eprint 2023/077](https://eprint.iacr.org/2023/077),
Tanuki [2025/1100](https://eprint.iacr.org/2025/1100), and the older
lattice blind-signature line) blind the *message*, not the key: a signer
signs without seeing what it signs. Key blinding blinds the *key* — the
signer knows exactly what it signs, on a derived pseudonymous identity.
Tor's use case and ours are key blinding; blind signatures are a different
primitive with a different security game.

**Deterministic derivation** (Alkadri et al., *Deterministic Wallets in a
Quantum World*, CCS 2020): per-address keys from a master secret with no
sender-computable public form. It answers issue #34's question — fresh
recipient-controlled keys per address — not the sender-side derivation this
scheme needs. Eaton et al. cite it; it is the wrong tool for blinding and the
right reference for rotation.

**Anonymous credentials / Privacy Pass** ([eprint 2023/414](https://eprint.iacr.org/2023/414)):
multi-show unlinkable credential presentations. Overlapping vocabulary,
different trust model (issuer-held attributes).

## What this means for the ERC security write-up

1. The key-blinding spine is Tor v3 spec → Eaton et al. 2021 (our direct
   ancestor, ROM) → Balumuri et al. 2025 (QROM, MPCitH only), with Celi et
   al.'s SoK as the map and isogeny randomization (Basso et al. 2026,
   unbounded-adversary unlinkability) as the alternative family. That is the
   set of families we build on, not a literature-completeness claim.
2. The widened-z write-up in
   [construction-a-security.md §1.2a/§8](../construction-a-security.md)
   is the Eaton-framework "independent blinding" side instantiated at
   ML-DSA-65: cube-uniform mask, widened gates, exact acceptance
   probability `(1047791/1048576)^1280`, independent of the secret. The
   two-property decomposition gives the write-up its citation anchor: the
   address-side blinding analysis is an instance of their generic framework,
   not an ad-hoc construction (signing side: see the boundary above).
3. The ROM/QROM boundary is the honest frontier statement for the ERC:
   classical-ROM decomposition proven in-repo; QROM blinding exists for
   MPCitH (2024/945) and unconditionally for the three isogeny schemes of
   2026/1169, but not for lattice blinding — still open as of 2026-10. Date
   that claim wherever the ERC text repeats it.
