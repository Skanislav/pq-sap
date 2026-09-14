# ERC evidence — key exchange first

Use this guide to review the D-024 key-exchange proposal without first reading
blinded-signature research or building the entire Lean package. The
[technical reference](TECHNICAL_SPEC.md) describes the current implementation;
the [security overview](SECURITY_ANALYSIS.md) states the unresolved obligations.
The final normative formats remain for the human-written ERC text.

## The review package

| Evidence needed for the stated scope | Start here | What it establishes |
| --- | --- | --- |
| Exact receive/scan behavior and deployment inputs | [Technical reference](TECHNICAL_SPEC.md), [Python commit module](../python/pq_stealth/commit.py) | Executable byte-level definition for the current commitment profile |
| Reproducibility and independent implementation | [Commitment vectors](../python/vectors/v0/commit_vectors.json), [Python tests](../python/tests/test_commit.py), [TS replay](../js-client/test/commit-vectors.test.ts) | Agreement on deterministic examples and rejection behavior |
| Full-announcement security argument | [Security overview](SECURITY_ANALYSIS.md) | Separates KEM confidentiality, recipient anonymity, and the commitment/address composition still to justify |
| Portable reviewer checks | [Submission roadmap](research/erc-submission-gap-analysis.md) | Planned standalone checker; not implemented by this documentation refactor |
| Encoding and generic game support | Lean declarations below | Precisely scoped abstract results, not a verification of application code |

A minimal reviewer path is technical reference → commitment vectors → security
overview → submission roadmap. Lean supplies additional evidence for named
claims. Completing every spending proof or tooling improvement is not a
prerequisite for this key-exchange package.

## Relevant Lean results

Source files are in [lean/PqStealth](../lean/PqStealth/). This table is a
semantic reading map, **not** an isolated build target.

| Modules | Relevant declarations | Limits |
| --- | --- | --- |
| `Games`, `KEMAnonymity` | `StealthScheme`, `ofKEMFull`, `perfectlyComplete_ofKEMFull`, `unlinkAdvantage_ofKEMFull_le` | Generic scheme and auxiliary-data model; concrete commitment instantiation still needed |
| `SharedSecretHiding` | `sharedSecretHiding_eq_indCpaAdvantage`, `unlinkAdvantage_ofKEMFull_le_indCpa` | Identifies the hiding terms, not the whole anonymity argument |
| `AnonymityFromSPR`, `MLKEM`, `SPRTwoHop` | `KEM.anonAdvantage_le_sprAdv`, `mlkem768_sprAdv_le_mlwe` | Ciphertext anonymity decomposition with named assumptions and MLWE terms |
| `MultiUnlink`, `MultiRecipient` | `unlinkAdvantageMulti_le_mul`, `unlinkAdvantageN_le_mul` | Generic losses for multiple announcements/recipients; requires an applicable single-challenge bound |
| `Soundness` | `falsePositiveRate_ofKEMFull_le`, `soundWithin_ofKEMFull_oneByteTag` | Conditional bounds; does not prove arbitrary SHA-256 tag behavior unconditionally |
| `Invariants` | `meta_address_zk_roundtrips_1217` | Abstract encode/decode roundtrip; does not prove commitment hiding, CREATE2 correctness, or runtime code |

The current `check_sizes.py` compares Construction A and classical-hybrid
vectors, including the documented 1,217/1,218-byte layout difference. It does
**not** check `commit_vectors.json`. Commitment conformance currently comes
from Python/TS tests, not that checker.

## Separate research and tooling

| Track | Modules or artifacts | Relationship to the ERC |
| --- | --- | --- |
| Construction A address derivation | `Blinding`, Construction A parts of `Invariants`, `ConstructionA`, `BlindingROM`, `BlindingEntropy`, `ConstructionASecurity` | Relevant if format `0x01` is included; not the privacy proof for format `0x02` |
| ML-DSA spending security | `Ownership`, `WidenedSigning`, `SpendSecurity`, spending portions of `ConstructionASecurity` | Account/spending research; witness extraction is not completed signature security |
| Classical comparison | `DKSAP`, `DKSAPOracle`, `Demo` | Motivation and control experiments; not needed to implement the commitment format |
| Shared proof infrastructure | `Reorder`, `ROMUpToBad`, `Controls`, `Axioms` | Supports and audits the development; not normative protocol behavior |
| Tooling and upstream work | Lean build pin, citation/size scripts, generated theorem browser, VCVio notes | Maintainer workflow; not reviewer installation requirements |
| Account and ZK experiments | ERC-4337/7913/8141 routes, Noir circuits, UI | Feasibility evidence with independent security and network assumptions |

The [Lean overview](../lean/README.md) maps all modules; the
[spending guide](SPENDING_RESEARCH.md) maps the account experiments.

## What has not been separated in code

`lean/PqStealth.lean` and `Axioms.lean` still import the entire development.
`Games.lean` imports `Blinding.lean`; `Invariants.lean` mixes serialization
with ML-DSA algebra; `Soundness.lean` imports the classical model. Therefore
building a relevant module can still compile unrelated support code.

This documentation split does not delete proofs, weaken the axiom audit, change
CI, or claim an ERC-only Lean package exists. Maintainers continue to run the
full checks for changes to the proof library. Any later module extraction must
preserve the audited statements and be reviewed as its own code change.
