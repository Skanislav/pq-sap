# Project plan — key-exchange ERC and supporting research

Current scope follows D-024/D-025. Deliver a reviewable proposal for ML-KEM
key exchange and sender-computable stealth destinations using existing
ERC-5564 announcements; the ERC-6538 registry is out of scope (D-014 scope
update, 2026-09-28). The original cohort plan is preserved as
[historical context](docs/research/original-project-plan.md).

## Core deliverable

1. Describe the supported meta-address profile, KEM announcement, tag,
   commitment derivation, and deployment binding in human-written ERC text.
   Format `0x02` is implemented; whether `0x01` is also normative remains open.
2. Package deterministic vectors and Python/TS reference behavior. Provide a
   small reviewer checker with explicit coverage limits.
3. Present the full-announcement security argument, separating existing generic
   KEM results from the commitment/address composition still needing review.
4. Publish reproducible receive/scan and data-size measurements with the exact
   profile, hardware, and environment.
5. Obtain community review before freezing the text and preparing a submission.

## Current evidence and next work

| Area | Current state | Next deliverable |
| --- | --- | --- |
| Key exchange and address derivation | Python `commit.py`, TS `commit-scheme.ts`, deterministic commitment vectors | Agreed profile/deployment binding in the human-written specification |
| Portable conformance | Reference tests and cross-language replay | Standalone checker and self-contained assets |
| Security | Generic KEM/announcement Lean results; Construction A analysis | Concrete commitment-profile privacy argument and explicit assumptions |
| Deployment feasibility | Account routes, browser preimage demo, explicit account profiles with an ML-DSA-44 committed-key reference and local contract path (D-027) | Separate route review; trustless ML-DSA key setup and any ML-DSA-65 verifier remain open; not a prerequisite to describe KEM conformance |
| Documentation | Key-exchange review path, research and tooling separated | Keep public claims aligned with actual evidence |

Start with the [technical reference](docs/TECHNICAL_SPEC.md),
[ERC evidence map](docs/ERC_EVIDENCE.md), and
[submission roadmap](docs/research/erc-submission-gap-analysis.md).

## Supporting tracks

Construction A's blinded-key derivation, widened ML-DSA signing, ownership/SIS
proofs, Noir circuits, alternative account routes, and EIP-8288 integration
are [supporting research](docs/SPENDING_RESEARCH.md). They remain available
and audited under the current build policy, but are not the key-exchange ERC's
required reading or a promise of completed spending security.

[Lean tooling](lean/docs/tooling.md), upstream contributions, and theorem-browser
work serve maintainers. Completing those backlogs is not the ERC critical path.
The commitment flow still needs its own security justification; narrowing scope
does not allow skipping that obligation.

The ERC draft remains human-written. Local changes are reviewed before any
commit, push, or PR, under the repository house rule.
