# Ethereum Magicians thread draft — Post-Quantum Stealth Addresses (ERC-5564 scheme ID)

**Category:** EIPs / ERCs — Standards Track
**Title:** Post-Quantum Stealth Addresses — a new ERC-5564 scheme
**Planned URL:** `https://ethereum-magicians.org/t/post-quantum-stealth-addresses-erc-5564-scheme/NNNNN`
(To be inserted into `docs/erc-draft.md` as `discussions-to`.)

---

## Abstract

This proposal registers a post-quantum stealth-address scheme under ERC-5564. Detection uses ML-KEM-768 (FIPS 203); the ephemeral public key in the announcement is the KEM ciphertext, and the shared secret drives a one-byte view tag and the address derivation. The spending key is an additively blinded ML-DSA-65 (FIPS 204) key whose signatures verify under any stock ML-DSA verifier. The scheme works against the already-deployed ERC-5564 announcer and ERC-6538 registry.

**Target scheme ID:** `2` (next unassigned after `1` = SECP256K1). Earlier prototypes used the placeholder `0x5567`; the draft and reference implementation now use `2`.

## What is being frozen

- One normative meta-address format: `version ‖ rho ‖ pack23(t) ‖ ek` (5,633 B for the default ML-KEM-768 + ML-DSA-65 set).
- One normative announcement: `announce(schemeId=2, stealth_address, ephemeral_pub_key=R, metadata[0]=view_tag)`.
- Deterministic v0 conformance vectors (positive + negative cases), reproduced byte-for-byte by an independent TypeScript client.
- A machine-checked Lean 4 core (VCVio): blinding identity, widened bound `β' = τ·2η`, encoding roundtrips, and security games.

## Open security question (stated plainly)

The blinded secret coefficients reach `2η`, so the post-rejection `z` distribution differs from stock ML-DSA. Signatures verify under unmodified FIPS 204 verifiers, but the leakage analysis of the widened distribution is the remaining open item in the security write-up. Until it closes, the draft recommends treating reuse of a single stealth key for many signatures conservatively.

We are seeking review on whether a paper-level argument + the single-use recommendation is sufficient for a Draft ERC, or whether the spec freeze should wait on a tighter bound.

## Links

- ERC draft: [`docs/erc-draft.md`](https://github.com/Skanislav/pq-sap/blob/main/docs/erc-draft.md)
- Decision log: [`docs/DECISIONS.md`](https://github.com/Skanislav/pq-sap/blob/main/docs/DECISIONS.md)
- Conformance vectors: [`python/vectors/v0/vectors.json`](https://github.com/Skanislav/pq-sap/blob/main/python/vectors/v0/vectors.json)
- Reference implementation: [`python/pq_stealth/`](https://github.com/Skanislav/pq-sap/tree/main/python/pq_stealth)
- TypeScript client: [`js-client/`](https://github.com/Skanislav/pq-sap/tree/main/js-client)
- Lean core: [`lean/PqStealth/`](https://github.com/Skanislav/pq-sap/tree/main/lean/PqStealth)

## Review ask

1. Is scheme ID `2` acceptable to the ERC-5564 editors?
2. Does the normative surface (detection + one meta-address encoding) look right, or should the ZK-spend / compact-meta-address variant (`docs/DECISIONS.md` D-012) remain informative only?
3. Is the widened-`z` leakage argument plus a single-use mitigation adequate for Draft, or should the freeze wait on a tighter concrete bound?

---

*Posted on behalf of the EPF cohort-seven project. This thread is the community review round before the spec freeze and the PR to `ethereum/ERCs`.*
