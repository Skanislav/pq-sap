# Key-exchange security — claims and review boundaries

Current scope after D-024/D-025. The ERC focus is ML-KEM key exchange and
sender-computable address derivation. A complete argument must cover the
**whole announcement**, including the tag and destination. KEM security alone
is not a proof that a derived account address hides its recipient.

This is a review map, not a completed reduction. The detailed
[Construction A analysis](construction-a-security.md) applies to format `0x01`;
it is supporting research, not the security theorem for format `0x02`.

## What the proposal needs to justify

| Property | Available evidence | Remaining boundary |
| --- | --- | --- |
| Honest sender/scanner agreement | Python commitment tests and independent TS vector replay; abstract KEM completeness results | Instantiate the concrete commitment/deployment flow; KEM correctness assumptions remain explicit |
| Shared-secret confidentiality | `SharedSecretHiding.lean` identifies generic hiding terms with KEM IND-CPA advantages | This does not by itself establish anonymity of the recipient key or a quantum-accessible oracle reduction |
| Recipient anonymity of ciphertexts | `KEMAnonymity.lean`, `AnonymityFromSPR.lean`, `MLKEM.lean`, `SPRTwoHop.lean` | Seeded-MLWE advantages and primitive/encoding assumptions remain; active FIPS-203 ANO-CCA mapping is separate work |
| Privacy of tag plus commitment-derived address | Generic `ofKEMFull` announcement model; executable derivation in both languages | Concrete joint derivation, recipient spend-key binding, deployment metadata, and CREATE2 composition are not discharged by Construction A's blinding proof |
| Reliable detection and rejection | Negative vectors; generic conditional soundness results in `Soundness.lean` | A one-byte tag is a filter after decapsulation, not a payment authenticator or a universal false-positive guarantee |
| Byte-level interoperability | Deterministic commitment vectors, encoding tests; abstract 1,217-byte roundtrip in `Invariants.lean` | Serialization facts are not cryptographic security or a proof of the Python/TS implementation |
| Explicit profile selection | Typed profiles and fail-closed `select_profile` in Python/TS (D-027) | A profile name and its binding are trusted configuration; nothing authenticates a substituted factory, verifier, or registrar |

The exact sources and proof-reading order are in [ERC evidence](ERC_EVIDENCE.md).
“Needed” here means evidence needed to support our claims; it does not mean
ERC reviewers must install Lean or that a formal proof is a process requirement.

## Adversaries and observations

The passive observer sees recipient meta-addresses and public announcements.
Review must include repeated announcements, the joint view tag/address
calculation, publicly known spending-key commitments, and the account profile
selected by each recipient. A distinct output in a vector is a correctness
sanity check, not evidence of computational unlinkability.

A sender knows the shared secret and opener it generated. A viewing-key holder
can recover them. Neither must be sufficient to authorize spending: this is an
obligation of the selected account model. Account code, verifier selection,
message binding, replay controls, and upgrades need separate review.

An active attacker can supply malformed announcements or ciphertexts and may
observe scanner behavior. Generic passive security results do not establish an
active ANO-CCA claim for final FIPS-203 ML-KEM. Timing, resource exhaustion,
retry leakage, and scanner/network metadata are not covered by the current
formal result. Quantum random-oracle access is also outside that result.

The deployment binding is public and supplied separately from the meta-address.
Its distribution must prevent substitution and must identify the intended
chain/account profile. The ERC-6538 registry does not provide that (its
entries are ecrecover-governed and overwritable by the classical key) and is
out of scope; the trust in a naming service or an off-chain channel is the
application's, not the scheme's. A profile shared by few recipients may itself narrow
an observer's candidate set. This requires explicit treatment even when the
commitment hash is modeled ideally.

## Spending is a separate assurance track

The key-exchange proposal does not require proving widened ML-DSA signing,
related-key signature security, or a Noir circuit to describe its receive and
scan behavior. Those obligations still matter for anyone using the corresponding
spending route. They are not removed by narrowing the ERC's scope.

- Construction A has a related-key **ownership-witness** reduction; its
  signature EUF-CMA layer remains uncomposed and widened HVZK currently has
  the trivial bound `1`. Concrete `z`-gate content of that gap (research
  note [widened-z distribution](research/widened-z-distribution.md) §4,
  corrected per review F4 2026-10-01): the honest widened signer aborts a
  `z`-gate round with probability `1 − 0.383 ≈ 0.617` at ML-DSA-65
  (`mldsa65_widened_z_accept_prob`, `WidenedSigning.lean:590`), while the
  pinned simulator's ring-uniform `z` **aborts with probability ≈ 1** (its
  gate-pass probability is ≈ 10⁻¹¹⁵⁶). Comparing the two abort masses, the
  `z`-gate-only transcript-distance contribution is
  `|0.617 − 1| ≈ 0.383` — not ≈ 0.617; the earlier text subtracted the
  simulator's success probability from the honest abort mass. Even the
  0.383 figure is a `z`-gate-only floor, not a full-scheme bound: the
  honest prover's other rejection gates (`r₀`, hint) change the honest
  abort mass, and no nontrivial full-scheme HVZK distance is claimed until
  the cube-source simulator and its exact transcript experiment land.
- The tightened `z` gate is a potential disclosure channel only in the
  fixed-shift, cube-uniform `z`-gate model. A widened `z` is always
  `‖z‖∞ < γ₁ − 2β`; a stock `z` lands entirely below that bound with
  probability `(1047791/1048183)^1280 ≈ 0.620` at ML-DSA-65 (≈ 0.543 at the
  deployed level-2 profile). A band coefficient rules out a widened
  `z`-gate response, but band avoidance is only probabilistic evidence: a
  stock response has the probability above. In that model the test has
  per-response advantage ≈ 0.38 (0.46 level-2), reaching 0.978 across eight
  independent responses. It does not establish a full published-signature
  classifier or recipient/key linkability result: Fiat–Shamir, `r₀`, and
  hint conditioning are outside the model. An observer therefore cannot use
  this calculation alone to label an observed signature as a blinded-key
  spend or narrow candidates to `0x01` recipients (note §3).
- Direct C13 spending exposes the recipient key and can link spends.
- Direct ML-DSA-44 committed-key spending (D-027) likewise reveals `pk`,
  whose hash is the published `spend_key`; spent addresses of one recipient
  are linkable from the first spend. Its local contract path trusts a key
  registrar for the expanded matrix; it is not a trustless or deployed route.
- Construction A's blinded stealth key carries the recipient's `rho`
  verbatim (`python/tests/test_construction_a_rho.py`). Receive-time
  announcements reveal only a hashed address, but any full-key disclosure at
  spend or key-contract deployment identifies the `0x01` recipient. Blinding
  alone does not guarantee unlinkability after key disclosure.
- Composed spend-time reading: the proven announcement bound
  (`Adv_unlink_q ≤ q · ε_single`, `unlinkAdvantageMulti_le_mul`,
  `MultiUnlink.lean:241`) covers a recipient who only receives and scans.
  A direct spend breaks that coverage through the key-disclosure channels —
  `rho` for any revealed Construction A key and the `spend_key` hash for the
  commit profile. The widened `z`-band calculation is only a z-gate-model
  discriminator with substantial stock false positives; it does not flag a
  blinded route in a published signature. Unlinkable spending requires routes
  that never reveal the key (ZK/preimage). The channel-by-channel map is note
  §5.
- The D-023/D-025 ZK demos use a non-PQ-sound proof backend. The intended
  witness privacy and ownership statement do not change that assumption.
- Prospective aggregation does not automatically supply zero knowledge,
  repair an underlying proof system, or prove an account's authorization.

See [spending research](SPENDING_RESEARCH.md) for implementation evidence and
[EIP-8288](research/eip-8288-summary.md) for the prospective integration assessment.

## Review priorities

1. Fix the supported profile and deployment-binding distribution in the
   human-written ERC text; specify every byte-level input.
2. Map the commitment flow into a full-announcement privacy experiment and
   justify its auxiliary-data independence under explicit hash assumptions.
3. State the classical/quantum and passive/active models precisely, including
   what comes from ML-KEM literature versus a checked theorem here.
4. Publish partial-checker coverage honestly and retain full KEM vector replay.
5. Review each spend integration separately before making end-to-end claims.
