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
chain/account profile. A profile shared by few recipients may itself narrow
an observer's candidate set. This requires explicit treatment even when the
commitment hash is modeled ideally.

## Spending is a separate assurance track

The key-exchange proposal does not require proving widened ML-DSA signing,
related-key signature security, or a Noir circuit to describe its receive and
scan behavior. Those obligations still matter for anyone using the corresponding
spending route. They are not removed by narrowing the ERC's scope.

- Construction A has a related-key **ownership-witness** reduction; its
  signature EUF-CMA layer remains uncomposed and widened HVZK currently has
  the trivial bound `1`.
- Direct C13 spending exposes the recipient key and can link spends.
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
