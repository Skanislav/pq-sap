# EIP-8288 and post-quantum stealth addresses

Reviewed 2026-09-14. This is an integration assessment, not a route decision
or ERC specification. The project's current scope is recorded in
[D-024 and D-025](../DECISIONS.md).

## Proposal summary

[EIP-8288](https://eips.ethereum.org/EIPS/eip-8288) is a Draft Core proposal
extending EIP-8141 with signature and proof aggregation. Transactions declare
dependencies as `(scheme, data_hash, verification_key_hash)` triples.
Mempool participants aggregate witnesses into recursive STARKs; block validity
requires a proof covering the block's dependencies. Accounts can inspect the
declared dependencies through frame introspection.

The direct schemes are leanSPHINCS and leanSTARK. Other signatures need ordinary
on-chain verification or a client-side STARK wrapper. The draft charges 3,000
gas per leanSPHINCS dependency and 30,000 per leanSTARK dependency, and defines
separate block-proof accounting. These are proposed charges, not measured total
transaction costs. Its aggregate verification key is still `TBD`.
Sources: [specification](https://eips.ethereum.org/EIPS/eip-8288#specification),
[gas accounting](https://eips.ethereum.org/EIPS/eip-8288#gas-accounting),
[signature alternatives](https://eips.ethereum.org/EIPS/eip-8288#why-lean-ethereum).

## What it means for this repository

Our assessment: aggregation is a possible spending integration for D-024's
key-exchange design. Receiving and scanning still use ML-KEM, the view tag,
commitment derivation, and the deployment binding. Adoption of EIP-8288 is
not necessary to demonstrate those operations against ERC-5564 announcements.

| Existing route | Evidence and security boundary | Work needed for an aggregation experiment |
| --- | --- | --- |
| Construction A, blinded ML-DSA | Python/TS derivation and Lean results; signature-security composition remains incomplete | Implement and benchmark a compatible signature-verification proof; retain the existing security caveats |
| Direct SPHINCS-C13 | Implemented spending; revealing the recipient key makes spends linkable | Establish compatibility with the exact leanSPHINCS profile before claiming a direct route |
| C13 signature inside ZK | D-023 demonstrates a hidden-key statement with UltraHonk | Port the statement to a compatible PQ-sound, zero-knowledge proof backend |
| Preimage ownership in the browser | D-025 demonstrates proving knowledge of the secret and opener; UltraHonk is not PQ-sound | Evaluate this smaller statement first with a compatible PQ-sound, zero-knowledge backend |

Sources: [Construction A analysis](../construction-a-security.md),
[C13 proof experiment](zk-sphincs-frames.md), [D-024/D-025](../DECISIONS.md).
These routes do not inherit one another's proofs. In particular, the Lean
Construction A results are not an end-to-end proof of commitment-account security.

## Recommended integration experiment

Start with D-025's preimage-ownership statement. This is a recommendation for
future work; no EIP-8288 integration is claimed here.

1. Specify the exact public-input encoding for the account commitment and
   transaction authorization message. Identify the selected verification key
   and bind the expected statement to the account's authorization policy.
2. Prove the statement with a compatible backend. Check both quantum soundness
   and zero knowledge; wrapping the existing pairing-based proof alone does
   not fix its underlying soundness assumption.
3. Have account validation require the exact expected dependency. Test rejection
   of a changed message, commitment, verification key, or missing dependency,
   plus replay across nonces, accounts, and chains.
4. Inspect what a sender, mempool observer, aggregator, and chain observer can
   learn. A repeated public spending-key identifier may link accounts even if
   individual signatures are aggregated. Keep the spending secret and opener
   private throughout proving.
5. Measure proof generation, peak memory, witness/proof transport, aggregation
   latency, first-account deployment, subsequent spends, and total billed gas.
   Keep proposed protocol charges separate from measurements.

A new backend or account can change the CREATE2 deployment binding and hence
the destination address. Migration of already-funded accounts needs its own
analysis; a backend swap must not be described as automatically transparent.

## Review deliverable

Before claiming readiness, publish a reproducible fixture linking the existing
commitment vectors to the public inputs, proof, dependency, account validation,
and resulting transfer. Record the exact protocol revision, backend version,
hardware, and negative-case results. Keep the ERC submission package focused
on key exchange and address derivation while this integration is evaluated.
