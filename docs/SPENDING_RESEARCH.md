# Spending and account research

These implementations explore how a detected destination can authorize a
transfer. They support the project's feasibility story but are separate from
the key-exchange ERC's core receive/scan evidence. Start with
[ERC evidence](ERC_EVIDENCE.md) for that scope.

| Track | Implementation and records | Security and deployment boundary |
| --- | --- | --- |
| Construction A | [Derivation/signing reference](construction-a.md), [security analysis](construction-a-security.md), Python blinded signer | Format `0x01`; stock signature-format compatibility does not complete related-key signature security |
| ERC-4337/7913 accounts | [TS client and E2E commands](../js-client/README.md), vendored ZKNOX verifier | Verifier profiles and account address rules differ; raw ML-DSA-key hashes are not ECDSA EOAs |
| Direct SPHINCS-C13 | D-018 in [decisions](DECISIONS.md), C13 verifier and committed signer | Recipient key revealed at spend time; spend-time linkability remains |
| C13 signature in ZK | [D-023 experiment](research/zk-sphincs-frames.md), `noir/sphincs-c13-verify` | Hidden-key statement with a non-PQ-sound UltraHonk backend; recorded costs are specific to that testnet/toolchain |
| Browser preimage ownership | D-025, `noir/preimage-ownership`, `ui/src/lib/preimage-prover.ts` | Proves knowledge of secret and opener; current backend is not PQ-sound; account/message binding needs separate review |
| MLWE ownership circuit | [Noir research notes](../noir/README.md), `noir/pq-stealth-ownership` | Separate lattice-relation PoC; not the current browser proof or a prerequisite for the ERC |
| Future aggregation/native keys | [EIP-8288 assessment](research/eip-8288-summary.md), [deployment experiments](research/prefix-deploy-native-keys.md) | Prospective integrations; proposed dependency charges are not measured total spend costs |
| Classical spending hybrid | [Hybrid notes](classical-spend-hybrid.md) | ML-KEM discovery with ECDSA authorization; spending is not post-quantum |

## Proof-reading path for spending specialists

For Construction A, read its derivation reference and security analysis, then
`Blinding`/`Invariants` → `Ownership` → `WidenedSigning` → `SpendSecurity` →
`ConstructionASecurity`. The related-key bound concerns short ownership
witnesses. The Fiat-Shamir-with-aborts signature composition remains open;
the widened HVZK distance is currently the trivial `1`.

For the commitment demo, inspect the preimage circuit and account authorization
instead. Construction A's signing proofs do not verify this circuit, backend,
or account. The sender knows the opener; proving only opener knowledge would
not establish recipient authorization.

## Evidence to report for any route

Record the precise key/profile and authorization statement, message and replay
binding, who learns the key or witness, account/factory/verifier dependencies,
and the proof backend's assumptions. Report hardware and toolchain alongside
proving time and memory. Separate registration, announcement, account creation,
verification, transfer, and total billed gas; distinguish initial and later
spends. Existing measurements remain in their dated experiment notes.

Narrowing the ERC scope leaves these research questions intact. It removes
them from the key-exchange reading path; it does not make a deployed account
secure by assumption or promise a transparent migration for funded accounts.
