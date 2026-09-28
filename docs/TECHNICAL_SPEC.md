# Key exchange and address derivation — technical reference

Current implementation reference following D-024/D-025, reviewed 2026-09-14.
Python defines byte-level behavior; this document describes it. The
human-written [ERC draft](erc-draft.md) determines the eventual normative
profiles and is not generated from these notes.

## 1. Scope

The proposal establishes a shared secret with ML-KEM-768 and uses it to derive
a recipient-detectable destination under existing ERC-5564 announcements.
Spending is delegated to an account model. The sender can compute the
address without knowing the spending secret; the viewing-key holder can scan
without that secret.

D-024 adopts the commitment format `0x02`. Construction A (`0x01`, blinded
ML-DSA) remains another implemented address form. Whether both belong in the
final ERC remains undecided. Its algebra, encodings, signatures, and historical
account measurements are in [Construction A](construction-a.md).

## 2. Commitment profile and sizes

Source: [Python commit module](../python/pq_stealth/commit.py), mirrored by
[TypeScript commit module](../js-client/src/commit-scheme.ts).

| Field | ML-KEM-768 size | Meaning |
| --- | --- | --- |
| Version | 1 byte | `0x02`; distinct from the target ERC-5564 scheme ID `2` |
| `spend_key` | 32 bytes | Public spending-key value or commitment, interpreted by the account profile |
| `kem_ek` | 1,184 bytes | ML-KEM encapsulation key |
| Meta-address | 1,217 bytes | `0x02 || spend_key || kem_ek` |
| `ephemeralPubKey` | 1,088 bytes | ML-KEM ciphertext |
| View tag | 1 byte | `SHA-256(ss)[0:1]` |
| Stealth address | 20 bytes | Derived from the selected account deployment binding |

The format omits ML-DSA public-key material; it still contains a lattice KEM
key. Python also exposes other ML-KEM parameter sets for experiments. The
reference profile here is ML-KEM-768; format `0x02` does not itself encode
the KEM choice, hash domains, chain, or account deployment configuration.
Those inputs must be agreed separately; their distribution/profile selection
is an ERC review item, not a solved negotiation mechanism.

Since D-027 the implementation makes that selection explicit: an **account
profile** (`python/pq_stealth/profiles.py`, `js-client/src/profiles.ts`) names
the KEM, the hash domains, the authorization scheme with its message
convention, and the deployment-binding layout, and `select_profile` /
`selectProfile` accept only the known profiles and a shape-validated binding
for one chain. Three identifiers keep distinct roles: the version byte `0x02`
describes the encoding, the ERC-5564 scheme ID describes announcement
interpretation, and the profile describes the selected authorization and
deployment behaviour. A profile name is trusted configuration, not
authentication of the factory or verifier behind it. Details:
[ML-DSA-44 committed-key profile](ml-dsa-commit-profile.md).

## 3. Implemented receive and scan flow

```text
Recipient: create ML-KEM viewing keys (ek, dk)
           publish 0x02 || spend_key || ek
Sender:    encapsulate ek -> shared secret ss and ciphertext ct
           opener = SHA-256(open_domain || ss)
           commitment = keccak256(commit_domain || spend_key || opener)
           address = account_address(commitment, deployment)
           view_tag = SHA-256(ss)[0:1]
           use ct as ephemeralPubKey and view_tag as metadata[0]
Scanner:   decapsulate ct using dk
           reject tag mismatch; otherwise re-derive commitment and address
           return payment only when the address also matches
```

The sender knows `ss` and the opener. Authorization must therefore require
an additional recipient-only spending secret. The view-tag optimization runs
**after decapsulation** and saves further derivation on mismatches; matching a
tag alone is not detection of a payment.

The Python scan returns `None` on the handled malformed-ciphertext errors,
a wrong tag, or an address mismatch. Decode rejects a wrong version or length.
These checks do not authenticate the sender, establish log completeness, or
make externally supplied account configuration trustworthy.

## 4. Domains and deployment binding

| Profile | `open_domain` | `commit_domain` |
| --- | --- | --- |
| C13 commitment (`sphincs-c13-commit/v0`) | `pq-stealth/sphincs-c13/open/v0` | `pq-stealth/sphincs-c13/commit/v0` |
| Preimage demo (`preimage/v0`) | `pq-stealth/preimage/open/v0` | `pq-stealth/preimage/commit/v0` |
| ML-DSA-44 committed key (`ml-dsa-44-commit/v0`) | `pq-stealth/ml-dsa-44/open/v0` | `pq-stealth/ml-dsa-44/commit/v0` |

For the preimage demo, `spend_key = keccak256("pq-stealth/preimage/key/v0" || sk)`
with a 32-byte secret. The C13 profile uses its 32-byte public key directly.
For the ML-DSA-44 profile, `spend_key = keccak256("pq-stealth/ml-dsa-44/key/v0" || pk)`
with `pk` the canonical 1,312-byte FIPS 204 ML-DSA-44 public key (hashed once;
the outer commitment hashes that value with the opener). The parameter set is
part of the profile and of the domain strings; ML-DSA-65 would be a different
profile with a different verifier.
The existing names are byte-level inputs; changing them changes destinations.
Ethereum Keccak-256 is not SHA3-256.

The implemented deployment record supplies a 20-byte factory, account creation
code, 20-byte verifier, 20-byte frame-context address, and 32-byte salt (default
zero). Constructor arguments are encoded as three 32-byte words:

```text
init_code = creation_code || commitment || leftpad32(verifier) || leftpad32(frame_ctx)
address = keccak256(0xff || factory || salt || keccak256(init_code))[12:32]
```

This describes the current account adapter, not a universal account interface.
Changing the deployment binding may change the address. Vectors use synthetic
creation code to test deterministic derivation; they do not establish that an
account is deployable or that its authorization policy is secure.

## 5. Conformance and security evidence

[Commitment vectors](../python/vectors/v0/commit_vectors.json) cover the C13
and preimage domain profiles. Their generator is
[generate_commit_vectors.py](../python/vectors/generate_commit_vectors.py).
Python tests cover encoding, derivation, scanning, and fixtures; TypeScript
replays the commitment vectors with `npm run test:commit`. `npm test` is the
separate Construction A vector test.

The [ERC evidence map](ERC_EVIDENCE.md) separates conformance, relevant Lean
results, unproved composition, and optional spending research. In particular,
no end-to-end Lean privacy theorem for this concrete commitment/CREATE2 profile
is claimed. Read the [security overview](SECURITY_ANALYSIS.md) before deriving
security conclusions from a successful roundtrip.

## 6. Account integrations

D-025's browser demo proves knowledge of a spending secret and opener with
UltraHonk. Its current proof backend is not PQ-sound. C13, blinded ML-DSA,
and other account routes are supporting experiments with distinct assumptions.
The direct ML-DSA-44 committed-key route (D-027) has a reference verifier in
both languages and a local contract path over the vendored ZKNOX ML-DSA-44
verifier; its on-chain key setup relies on a trusted registrar, nothing is
deployed, and a spend reveals the key and links that recipient's spent
addresses. Construction A's revealed stealth key exposes the recipient's `rho`
(D-027). See the [profile record](ml-dsa-commit-profile.md).
The [spending research guide](SPENDING_RESEARCH.md) records those boundaries.
They do not require changing the KEM announcement format, but they have their
own deployment and network requirements.
