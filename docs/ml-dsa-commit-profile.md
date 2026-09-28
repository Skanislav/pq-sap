# ML-DSA authorization under format 0x02 — the `ml-dsa-44-commit/v0` profile

Implementation record for D-026 (2026-09-22). Python defines the bytes
(`python/pq_stealth/profiles.py`); TypeScript mirrors them
(`js-client/src/profiles.ts`); the contracts under `js-client/contracts/src`
implement the account side. This is supporting implementation documentation:
the human-written [ERC draft](erc-draft.md) decides what, if anything, becomes
normative. Nothing here retires format `0x01`, allocates or reuses an ERC-5564
scheme ID, or establishes end-to-end post-quantum security of the protocol.

## 1. What an account profile is

The wire format is unchanged: `0x02 || spend_key(32) || kem_ek(1184)` =
1,217 bytes with ML-KEM-768. The 32-byte `spend_key` is opaque. Which spending
scheme, hash domains, chain, factory and account code interpret it is an
**account profile**, chosen explicitly by the application before a payment is
sent or scanned. A profile is never inferred from the commitment, guessed by
trial verification, or left until deployment.

Three identifiers, three roles:

| Identifier | Role | Changed by this work? |
| --- | --- | --- |
| Meta-address version byte `0x02` | Encoding of the published key material | No |
| ERC-5564 scheme ID | How an announcement is interpreted (KEM ciphertext as `ephemeralPubKey`, view tag in metadata) | No — no allocation, no reuse |
| Account profile (`profiles.py`, `profiles.ts`) | The selected authorization and deployment behaviour for a `spend_key` | New: typed, explicit, fail-closed |

A profile determines all of the following. The three implemented profiles:

| Input | `sphincs-c13-commit/v0` | `preimage/v0` | `ml-dsa-44-commit/v0` |
| --- | --- | --- | --- |
| Meta-address format | `0x02` | `0x02` | `0x02` |
| KEM | ML-KEM-768, existing encodings | same | same |
| `spend_key` | the raw 32-byte C13 key | `keccak256("pq-stealth/preimage/key/v0" ‖ sk)` | `keccak256("pq-stealth/ml-dsa-44/key/v0" ‖ pk)`, `pk` the canonical 1,312-byte FIPS 204 ML-DSA-44 public key |
| Authorization | C13 signature revealing the key | UltraHonk proof of `(sk, opener)` | pure ML-DSA-44 signature, empty context, over the 32-byte account digest; payload `pk ‖ opener ‖ sig` |
| `open_domain` | `pq-stealth/sphincs-c13/open/v0` | `pq-stealth/preimage/open/v0` | `pq-stealth/ml-dsa-44/open/v0` |
| `commit_domain` | `pq-stealth/sphincs-c13/commit/v0` | `pq-stealth/preimage/commit/v0` | `pq-stealth/ml-dsa-44/commit/v0` |
| Deployment binding | `Stealth8141ZkFactory(commitment, verifier, frameCtx)`, salt 0 | same | same shape, `verifier` = `MlDsa44CommitFrameVerifier` |
| Trust source | application-pinned / operator-supplied binding | same | same; plus the key registry's registrar (§4) |
| Spend route status | deployed (D-018, D-023) | deployed on the frames testnet (D-025) | local contract path only; nothing deployed |

Existing profiles keep their exact domain bytes and fixtures; the C13,
preimage and `0x01` tests pass unchanged. Renaming a domain would move funds.

**Trust boundary.** A profile name is a name. `select_profile` /
`selectProfile` accept only the three known profiles, require a positive chain
ID, validate the binding's shape (20-byte factory / verifier / frame context,
32-byte salt, non-empty creation code) and refuse to be used on another chain
(`for_chain` / `bindingForChain`). They do not — cannot — authenticate that the
factory, verifier or creation code are the intended ones. The application must
obtain the binding from a source it trusts. No negotiation or registry
mechanism is introduced; unknown profiles are rejected.

## 2. Derivation (exact bytes)

`‖` is byte concatenation; domain strings are UTF-8 (ASCII) without length
prefixes or terminators; Keccak-256 is Ethereum's, not SHA3-256.

```text
spend_key  = keccak256("pq-stealth/ml-dsa-44/key/v0" ‖ pk)              pk: 1,312 B
(ss, ct)   = ML-KEM-768.Encaps(kem_ek)                                    ct: 1,088 B
opener     = SHA-256("pq-stealth/ml-dsa-44/open/v0" ‖ ss)
commitment = keccak256("pq-stealth/ml-dsa-44/commit/v0" ‖ spend_key ‖ opener)
init_code  = creation_code ‖ commitment ‖ leftpad32(verifier) ‖ leftpad32(frame_ctx)
address    = keccak256(0xff ‖ factory ‖ salt ‖ keccak256(init_code))[12:32]
view_tag   = SHA-256(ss)[0:1]
```

`spend_key` is hashed once, by the recipient, from the canonical key bytes;
the outer commitment hashes that value together with the opener. The sender
needs only the meta-address, the trusted binding and its own KEM result. The
scanner needs the viewing secret, the public `spend_key` and the selected
profile — never the signing key — and accepts a payment only after re-deriving
the destination; a matching one-byte tag is a filter, not acceptance.

Why ML-DSA-44 and not ML-DSA-65: the only ML-DSA verifier in this repository
with an executable on-chain path is the vendored ZKNOX `ZKNOX_dilithium`
(ETHDILITHIUM rev `df999ed`, NIST/SHAKE profile), whose signature slicing and
matrix size are fixed at `k = l = 4` (D-006). An ML-DSA-65 profile needs its
own verifier, its own domains and its own name; this profile refuses 1,952-byte
keys and 3,309-byte signatures by length, and never labels the 44 verifier as
65. The scheme's Construction A default remains ML-DSA-65 and is untouched.

## 3. Authorization

A direct authorization payload is

```text
payload = pk(1312) ‖ opener(32) ‖ sig(2420)        = 3,764 bytes
```

The account/verifier (`MlDsa44CommitSigner7913`, and the reference
`verify_authorization` / `verifyAuthorization`) performs, in order:

1. exact-length parse for ML-DSA-44 (`key` 32 B, payload 3,764 B);
2. `spend_key = keccak256(KEY_DOMAIN ‖ pk)`;
3. recompute the outer commitment and compare it with the account's bound
   commitment (the ERC-7913 `key`);
4. verify `sig` under `pk` over the account's 32-byte operation digest;
5. leave nonce, replay, chain, destination, value and calldata binding to the
   account: they are what the digest commits to.

Message convention: **pure ML-DSA-44 (FIPS 204 Algorithm 2/3), empty context**,
message = the 32-byte digest, so `M' = 0x00 ‖ 0x00 ‖ digest`. This is exactly
what the vendored verifier's 3-argument `verify(bytes,bytes32,bytes)` hashes.
No HashML-DSA prehash mode, no external-mu mode, and the digest is not hashed
again anywhere. The digest is the account's: the EIP-8141 frame `sig_hash`
(chain, sponsor, nonce, frames) for `Stealth8141ZkAccount`, the ERC-4337
`userOpHash` for `Stealth7913Account4337`.

Anyone knowing the published `spend_key`, the shared secret and the opener
still needs the recipient's ML-DSA-44 signing key: the vectors and tests
exercise keys derived from `ss` and from the opener (they sign fine, but
`keccak256(KEY ‖ pk')` is not the published `spend_key`) and a signature from
another key over the recipient's `pk`.

## 4. On-chain integration and its honest status

| Contract | Role |
| --- | --- |
| `ZKNOX_dilithium` (vendored, `lib/ETHDILITHIUM` @ `df999ed`) | The real ML-DSA-44 verifier. Expanded-key form: reads `(aHat, tr, t1)` from a `PKContract` pointer |
| `TrustedMlDsa44KeyRegistry` (new) | Key setup: `keccak256(pk) → PKContract`. Recomputes `tr = SHAKE256(pk, 64)` and unpacks `t1` from the key bytes on chain; **trusts its registrar for `aHat = ExpandA(rho)`**. `register` binds once; registrar-only `replace` corrects a wrong binding (each binding is its own CREATE2 `PKContract`, salted by `pk` and `aHat`) |
| `MlDsa44CommitSigner7913` (new) | ERC-7913 verifier: `key` = commitment, `signature` = payload; steps 1–4 above. Uniform `0xffffffff` for a bad payload or an invalid signature; **reverts** with `VerifierCallFailed` if the inner verify does not complete (out of gas, malformed return) |
| `MlDsa44CommitFrameVerifier` (new) | `IProofVerifier` adapter so the unchanged `Stealth8141ZkAccount` / `Stealth8141ZkFactory` bind `(commitment, adapter, frameCtx)` |
| `Stealth7913Account` / `Stealth7913Account4337` (existing) | Hold `verifier ‖ commitment` (52 B) as OpenZeppelin `SignerERC7913` signer bytes; exercised through ERC-1271 |

**Verifier identity, established locally.** `ZKNOX_dilithium` at `df999ed`
accepts stock FIPS 204 ML-DSA-44 signatures: the fixture signature is produced
by `dilithium-py` 1.4.0 `ML_DSA_44.sign` (deterministic mode), reproduced byte
for byte by `@noble/post-quantum` 0.6.1 `ml_dsa44` in TypeScript, verified by
both libraries, and accepted on chain with `tr` and `t1` derived on chain from
the canonical key bytes (`forge test --match-contract MlDsa44CommitAccount`,
`npm run e2e-mldsa44`). D-006's "round-3 Dilithium2" wording therefore
describes the parameter set (identical to ML-DSA-44) and not a different
message or key format.

**What is blocked: trustless key setup.** The verifier needs `aHat =
ExpandA(rho)`, sixteen SHAKE128 polynomial expansions. With the vendored
Solidity Keccak-f, one SHAKE256 over the 1,312-byte key costs ≈ 4.4 M gas, so
a full expansion is ≈ 40 M gas — more than one transaction can do today and
far more than a per-spend budget. The registry therefore does **not** verify
`aHat`; a dishonest registrar could bind a matrix of its choosing to the
recipient's `pk` and then spend from every account committed to it. Anyone can
audit a registration off chain (`PKContract.getPublicKey().aHat ==
ExpandA(pk[0:32])`); nothing on chain does. Consequently:

* the contract path is a **local, reviewed-registrar integration**, not a
  working trustless spend route and not a deployment;
* the registrar's trust is **ongoing**: `replace` exists so that a registrar
  *mistake* does not strand funds (every account address pins the registry
  through the signer and adapter, so "deploy a new registry" is not a remedy
  for money already at a counterfactual address), which means a registrar
  compromised later can re-bind a key and spend. Both events are logged; a
  deployment that prefers immutability can retire the registrar address;
* removing the trust needs either a staged on-chain expansion (≈ 16
  transactions per recipient key), a cheaper SHAKE, or a verifier that takes
  the raw key — D-014's still-open "stateless raw-key verifier";
* no ML-DSA-44 verifier, registry, signer or factory of this profile is
  deployed anywhere; the vectors' binding is synthetic.

The counterfactual address binds the policy: the account's `verifier` is the
adapter, the adapter's signer is immutable, and a factory with any other
verifier — or the same factory with another commitment — yields a different
address (`testInitializationCannotSubstitutePolicy`). A fresh deployment cannot
set a different owner.

### Measured costs

Local only: forge 1.4.1 / anvil 1.4.1, solc 0.8.30, optimizer 10,000 runs,
`evm_version = prague`, ETHDILITHIUM `df999ed`. Nothing here is a mainnet or
testnet measurement, and nothing here says anything about ML-DSA-65.

| Step | Gas | Where measured |
| --- | --- | --- |
| Verifier deploy (`ZKNOX_dilithium`) | 3,176,477 | anvil, tx receipt |
| Registry / signer / adapter / factory deploy | 2,046,895 / 680,272 / 313,072 / 971,303 | anvil, tx receipts |
| Key setup, once per recipient key (`register`: SHAKE256 `tr` + `t1` unpack + `PKContract`) | 10,791,042 (tx) / 11,794,233 (internal) | anvil / forge |
| Account deploy (`createAccount`, no key material in initcode) | 704,195 | anvil, tx receipt |
| `MlDsa44CommitSigner7913.verify` (commitment check + ZKNOX verify) | 14,966,788 internal; 15,038,028 as a tx with 3,764 B calldata | forge / anvil |
| Complete spend (`executeFrame`: adapter + signer + verify + call) | 15,013,931 internal; 15,291,722 tx-level | forge / anvil |

The per-spend cost is the ZKNOX verify (D-022's 14.9 M) plus ≈ 60 k for the
commitment check and calldata. Because the signer reverts rather than
returning `0xffffffff` when the inner verify runs out of gas, `eth_estimateGas`
on `verify` reports the real cost (15,274,775 on anvil) instead of settling on
a cheap failure path; callers of wrappers that swallow reverts (OpenZeppelin
`ERC7913Utils`, `Stealth8141ZkAccount`) must budget that gas themselves. The previously circulated "Fireblocks 1.23 M"
figure is not used here: no primary source, commit, parameter set, hash
functions, key representation or reproducible benchmark for it was evaluated
in this work, so it is not evidence.

## 5. Privacy boundaries

Keep these apart; passing tests, distinct addresses and vector agreement are
not privacy proofs.

* **Receive time.** The announcement exposes the ciphertext, the tag and a
  CREATE2 address of a commitment; `spend_key` and the key stay hidden. The
  full-announcement composition argument for the commitment profile remains
  the open review item of [SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md).
* **Key disclosure at spend.** A direct ML-DSA spend reveals `pk`. Fresh openers
  give fresh commitments and addresses, but `keccak256(KEY ‖ pk)` is the
  recipient's published `spend_key`, so every spent address of one recipient
  is linkable to each other and to the meta-address from the first spend
  (`test_two_direct_spends_are_linkable`, the `linkage` block of the vectors).
  Direct verification does **not** preserve recipient anonymity after key
  disclosure. This is the same trade-off as the D-018 C13 commit signer.
* **Construction A retained `rho` — confirmed.** `derive_stealth_pk` returns
  `pack_pk(rho, t1')`, and `rho` is the same 32 bytes the recipient publishes in
  its `0x01` meta-address (`python/tests/test_construction_a_rho.py`). Blinding
  hides `t`, not `rho`. Announcements reveal only `keccak256(stealth_pk)[12:]`,
  so receive-time privacy is unaffected — but any route that reveals the full
  stealth public key exposes `rho` and with it the recipient: an ML-DSA
  signature verified against `stealth_pk` (ERC-7913 route, D-014), a deployed
  `PKContract` (its `aHat = ExpandA(rho)`), pointer-signature key tables, the
  `zknox_*_demo.json` fixtures. D-018's sentence "blinded ML-DSA has no such
  identifying event" holds only while no stealth public key is revealed; after
  disclosure Construction A spends are linkable by `rho`. No algebraic repair
  is attempted here (changing `rho` independently of the matrix, or a common
  seed, needs its own analysis).
* **Per-address key rotation is separate work.** Deriving the recipient's
  spending key from `ss` is unacceptable (the sender knows `ss`), and a sender
  cannot derive `H(pk_n)` from `H(pk_master)`; fresh recipient-controlled keys
  need an authenticated distribution or derivation protocol with its own
  privacy analysis.
* **Signing security.** Stock ML-DSA-44 EUF-CMA under FIPS 204; no widened or
  related-key signing is involved in this profile.
* **Proof-system soundness.** Not applicable to this profile. The D-025 browser
  demo (profile `preimage/v0`) proves knowledge of a spending secret and opener
  with UltraHonk, which is not post-quantum sound; it is a different route, not
  an ML-DSA-signature demo, and it is unchanged and still working.
* **Account safety.** Verifier immutability, rotation-by-self-call, entry-point
  gating and digest binding are the account's properties (`Stealth8141ZkAccount`
  unchanged) and the registrar trust of §4 sits on top.

## 6. Conformance

| Artifact | Command |
| --- | --- |
| Vectors `python/vectors/v0/mldsa44_commit_vectors.json` (profile, binding, two recipients, two payments, one cross-recipient miss, 2 valid + 12 invalid authorizations, linkage) | `python vectors/generate_mldsa44_commit_vectors.py` — byte-identical on regeneration (CI `cmp`) |
| Python tests (`tests/test_profiles.py`, `tests/test_construction_a_rho.py`) | `pytest -q` |
| TS replay + independent ML-DSA-44 verification | `npm run test:mldsa44` |
| Contract path (forge, fixture `python/scripts/mldsa44_commit_7913_demo.json`) | `forge test --root contracts --match-contract MlDsa44CommitAccount -vv` |
| Contract path (anvil, viem, cross-language CREATE2 over real creation code) | `npm run e2e-mldsa44` |

Receive/scan conformance (vectors, `check_with_profile`) is separate from the
optional spend-profile conformance (authorization vectors and contracts); an
implementation may claim the former without the latter.

## 7. Open items

* Trustless key setup or a raw-key ML-DSA-44 verifier (§4). Until then the
  registrar is a live trust assumption with a correction path, not a one-shot
  ceremony; a deployment must decide who holds that role and how it is retired.
* Gas-exhaustion semantics across the stack: the signer reverts, but the
  OpenZeppelin and frame-account wrappers convert any revert into "not
  authorized"; an integrator under a gas cap cannot tell the two apart at
  those layers.
* An ML-DSA-65 verifier and profile; nothing measured here transfers.
* ERC-4337 binding: `Stealth7913Account4337` accepts the same signer bytes, but
  its constructor layout differs from the `Deployment` record, so no
  cross-language address derivation is provided for it.
* Whether direct ML-DSA spending is offered in the ERC at all, given §5; the
  UI does not expose this route.
* Construction A's `rho` exposure: decide whether the `0x01` form is kept
  with the linkability stated, or reworked with a separate analysis.
