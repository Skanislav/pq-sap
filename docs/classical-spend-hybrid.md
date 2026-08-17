# Classical-spend hybrid (secp256k1 + ML-KEM)

*Authors: [@ivanmmurciaua](https://github.com/ivanmmurciaua), Claude (Opus 5).*

An alternative construction in the same family as the ML-DSA scheme, offered as a complementary point in the design space, not a replacement.

Same rail: ML-KEM key exchange, the same additive-blinding idea, the same view-tag, the same `Announcement`, the same ERC-6538 registry. The only thing that changes is **what gets blinded**: a secp256k1 spending key instead of an ML-DSA one.

## Idea in one line

Blind a secp256k1 key with a tweak derived from the ML-KEM shared secret. The stealth address is a normal EOA, so **spending is a plain ECDSA transaction, deployable today**: no protocol-level PQ signature support, no ERC-4337, no ZK circuit.

Confidentiality is already post-quantum: linking a stealth address to its recipient means breaking ML-KEM, not ECDH.

This is exactly the DKSAP baseline that `benchmarks/scan_bench.py` measures (`ss = v·R`, then `P = K + H(ss)·G`), with the classical ECDH key exchange replaced by ML-KEM encapsulation. Nothing else moves.

## Where it sits

Both schemes derive a per-payment tweak from an ML-KEM shared secret and add it to the recipient's published key. They differ only in the group the spending key lives in:

| | ML-DSA scheme | Classical-spend hybrid |
|---|---|---|
| Spending key | ML-DSA, blinded `t' = A·s' + e' + t` | secp256k1, blinded `P = K + t·G` |
| Stealth address | `keccak(ML-DSA pk)[12:]` | `keccak(uncompressed pubkey)[12:]` (EOA) |
| ERC-7913 signer | `verifier \|\| key` pointer (over 20 B) | 20-byte address, empty key (`ecrecover` base case) |
| Key exchange / view key | ML-KEM | ML-KEM (identical) |
| View tag | `sha256(ss)[:n]` | `sha256(ss)[:n]` (identical) |
| Signature / spend | ML-DSA (FIPS 204) | ECDSA (secp256k1) |
| **Spendable on-chain today** | No (needs protocol PQ signatures) | **Yes** (plain tx) |
| Quantum posture | Fully PQ (spend included) | PQ confidentiality; classical spend |

The ML-DSA scheme is the destination: a fully post-quantum stealth output.

The classical-spend hybrid is the bridge you can deploy while that destination waits on protocol-level PQ signatures (EIP-8141). They share a recipient's ML-KEM viewing key, so a wallet can publish both under one registry and let the sender pick.

## Construction

Recipient keys:

- **spending key** `(k, K = k·G)`: a normal secp256k1 keypair.
- **viewing key** `(kem_dk, kem_ek)`: an ML-KEM keypair, identical in role to the ML-DSA scheme's viewing key.

Meta-address (versioned, same shape as the ML-DSA scheme, smaller because there is no lattice `t` to carry):

```
meta_address = version(1) || spend_pub(33, compressed) || kem_ek
```

Send (public inputs only):

1. `ss, R = ML-KEM.encaps(kem_ek)`: shared secret and ciphertext.
2. `t = KDF(ss) mod n`: the tweak scalar (`n` = secp256k1 group order; the mapping avoids `0`, see `classical/blinding.py`).
3. `P = K + t·G`: the one-time stealth public key.
4. address `= keccak(uncompressed(P)[1:])[12:]`, view tag `= sha256(ss)[0]`.
5. announce `(address, R, view_tag)`: the same `Announcement` as the ML-DSA scheme.

Scan (viewing key only):

1. `ss = ML-KEM.decaps(kem_dk, R)`; discard on the view-tag miss.
2. recompute `P`, `address`; keep on match.

Spend (spending key only):

- `p = (k + t) mod n` is the private key for the stealth EOA. Because `p·G = k·G + t·G = K + t·G = P`, a standard ECDSA signature from `p` controls the address. No new machinery.

## What it gives up, what it keeps

| Property | Classical-spend hybrid |
|---|---|
| Confidentiality (unlinkability) | **Post-quantum**, rests on ML-KEM |
| Holding funds at rest | Only an address hash is on-chain; no long-lived key exposure |
| Spending | Classical secp256k1 ECDSA, short exposure at spend time only |
| Harvest-now-decrypt-later on *who paid whom* | Resisted (the link is an ML-KEM ciphertext) |
| A future quantum adversary forging a *spend* | Not resisted: the spend is classical, deferred to EIP-8141 |

The trade is deliberate: give up post-quantum resistance on the spend signature (a short, one-time exposure that EIP-8141 upgrades later) to gain same-day deployability with unmodified wallets and no on-chain verifier.

## On-chain distribution: the same registry, no off-chain channel

The hybrid uses the ERC-6538 registry the ML-DSA scheme already targets (`MetaPublic`: "published ... via ERC-6538 registry or ENS"). The registry maps `(registrant, schemeId) -> bytes` and is agnostic to the blob's schema, so:

- The ML-DSA scheme registers under its `schemeId`.
- The hybrid registers under **a distinct `schemeId`, in the same canonical registry, with no new contract**.
- Both coexist; the sender reads by `schemeId`. No off-chain meta-address sharing on either path.

The same registry deployment serves every scheme on every network: the reuse is free.

For the **announcement**, the hybrid rides the same rail: the ERC-5564-style `Announcement` (`stealth_address`, `ephemeral_pub_key = R`, `view_tag`). An announcer-less variant that carries the announcement blob in the payment transaction's calldata is possible and removes the dedicated announcer, at the cost of a chain-wide calldata scan; it is a deployment choice, not a change to the scheme, and is out of scope for the reference here.

## A linkability corner that does not exist here

The ML-DSA scheme adds a fresh error term `e'` per stealth key, on purpose: reusing the recipient's `s2` across stealth keys (as in pq-sap v2) leaks a linkability signal, so `derive_blinding` derives `(s', e')` together to close it.

The hybrid has no error term to reuse. The tweak is a single scalar `t = KDF(ss) mod n`, each `ss` fresh per payment, and `P = K + t·G` is a uniform point given `t`. The `s2`-reuse vector simply is not present, not because it was patched, but because the classical group has nothing analogous. Simpler by construction, not by cutting a corner.

## ERC-7913 compatibility: the same account, the 20-byte case

The stealth identity does not have to be a bare EOA. ERC-7913 represents a signer as `verifier || key`, and OpenZeppelin's `SignatureChecker.isValidSignatureNow(bytes signer, ...)` resolves it by length: fewer than 20 bytes fails, exactly 20 bytes falls back to `ecrecover` (or ERC-1271), and more than 20 bytes dispatches to the verifier contract. There is no separate secp256k1 verifier in that set (only P256, RSA, WebAuthn), precisely because a secp256k1 key is the 20-byte, empty-key base case handled by the `ecrecover` fallback.

That is exactly where this scheme lands. The blinded stealth key is a plain secp256k1 key, so its ERC-7913 signer is the 20-byte stealth address with an empty key, and a spend is a plain ECDSA signature over the 32-byte hash the account validates. The same account harness the ML-DSA scheme drives (an OpenZeppelin `SignerERC7913` account, `Stealth7913Account` in the ML-DSA scheme's `TECHNICAL_SPEC.md` section 7 and `DECISIONS.md` D-014) accepts this scheme with no change: the hybrid is the 20-byte leaf, the ML-DSA scheme is the longer `verifier || pointer` leaf, and both resolve to the same counterfactual CREATE2 account address derived from the signer. One account model, one identity rule, two signer forms.

This is what makes the migration in place rather than a re-anchor. An account can start life with the 20-byte secp256k1 signer, spendable today through `ecrecover` at ecrecover cost, and later swap in a post-quantum verifier signer without changing the account model or the way its address is derived. The hybrid is not a detour off the ERC-7913 path: it is that path's base case.

The bare-EOA form in the Construction section stays the minimal reference (spend with no contract at all). The `SignerERC7913` account is the form that shares an identity rule with the ML-DSA scheme and migrates in place, at the cost of an account deployment per stealth output. The on-chain demonstration of this route lives alongside the reference, mirroring the ML-DSA scheme's own ERC-7913 test.

## Upgrade path

The recipient's ML-KEM viewing key is shared between both schemes. When protocol-level PQ signatures land (EIP-8141), or sooner through the ERC-7913 account above, a wallet can move new payments to the ML-DSA scheme without rotating its viewing identity, and sweep any hybrid funds with a final classical spend. The hybrid is the interim; the ML-DSA scheme is where it goes.

## Status

Reference implementation, unaudited, for research and discussion. The spend flow is real and exercised end-to-end (secp256k1 via `coincurve`); the ML-KEM half reuses the same `kyber-py` backend as the ML-DSA scheme.
