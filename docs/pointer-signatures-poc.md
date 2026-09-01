# POC: (v, r, s) as pointers — ABI-compatible PQ signatures

Prototype of the "re-interpret the 65-byte ECDSA tuple" hotfix (Circle, Aug 2026 PQ call).
Code: `docs/pointer-sig-poc/PointerSig.sol` (→ `ETHDILITHIUM/src/`), tests: `docs/pointer-sig-poc/PointerSig.t.sol` (→ `ETHDILITHIUM/test/`). `ETHDILITHIUM/` is a gitignored clone of ZKNoxHQ/ETHDILITHIUM; copy the two files in to run.

**Extended version (2026-08-27, CI-tested):** `js-client/contracts/src/PointerSig.sol` — the same registry adapted to the vendored ETHDILITHIUM `df999ed` (key entries are `PKContract` addresses, which is what its ERC-7913 `verify` takes) plus two SPHINCS- C13 versions, `v = 0x52` and `0x53`; `npm run e2e-pointer-sig`. See [SPHINCS- C13 variants](#sphincs--c13-variants-2026-08-27) below, and read [Where the value lives](#where-the-value-lives) first.

## Encoding

| field | classic | `v = 0x50` (pq) | `v = 0x51` (hybrid) |
|---|---|---|---|
| `v` | 27 / 28 | version | version |
| `r` | curve scalar | index into **key table** (ML-DSA pk) | index into key table (entry binds EOA + ML-DSA pk) |
| `s` | curve scalar | index into **signature table** | index of blob `abi.encode(ecdsaSig, pqSig)` |

`PointerSigRegistry.recover(digest, v, r, s) → address` is a drop-in for `ecrecover`.
Consumers keep their `(v, r, s)` ABI; `PointerSigVault.withdrawWithSig` is the example — one call site changed.

- Key table: `registerKey(expandedPk)` stores the ML-DSA-44 key via SSTORE2; the entry's address is `keccak256(pk)[12:]` (pure PQ) and `msg.sender` (hybrid binding).
- Signature table: `publishSignature(bytes)` — anyone can publish; a blob only has effect if it verifies against the digest at use time, so replay across digests fails (tested).
- Verification: ZKNOX `ZKNOX_ethdilithium.verify(pk, digest, sig)` (ERC-7913 interface, Dilithium2 / ETH-keccak profile).

## Measured (forge, default profile)

| op | gas |
|---|---|
| classic withdraw (unchanged path) | ~110k (whole test) |
| `publishSignature` (2420-byte ML-DSA sig, SSTORE2) | ~566k |
| `withdrawWithSig` pq (lookup + ML-DSA verify) | ~4.9M |
| hybrid (ECDSA + ML-DSA) | ~ same + ecrecover |

## Caveats this POC does not solve

- **Where the value lives (stated late — it was implicit in the demo's `depositFor`).** `recover` authorizes actions *inside contracts that call it*. The address a PQ branch returns (`keccak256(pk)[12:]`, or `keccak256(r)[12:]` below) is not an account: native ETH or tokens transferred to it directly are unspendable, because no EVM rule lets a hash-based or lattice key move them. The pq address is meaningful only as an owner key in pointer-aware contracts (this vault; a token whose permit/transfer-by-signature path adopted `recover`). Consequence for the stealth scheme: this is a **spend-authorization shim for value already held by adopting contracts**, not a stealth-receive mechanism — an ERC-5564 payment to a bare stealth address still needs that address to be a contract account (the CREATE2 ERC-7913 route, D-014/D-018). See [Where the value lives](#where-the-value-lives).
- Two transactions per PQ spend (publish sig, then use it) unless a relayer/4337 bundler batches them; the `s` index is predictable (`signatureCount()`) so batching is feasible.
- Table indices are global and monotonic; production would scope keys per account and allow inline signature blobs (e.g. `v=0x52`, `s` = calldata offset) to skip storage.
- Verifier is the level-2 Dilithium2 profile, not ML-DSA-65; ~22 kB key storage per registration.
- `v` values 0/1 (EIP-2098 yParity) are untouched; 0x50/0x51 are arbitrary POC constants.

## Run

```
cd ETHDILITHIUM && python3 -m venv pythonref/myenv && pythonref/myenv/bin/pip install -r pythonref/requirements.txt
forge test --match-contract PointerSigTest -vv
```

## Live run on anvil (real transactions)

Copy `docs/pointer-sig-poc/PointerSigDemo.s.sol` and `demo_anvil.sh` into `ETHDILITHIUM/script/`, then
`cd ETHDILITHIUM && bash script/demo_anvil.sh`. Boots anvil, broadcasts every step from anvil account #0, reads state back with `cast`.

Per-tx gas measured (anvil, solc 0.8.30, optimizer 10k runs):

| tx | gas |
|---|---|
| deploy `ZKNOX_ethdilithium` | 2,450,564 |
| deploy `PointerSigRegistry` | 988,104 |
| deploy `PointerSigVault` | 438,068 |
| `registerKey` (expanded ML-DSA-44 pk → SSTORE2, one-time per key) | 4,943,054 |
| `publishSignature` (2420 B ML-DSA sig → SSTORE2) | 625,420 |
| `withdrawWithSig` **pq** (`v=0x50`, r=0, s=0) | 4,943,553 |
| `withdrawWithSig` **classic** (`v=27/28`) | 67,518 |

Result: recipient balance 0.35 ETH (0.25 pq + 0.1 classic) through the same `withdrawWithSig(owner,to,amount,v,r,s)` entry point; `keyCount=1`, `signatureCount=1`.

## SPHINCS- C13 variants (2026-08-27)

A SPHINCS- C13 public key (D-018) is `pkSeed[0:16] || pkRoot[0:16]` — **exactly one word** — so the trick loses its worst part: `r` carries the key itself, there is no key table and no registration transaction. Home: `js-client/contracts/src/PointerSig.sol` (registry + vault, adapted to the vendored ETHDILITHIUM `df999ed`), test `js-client/test/e2e-pointer-sig.test.ts` (`npm run e2e-pointer-sig`, in CI), fixture `python/scripts/sphincs_c13_7913_demo.json` (`pointer` section: the two vault digests, signed with upstream's Rust signer against the deploy order the test pins).

| field | `v = 0x52` (SPHINCS-) | `v = 0x53` (SPHINCS-, committed) |
|---|---|---|
| `r` | **the C13 public key** (32 B) | `keccak256("pq-stealth/sphincs-c13/commit/v0" ‖ pk ‖ opener)` |
| `s` | index of the 3,688-B C13 signature in the signature table | index of the blob `pk(32) ‖ opener(32) ‖ c13sig` |
| address returned | `keccak256(r)[12:]` | `keccak256(r)[12:]` |
| who can compute the address | anyone with the key | **the stealth sender** — `pk` from the meta-address, `opener = SHA-256("…/open/v0" ‖ ss)` from the KEM shared secret |
| what a spend reveals | — | `pk` (opens the commitment): every spent address of the recipient becomes linkable to the recipient; unspent ones stay hidden (D-018) |

`0x53` is therefore a stealth address in plain address shape — no CREATE2 account, no initcode — *for value that lives in pointer-aware contracts* (next subsection). It composes unchanged with the hybrid binding idea, and both branches reuse the D-018 byte conventions (`js-client/src/sphincs.ts`).

### Where the value lives

This is the constraint the original POC left implicit (its demo already parks the ETH inside `PointerSigVault.depositFor(owner)`), and it decides what these branches are for. `registry.recover` only authorizes actions inside contracts that call it. `keccak256(r)[12:]` is not an account: ETH or tokens sent to it directly are stuck — no EVM rule lets a SPHINCS- (or ML-DSA) key move them, and nothing short of native post-quantum transaction signatures changes that. So:

- **Spend authorization for value already held by adopting contracts** — a vault, an ERC-20 whose `permit`/transfer-by-signature path swapped `ecrecover` for `recover`, an escrow: this is what pointer signatures do, and for C13 they do it at ~2× the classic cost (table below).
- **Stealth receive of arbitrary value** — an ERC-5564 payment to a bare stealth address: **not this.** The stealth address must be a contract account (the CREATE2 ERC-7913 route, D-014/D-018) for the recipient to be able to move whatever lands there. A stealth *payment into* a pointer-aware token/vault (`depositFor(keccak256(commitment)[12:])`) works, but that is a payment into a contract, and the announcer flow would have to be that.

### Measured (anvil, viem transactions, `e2e-pointer-sig`)

| tx | gas |
|---|---|
| deploy `PointerSigRegistry` (ML-DSA + C13 dispatch) | 1,319,404 |
| deploy `PointerSigVault` | 438,068 |
| `withdrawWithSig` **classic** (`v=27/28`) | 92,555 |
| `publishSignature` (3,688-B C13 sig → SSTORE2) | 898,534 |
| `withdrawWithSig` **0x52** (`r` = C13 key, no key table) | **182,799** |
| `publishSignature` (`pk ‖ opener ‖ sig`, 3,752 B) | 895,264 |
| `withdrawWithSig` **0x53** (`r` = commitment) | **183,237** |
| ML-DSA `PKContract` deploy (one-time per key) | 5,324,156 |
| ML-DSA `registerKey(pkContract)` (hashes the 22.4 kB key for the pq address) | 396,634 |
| `recover` **0x50** (ML-DSA, `df999ed` verifier) | ~15,186,908 (estimate) |

Relative to the same vault's classic withdraw: C13 costs **2.0×**; the ML-DSA branch on the vendored `df999ed` costs ~164× (its `verify` recomputes `NTT(t1·2^d)` per call, D-014). Publishing the C13 signature is the dominant one-time cost per spend (~0.9 M) — the same two-transaction shape as the original POC; the inline variant (`s` = calldata offset, consumer forwards `msg.data[s:]`) would remove it at the price of one consumer-side line.

Negative cases exercised: signature bound to its digest (replay for another amount, replay after the nonce advanced), commitment/opening mismatch, bare signature presented to the commit branch, wrong key word, bad index, unknown version, hybrid without its EOA half.
