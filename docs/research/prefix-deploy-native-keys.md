# ML-DSA spend without an EVM verifier: pre-frame deploy, native keys, pointer signatures

*2026-09-02. Companion artifacts: `python/pq_stealth/native_key.py` +
`js-client/src/native-key.ts` (EIP-8164 crafted-authorization address
derivation, cross-checked by `python/vectors/v0/native_key.json`),
`js-client/contracts/src/ntt/` + `contracts/test/NttPrecompute.t.sol`
(key-setup NTT spike) and `contracts/test/DilithiumProfile.t.sol` (where the
verify gas goes). Decision record: D-022. Extends D-020 (frame transactions)
and the pointer-signature PoC (`docs/pointer-signatures-poc.md`).*

## 1. Questions

1. Can the deployless `eth_call` trick — bytecode passed along with the call
   instead of being deployed (viem `deployless`, Multicall3-in-constructor,
   `eth_call` state-override `code`) — help ML-DSA verification?
2. Precompiles are not the way forward; what are the ways around, and can the
   verification be split?
3. What does "deploy the account in the EIP-8141 pre-frame" buy, combined with
   the Circle proposal "Proposed PQ upgrade for ecrecover" (ethresear.ch 25844,
   2026-08-28)?

Everything below is checked against the live EIP texts (8141, 8164, 7819, 7932,
7997) and the thread as of 2026-09-02, and against measurements in this repo.

## 2. The deployless trick does not touch the cost that matters

The trick is a *simulation* feature: `eth_call` with `to = null` runs initcode
and returns what the constructor returns as if it were runtime code, and state
overrides are a node-side option of `eth_call` / `eth_simulateV1`. Neither
exists in a mined transaction. The on-chain analogue — run the verifier inside
initcode and `REVERT`/`RETURN` the result so no code is deposited — removes the
code deposit and nothing else: the same opcodes still execute.

EIP-8141 closes the remaining doors:

- a frame with `target = null` resolves to `tx.sender`; there is **no CREATE
  frame** and explicitly **no access list**. Bytecode can only enter a frame as
  `data` handed to a factory or to the account;
- the account's verify runs through a `staticcall` into the ERC-7913 verifier
  (`Stealth8141Account.sol:55-60`), so it cannot `CREATE` an initcode-verifier;
- transient storage is **wiped between frames** ("Discard the `TSTORE` and
  `TLOAD` transient storage between frames"), so intermediates cannot be
  carried across frames except through persistent `SSTORE`, which costs more
  than recomputing any ML-DSA intermediate;
- the EIP-7825 cap applies to the **sum** of frame execution gas
  (`TX_MAX_GAS_LIMIT = 2^24 = 16,777,216`), so splitting one verify over
  several frames buys no headroom.

What it *does* buy, marginally: (a) running a verifier on a chain where nobody
deployed one, at ≈ 14.5 KB × calldata price (EIP-7623/7976 floor) ≈ 0.6–0.9 M
per spend instead of a one-time deploy; (b) carrying the 22.4 KB expanded pk in
frame data instead of a `PKContract` (≈ 0.9–1.3 M per spend vs 5.3 M once —
break-even after four or five spends, so no for a long-lived account);
(c) client-side pre-flight of a sponsored PQ spend via `eth_simulateV1` on a
chain where the verifier is not yet deployed. None of these is a cost lever for
the reference route.

## 3. Where the ML-DSA verify gas actually goes

Measured on the blinded level-2 fixture `python/scripts/zknox_7913_demo.json`
through the vendored ZKNOX `df999ed` verifier (NIST/SHAKE profile), forge,
optimizer 10k runs, prague (identical under cancun):

| step (`DilithiumProfile.t.sol`) | gas | share |
|---|---|---|
| 0 slice the 2,420-B signature into `cTilde/z/h` (memory copies) | 589,835 | 4 % |
| 1 `dilithiumCore1` — unpack `z`, `h`, norm checks | 1,394,684 | 10 % |
| 2 `sampleInBallNist` — **SHAKE256** in Solidity | 936,507 | 7 % |
| 3 `nttFw(c)` | 258,376 | 2 % |
| 4 expand + `<< d` + `nttFw(t1)` × 4 — **key-dependent only** | 1,405,488 | 10 % |
| 5 `dilithiumCore2` — `expandMat`, NTT(z) × 4, `A·z − c·t1`, invNTT × 4, hints, w1 encode | 5,692,486 | 40 % |
| 6 final **SHAKE256** — `mu = H(tr ‖ M')`, then `c̃ = H(mu ‖ w1Encode)` | 4,046,294 | 28 % |
| sum (in-memory) | 14,323,670 | |
| ERC-7913 `verify` via `PKContract` (call overhead, SSTORE2 read + `abi.decode` = 217,756) | 14,911,249 | |

Two corrections to earlier notes:

- **The "1.8× regression is exactly the per-verify `NTT(t1·2^d)`" explanation
  in D-014 / `TECHNICAL_SPEC.md §7` was an inference, not a measurement, and it
  is wrong.** The key-dependent step is 1.4 M (10 %). Moving it to key setup
  (`PKContractNtt` + `ZKNOX_dilithium_ntt`, `NttPrecompute.t.sol`) takes the
  ERC-7913 verify from **14,911,249 to 13,678,091** (−8 %) and raises the
  one-time `PKContract` deploy from 5,145,320 to 7,310,211. The upstream README's
  own 13.5 M for `Dilithium` at this revision agrees with the precomputed
  figure; the 8,176,453 in `TECHNICAL_SPEC.md §7` was measured on an earlier
  upstream revision with a different key path and is not reproducible at
  `df999ed`.
- **SHAKE256 in the EVM is the largest single cost: ≈ 5.0 M of 14.9 M (34 %).**
  That is the whole difference to `ZKNOX_ethdilithium` (4.9 M): the keccak-PRNG
  profile replaces every SHAKE call by the `KECCAK256` opcode. It is also the
  one lever that leaves FIPS 204 (D-015's "standard hashes everywhere" is
  satisfied by keccak, the *scheme* is what stops being ML-DSA).

## 4. Ways around, ranked

1. **Key-setup NTT** (this spike): −1.2 M per spend, exact, FIPS-compatible.
   Cheap to keep; not a game changer.
2. **Keccak-XOF profile** (`ZKNOX_ethdilithium`, 4.9 M): −10 M per spend, but
   the derived stealth keys are no longer ML-DSA keys (ExpandA/ExpandS/SampleInBall
   change), so every FIPS 204 verifier and every future native scheme stops
   accepting them. Record as a named option only.
3. **Split across frames / transactions**: no. Frames share the 2^24 cap and lose
   transient storage; a cross-transaction split would have to persist
   intermediates (4 polynomials ≈ 3 KB ≈ 100 slots ≈ 2 M state gas plus a
   binding hash) — more than the compute it saves — and only matters when a
   single verify exceeds the cap, which 13.7 M does not.
4. **Optimistic verify** (claim → challenge window → finalize): moves the
   13.7 M off the happy path at the price of latency and a watcher assumption
   on the account's own funds. An option for the ERC draft's Future section,
   not for the reference route.
5. **Proof-based** (Groth16/STARK of the verify, EIP-8288 aggregation): the
   durable EVM-side fix, already cited in `TECHNICAL_SPEC.md §7b`; EIP-8288 is
   still a stub.
6. **Protocol-native validation** (§6): the only shape that makes the EVM
   verify disappear.

## 5. Deploy in the EIP-8141 validation prefix — designator only

What the spec allows in the prefix: the `deploy` frame must be the first frame,
DEFAULT mode, targeting a factory; afterwards non-empty code must exist at
`tx.sender`; the only writes allowed are `CREATE`/`CREATE2`/`SETDELEGATE`
installing code at `tx.sender` and `SSTORE` to `tx.sender`; the budget across
the whole prefix is `MAX_VERIFY_GAS = 100,000` execution and
`MAX_VERIFY_STATE_GAS = 500,000` state.

| deploy shape | exec | state | fits prefix? |
|---|---|---|---|
| SPHINCS- account, 3.4 KB code, measured in-frame on the frames testnet | 63 k | ≈ 5.7 M | no (state 11×) |
| ML-DSA `Stealth8141Account` type-2 deploy on the frames testnet | ≈ 43 M total | — | no |
| `SETDELEGATE` (EIP-7819) designator, 23 B, + 1 `SSTORE` (key pointer) | ≈ 30 k | ≪ 500 k | **yes** |

So a pre-frame deploy works as a **delegation designator to a shared account
implementation**, with the per-account key pointer in the sender's own storage.
The stealth address becomes the EIP-7819 address
`keccak(DESIGNATOR ‖ factory ‖ salt)[12:]` with `salt = H(signer)` — still
counterfactual, still sender-computable. EIP-7819 is Draft but is referenced by
the 8141 text. What it does **not** fix: `self_verify` in the prefix (13.7 M and
even C13's 188 k exceed 100 k), so the prefix stays `[deploy, sponsor VERIFY]`
and the PQ verify remains a post-prefix DEFAULT frame (today's
`Stealth8141Account.executeFrame`). Net effect on the current route: the 43 M
account deploy disappears; the `PKContract` (code deposit → state gas, outside
the 7825 cap) can be created through the EIP-7997 factory in a post-prefix frame
of the same transaction ahead of the verify frame (exec sum ≈ 0.5 M + 13.7 M
< 16.78 M, tight). Sponsorship remains mandatory.

## 6. EIP-8164 native keys — the ecrecover post's binding, and a second address form

Facts (EIP-8164 "Native Key Delegation for EOAs", Draft 2026-02-17,
Markou/Prestwich; no client implementation found, on no devnet):

- account code becomes `0xef0101 ‖ pk` (ML-DSA-44 only, 1,315 B; `0xef0102…`
  reserved, FN-DSA named as the next candidate). ECDSA is **permanently**
  rejected for the account afterwards — which is the thread's main objection
  (TMerlini: the classical path must be retired) answered;
- installed from a `native_key_authorization_list` tuple
  `[chain_id, pubkey, nonce, y_parity, r, s]` with
  `msg_hash = keccak256(0x07 ‖ rlp([chain_id, pubkey, nonce]))`; **any party may
  include it**; tuples are skipped, not reverted, on failure (7702 semantics);
  delegation bumps the authority nonce; costs `PER_NATIVE_AUTH_BASE_COST =
  12,500` + `PER_EMPTY_ACCOUNT_COST = 25,000`;
- transactions from the account carry the 2,420-B ML-DSA-44 signature and are
  validated by the client at admission for `ML_DSA_44_VERIFY_COST = 50,000`
  intrinsic gas. **Not an EVM precompile** — the same category as secp256k1
  transaction validation. Whether that passes the "no precompiles" bar is a
  user decision (D-022 records the question, not an answer);
- **crafted-signature keyless accounts are spec'd**: `r_seed =
  keccak256("nkd-v1" ‖ chain_id ‖ pk)`, `r` = smallest valid secp256k1
  x-coordinate ≥ `r_seed mod p`, `s = 1`; the account is "provably rootless"
  (ECDLP), with the explicit warning that the recovered ECDSA public key is
  quantum-exposed until the delegation lands;
- native-key accounts execute no code and cannot use 7702 delegation or
  `APPROVE`; the draft defines its **own type `0x06`** envelope (a number clash
  with 8141 — draft artefact; an EIP-7932 update is said to reconcile
  7932/8141/8164, unverified).

Mapping onto the stealth scheme (Construction A is parameter-set generic;
`ML-KEM-512+ML-DSA-44` is already in `python/pq_stealth/params.py`):

1. The sender derives the blinded ML-DSA-44 stealth pk exactly as today, then
   the **stealth address = ecrecover(msg_hash(chain_id, pk, 0), y = 0,
   r_crafted, s = 1)**. No factory, no initcode, no code hash in the
   meta-address. The recipient recomputes it from the shared secret.
   `native_key.py` / `native-key.ts` implement this; the vector file pins the
   encoding choices the draft leaves open (chain_id as 32-byte big-endian in
   `r_seed`, `y_parity = 0`, `r < n`).
2. The sender's payment transaction **carries the authorization tuple itself**.
   Funds and the `0xef0101 ‖ pk` code land in the same transaction, so ECDSA is
   dead from the first block the address holds value — quantum-safe at rest,
   unlike any keyless-ECDSA address that waits for its owner. Sender pays
   ≈ 37.5 k plus the designator storage.
3. The recipient's spend is a plain native-key transaction: 50 k verify, **no
   sponsor, no `PKContract`, no verifier contract, no `MAX_VERIFY_GAS`
   problem**. The 13.7 M EVM verify disappears.

Caveats:

- pre-quantum safe in flight only: with a CRQC an observer could recover the
  crafted address's ECDSA key from the mempool and front-run a competing
  authorization (nonce 0); the sender's tuple is then skipped and the funds go
  to an attacker-keyed account. Mitigations: private/builder inclusion; if 8164
  folds into 8141 frames, an atomic DEFAULT frame that asserts
  `EXTCODEHASH(stealth) == keccak(0xef0101 ‖ pk)` and reverts the payment
  otherwise. Pre-CRQC this is moot;
- parameter set: ML-DSA-44 (Level 1) versus the scheme's ML-DSA-65 default;
- fingerprint: every stealth address carries native-key code, so the anonymity
  set is "all EIP-8164 accounts", not "all EOAs". The pk in code is the blinded
  stealth key, unlinkable to the master key (Construction A), the same key a
  spend reveals today — but revealed at receive time;
- no smart-account features (batching, paymaster) on such accounts as drafted.

## 7. The ecrecover pointer proposal itself

Sentinel `v = 27, s = 0`, `r = 0x00 ‖ sigIndex(11 B) ‖ verifierId(20 B)`,
signature bytes read from the EIP-8141 signatures array (`pk ‖ sig`), binding
via 8164 / 7932 / 8130, returns the claimed address. It is a **contract-consumer
ABI hotfix** (permit, vaults, `ecrecover` call sites); it does not move value
at a bare address — that still needs §6 or a contract account
("Where the value lives", `docs/pointer-signatures-poc.md`). So it is
complementary to §6, not an alternative. `PointerSig.sol` already implements the
contract-shim version with a different encoding (`v = 0x50/0x51`, table
indices); re-encoding it to the post's form with the signature fetched through
`FrameTxContext` (SIGPARAM/SIGDATACOPY) would make it a faithful shim of the
proposed precompile semantics on the frames testnet. Thread status (2026-09-02):
TMerlini (retire ECDSA — 8164 does), 71104 (new opcode instead), matt (prefers
EIP-8151 account-code-restricted ecrecover), Helkomine (DoS).

## 8. Recommendation

- **Tracked target: §6 + §7** — native key for value at the address, pointer
  signatures for contract authorizations. It is the only shape where the PQ
  spend costs tens of thousands of gas and needs no sponsor, and it removes the
  CREATE2-account machinery from the meta-address. It depends on two Drafts
  with no client code, so it cannot be demoed yet; the address derivation is
  implemented and vectored so the scheme is ready when a devnet is.
- **Near-term on the frames testnet:** keep the sponsored post-prefix verify;
  adopt the key-setup NTT (−8 %); restructure the first spend as
  `[deploy via 7997 factory …]` only where state gas allows (C13 accounts).
- **Do not** pursue the deployless trick, cross-frame or cross-transaction
  splitting, or an EVM ML-DSA precompile.
