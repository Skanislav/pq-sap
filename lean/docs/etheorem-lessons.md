# What etheorem teaches us (and what it doesn't)

Survey of [`github.com/etheorem/etheorem`](https://github.com/etheorem/etheorem)
at commit `39be608f` (2026-08-21), read as "a mature Lean 4 Ethereum codebase —
what should we borrow?". Paths below are into that repository unless prefixed
with `PqStealth/` or `docs/`.

## 1. What it is

A **consensus-layer** implementation: SSZ (`packages/SizzLean`), the beacon
state transition and fork choice for the Fulu / Gloas (ePBS) / Heze (FOCIL)
forks (`packages/EthCLSpecs`, `packages/EthCLLib`), plus crypto packages
(`LeanSha256`, `LeanPoseidon`, FFI wrappers `LeanHazmat{Sha256,Bls,Kzg}` over
OpenSSL, blst, c-kzg). Single developer, LGPL-3.0-only, Lean `v4.29.1`
(we are on `v4.32.0`), Mathlib quarantined into the one proof package that
needs it (`packages/LeanPoseidonProofs`), no VCVio. About 39 kLoC across 256
files; ~500 `native_decide` uses almost all in test modules; 0 `sorry` (banned
by `just lint`) and exactly 5 `axiom`s, each with a docstring explaining the
trust step.

It is **not** an execution-layer implementation. There is no Keccak-256, no
secp256k1 / ECDSA / `ecrecover`, no RLP, no ABI, no EVM, no Merkle-Patricia
trie. So it cannot supply the primitives our Lean tree leaves uninterpreted —
`Prims.hashAddr` (keccak), `viewTag` (SHA-256 truncation), `expandA`/`expandBlind`
(SHAKE), the inner byte packers (`PqStealth/ConstructionA.lean`,
`docs/encodings.md`). The value is in engineering discipline, not primitives.

## 2. Borrowed, landed in this tree

| etheorem artefact | our version | status |
|---|---|---|
| `scripts/check_citations.py` — resolves every `File.lean:N-M` cited in docs against the declaration it names; `--fix` rewrites. Their motivation: 16 of 37 ledger rows were stale, worst off by 187 lines. | `lean/scripts/check_citations.py` (own code, same idea) | First run found 7 of 33 citations in `docs/improvements.md` stale, including one file that no longer exists (`MLKEMInstance.lean`) and a range past end-of-file. Fixed; 35/35 clean. |
| `scripts/check_constant_tiers.py` + `constant_tiers.json` — pins spec constants against a vendored ground truth, because "a misfiled preset value silently shapes an SSZ cap → wrong root, green build". | `lean/scripts/check_sizes.py` | Compares the sizes Lean proves by `rfl` (`metaAddress_size_mldsa65_mlkem768 = 5633`, `Bytes 1184`, `metaAddressZk_size_mlkem768 = 1217`) against `python/vectors/**/vectors.json`. First Lean ↔ implementation link in the repo; the `1217` vs `1218` ZK-layout difference is recorded as expected, not drift. |

Run both with `python3 lean/scripts/check_citations.py && python3 lean/scripts/check_sizes.py`
(stdlib Python only, no build needed).

## 3. Borrowable, not yet taken

### 3a. `LeanSha256` — an executable `viewTag`

`packages/LeanSha256/LeanSha256/Core.lean` is a pure-Lean, Mathlib-free,
kernel-reducible FIPS 180-4 SHA-256 (`hash : ByteArray → ByteArray`), validated
against NIST CAVP vectors with `native_decide` and carrying ~23 structural
theorems (`ch_eq_fips`, `pad_size_multiple_of_64`, `hash_size_eq_32`, …). It is
mirrored to a standalone repo (`github.com/etheorem/LeanSha256`) for Reservoir.

**Probe (2026-08-21):** copied the package, changed only `lean-toolchain` to
`v4.32.0`, `lake build LeanSha256` succeeded unmodified in ~2 s, and
`hash "abc"` starts `ba 78 16 bf` (the FIPS KAT). So it is a cheap
`[[require]]` if we ever want to

- instantiate `viewTag` concretely instead of as a `Prims` field, and
- check the `view_tag` values in `python/vectors/v0/vectors.json` from Lean
  (`#guard_msgs`-wrapped `#eval`, the `Demo.lean` pattern).

Cost: a second git dependency beside VCVio (pin it like `docs/vcvio-pin.md`),
and an LGPL-3.0 licence entry. Using it changes nothing in the proofs: the
view-tag soundness theorems (`Soundness.lean`) take the tag function as a
parameter and would simply be specialised. Tracked as issue #22 in
`docs/improvements.md`.

### 3b. The `UIntWide` proof technique for our inner packers

`packages/SizzLean/SizzLean/Proofs/UIntWide.lean` proves the `BitVec 128/256 ↔`
little-endian `ByteArray` codec roundtrip and size bounds with **only the three
kernel axioms** (no `bv_decide`, no `native_decide`) by `Nat` induction on the
digit expansion:

1. `size_natToLEBytes` — the writer appends exactly `w` bytes;
2. `get!_natToLEBytes` — byte `i` is `⌊n / 256ⁱ⌋ mod 256`;
3. `readNatLEAux_value` — the Horner reader over any buffer with those digits
   rebuilds `n mod 256^w` (one induction with the accumulator generalised,
   digit step is `Nat.mod_mul`);
4. compose.

`docs/encodings.md` leaves `packT : Vector (Fin 8380417) (k·256) → Bytes (k·736)`
and `packEk` as *parameters with roundtrip hypotheses*. Our packer is 23-bit
fields, not byte-aligned, so the file is not a drop-in, but the lemma path
(size → digit characterisation → reader-value induction → compose) is exactly
the shape of the missing proof. Rewrite from the idea rather than copying the
LGPL file.

### 3c. The explicit FFI-equals-spec axiom

`packages/SizzLean/SizzLean/Hasher/Sha256Equiv.lean`:

```lean
axiom sha256Hash_eq_spec : @LeanHazmat.Sha256.sha256Hash = LeanSha256.hash
```

One fast `@[extern]` implementation, one slow pure-Lean spec, one named axiom
identifying them, and a docstring saying a `@[csimp]` theorem could replace it
later without disturbing dependents; `#print axioms` keeps it auditable. This is
the pattern to use if we ever want an executable ML-KEM or Keccak in Lean via
`liboqs`/XKCP without proving the C: it fits our `Axioms.lean` guard directly
(the axiom's name would appear in the frozen list, visibly).

### 3d. Proof-coverage ratchet

`packages/EthCLLib/EthCLLib/Internal/ProofLedger.lean` defines an attribute
`@[characterizes f]` (registered with `applicationTime := .afterTypeChecking`,
so the handler rejects a tag whose theorem statement never mentions `f`), and
`scripts/ProofCoverage.lean` reads the compiled `.olean` environment — not
source — to grade coverage and `--check` fails CI if the number moves in
*either* direction. Our `Axioms.lean` ratchets the *axiom set* of 95 theorems;
it does not record *which ERC claim each theorem discharges*. A lighter
analogue for us: a claim ledger (ERC section → theorem name) validated by a
script that checks each name resolves. Worth doing once the residual terms in
`docs/improvements.md` settle.

### 3e. Hygiene we could copy cheaply

- `just lint` bans `sorry`, bare `#eval`, `#check`, `#print` from committed
  source by `git grep`. We keep `#guard_msgs`-wrapped `#eval`/`#print axioms`
  on purpose, so our rule would be "no `sorry`, no unwrapped `#eval`".
- Every module opens with `/-! # Module: purpose -/` and a *"Lean idioms used
  here (annotated on first appearance)"* section (`dif_pos`, `ByteArray.get!`,
  …). Our readers are cryptographers first; this is a good habit for the
  files that use VCVio-specific idioms.
- `set_option autoImplicit false` in every file (we do it once in
  `lakefile.toml`, which is the same thing); `maxHeartbeats` bumps are local
  and commented.
- CI calls `just <recipe>` for every step so local and CI cannot drift.
- A `CLAUDE.md` agent brief (26 KB) with an explicit *Don'ts* list and a
  writing-style section. We have none under `lean/`; ours lives in the `vcvio`
  skill and memory. Note their `ai_coauthor_guard.yml` rejects commits with an
  AI `Co-authored-by:` trailer — the opposite of our convention; listed for
  completeness, not adoption.

## 4. Confirmed not useful to us

BLS12-381 / KZG FFI (`blst`, `c-kzg-4844`), Poseidon2, SSZ, beacon state
transition, fork choice, the pyspec conformance harness
(`packages/EthCLSpecs/PySpecTests/`, pytest-xdist against a long-lived Lean
server — a nice pattern, but our conformance surface is seven JSON cases), and
anything game-based: there is no probabilistic reasoning in the repository.

## 5. Modelling choices worth noting for comparison

- `UInt256` is `BitVec 256` (`SizzLean/Spec/Interp.lean`); buffers are
  `ByteArray`; fixed-width roots/keys are `Vector UInt8 32/48`. We use
  `Vector UInt8 n` (`Bytes n`) for the wire layout and `ByteArray` only where
  VCVio's concrete ML-KEM forces it — the same split.
- Their central SSZ theorems are stated over a `BasicSupported` subset strictly
  smaller than `Supported`, with the restriction proved and documented rather
  than hidden. Same spirit as our "what is NOT proved" sections.
- Spec arithmetic stays in `UInt64` to match upstream overflow semantics, with
  `Nat` only as a documented escape hatch.
