# StealthKeyExchange — Lean model of the on-chain key-exchange layer

A machine-checked model of [`../src/StealthKeyExchange.sol`](../src/StealthKeyExchange.sol),
the contract that owns the chain's share of the ML-KEM handshake: the
encapsulation-key registry and the shape-validated `announce` that forwards
to the ERC-5564 singleton (D-021 in `docs/DECISIONS.md`). A second Lean
package next to the contract, on the same toolchain pin as [`lean/`](../../../lean/)
but with **no dependencies** — no Mathlib, no VCVio — so `lake build` takes
seconds and runs in `ci.yml` beside `forge test`.

## Modules

| Module | What it holds |
| --- | --- |
| `Params.lean` | The parameter table (four KEM sets, ciphertext / key / packed-`t` / meta-address sizes, version bytes, the length lookups) and its consistency: every lookup inverts its size function, the size functions are injective, the ERC draft's numbers by `rfl`. |
| `Contract.lean` | `State` (registry array + the announcer's log), `announce`, `registerViewingKey`, `viewingKeyOf`, `kemOfMetaAddress`, `isValidAnnouncement` — one line per `if`/`revert` of the Solidity, same order — and the theorems below. |
| `Vectors.lean` | **Generated** by `scripts/gen_vectors.py` from `python/vectors/v0/vectors.json`: each conformance case replayed through the model as a build-checked `#guard` (lengths, version bytes and addresses only — the contract reads nothing else). |
| `Axioms.lean` | `#guard_msgs in #print axioms` per headline theorem: a `sorry` anywhere in a cone is a build error. |

## What is proved

- `announce_toBool` — `announce` succeeds exactly when `isValidAnnouncement`
  holds (a ciphertext of a supported length, a view tag present). The Foundry
  suite fuzzes the same equivalence on the bytecode.
- `announce_ok` — on success exactly one entry is appended to the log, with
  scheme ID `2`, the caller's `stealthAddress`, ciphertext and metadata
  unchanged; the registry and the contract identity are untouched.
  `announce_error` names the failing input; `announce_log_prefix` is the
  append-only statement.
- `announce_no_registry_read` — the announcement path is the same function
  for every registry content: nothing recipient-identifying can enter (or
  leave through) an announcement.
- `registerViewingKey_toBool`, `registerViewingKey_ok`,
  `viewingKeyOf_after_register` — registration succeeds exactly on the
  supported key lengths, assigns the next index, stores the bytes and their
  set, and every older index still resolves to what it did.
- `kemOfMetaAddress_ok_iff` — a meta-address is typed exactly by its version
  byte and total length; `Kem.*_injective` — no two sets share a size.

## What ties the model to the bytecode

1. `Vectors.lean` and `test/StealthKeyExchange.t.sol` replay the same vectors.
2. `scripts/check_constants.py` diffs the parameter table across the Solidity
   constants, `Params.lean`, `js-client/src/key-exchange.ts` and the vectors.
3. `scripts/gen_vectors.py --check` fails if `Vectors.lean` is stale.

The proofs are about the model; its faithfulness rests on the line-by-line
correspondence plus (1)–(3), the same footing as `lean/` vs. `python/`. A
mechanized link to the compiled code (Nethermind's Clear, Yul → Lean 4; or an
EVM semantics such as EvmYul) is the upgrade path — both need Mathlib and
belong in the multi-hour `lean.yml` lane.

## Build

```sh
elan toolchain install "$(cat lean-toolchain)"   # once
lake build                                        # seconds; the build IS the check
python3 scripts/gen_vectors.py --check
python3 scripts/check_constants.py
```

Conventions follow `lean/`: `autoImplicit = false`, `linter.missingDocs`,
`simp only` with explicit lists, no `set_option linter.* false`, no
`native_decide`.
