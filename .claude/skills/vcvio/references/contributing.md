# Contributing to VCVio (PRs, issues, file conventions)

Condensed from VCVio `CONTRIBUTING.md` + `AGENTS.md` @ main `ea9916db` (2026-08-19). Apache 2.0.

## House rule first (this user, 2026-08-19)
Prepare everything locally (clone/branch/edit/build), **show the diff and the proposed PR text,
and wait for an explicit go-ahead** before any `git commit`, fork, push, or `gh pr create` —
upstream or in erc-5567. Never stack the commit onto the "build it" step.

## Before sending work
- `lake exe cache get && lake build` (Mathlib from cache; VCVio, LatticeCrypto etc. from source —
  a cold build is long; warm-start from a donor `.lake/build` when possible).
- New `.lean` files → `./scripts/update-lib.sh` (regenerates `ToMathlib.lean`, `VCVio.lean`,
  `LatticeCrypto.lean`, `Extern.lean`, `HashSig.lean`, `Examples.lean`, `VCVioWidgets.lean`,
  `VCVioTest.lean`; `LatticeCryptoTest.lean` is curated by hand).
- No `sorry` in finished work unless the PR explicitly preserves partial work (use `stop`).
- Repo-wide options live in `lakefile.lean`; don't restate `autoImplicit = false` per file.
- **Never** silence linters (`set_option linter.* false`, `weak.linter.*`, lakefile lint-offs).
  Fix the declaration/proof/name/format. Only exception: `weak.linter.unicodeLinter`.
- CI isolation checks: `scripts/check-extern-isolation.sh` (proof libs never import `Extern`),
  `scripts/check-interop-isolation.sh` (core never imports `Interop`/`Hax`/`Aeneas`).
- CI timed build: `ToMathlib`, `VCVio`, `LatticeCrypto`, `Extern`, `HashSig`, `Examples`,
  `VCVioWidgets`; smoke `lake env lean VCVioTest/Smoke.lean`. Toolchain + Mathlib both `v4.32.2`
  on main — update together.

## File prologue (ordinary Lean source)
```lean
/-
Copyright (c) 2026 Author Name. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Author Name
-/

module
public import VCVio.…        -- transitive public surface
import Mathlib.…              -- implementation-only

/-!
# Title

Summary; notation/references when they help.
-/
```
Exactly one blank line between blocks. Umbrella roots and `lakefile.lean` stay bare.

Attribution: new files get the current year + credited authors; **routine edits preserve the
existing header**; rewrite only when the file is genuinely new/replaced; keep upstream credit on
ported material; **no separate AI-attribution line**.

## Module scopes
Declarations in `public section` (`public meta section` for tactics/elaborators). Existing files:
`@[expose] public section` (keeps pre-migration defeq available downstream). New code may expose
individual defs with `@[expose]` when unfolding is part of the API; executable/runtime modules use
opaque `public section`. `public import` = transitive dep; `public meta import` = exported
compile-time dep; plain `import` = private dep; `import all` in a proof module that needs a
dependency's private implementation. Never `backward.privateInPublic` / `backward.proofsInPublic`.
(Our pin predates the module system — files there are plain `import`; don't copy that style into
an upstream PR.)

## Docstrings and sections
- Every ordinary file: module docstring `/-! … -/`; public defs and major theorems: `/-- … -/`.
- Intrinsic and descriptive; cross-reference live siblings; never "renamed from", "replaces",
  change history.
- Inline section breaks: `/-! ## Title -/` (or multi-line `/-! ## Title\n\n text -/`). **No ASCII
  banners.** Big enough for a banner → own `namespace` or file.
- Cite papers publicly (title/venue/URL), not by repo-local path. Relational-logic design
  authority: ERHL25 (`REFERENCES.md`).

## Naming (Mathlib)
`{head_symbol}_{operation}_{rhs_form}`: `probOutput_bind_eq_tsum`, `support_pure`, `simulateQ_map`.
Props/Types/structures/classes `UpperCamelCase` (`SecExp`, `SymmEncAlg`, `RelTriple`); proofs
`snake_case`; other terms `lowerCamelCase`; functions named like their return value.

## Structure rules
- Respect the layering DAG (SKILL.md §5); `EvalDist/` never imports `OracleComp/`.
- No sub-directory umbrella modules; callers import the specific submodule.
- Full cutover on refactors — no deprecated aliases / compat wrappers.
- Delete obsolete commented-out code; preserve live partial proofs with `stop`.
- Prefer `preInsert`/`postInsert`-based wrappers over hand-rolled `QueryImpl`s; register
  automation-facing lemmas with `@[vcspec]`/`@[wpStep]`; gate new `@[grind norm]` rules against
  `VCVioTest/{ProbabilityTactics,MonadProbability,LongChainPrograms,GrindFailFast}.lean`.
- Hypothesis bundles in new theorems must be shown inhabitable (gotcha 14).

## Filing issues
Each issue: the failing snippet (minimal `#check`/`example` that errors at a named commit), why
it bites downstream, and the concrete proposed change. Group roadmap-level asks (e.g. KEM-level
IND-CPA, KEM anonymity, un-`sorry` ML-KEM security) into one discussion thread. Our queue:
`lean/docs/vcvio-upstream.md` ("Suggested filing order").

## PR mechanics
- Branch from current `main` (not from our pin); `gh repo fork --remote` then push the branch;
  `gh pr create --repo Verified-zkEVM/VCVio`.
- Keep the diff to the change; don't touch headers of files you merely edit.
- Title in Conventional-Commit style as upstream uses (`feat(MLKEM): …`, `fix: …`, `refactor(…): …`).
- Stacked branches: restack with `git rebase --empty=drop --onto …`, review `git range-diff`.
