# Gotchas and troubleshooting (full list)

Condensed from VCVio `docs/agents/gotchas.md` @ main `ea9916db` (2026-08-19). Numbering matches upstream.

## Critical
1. **Probability needs the right spec class.** `evalDist`/`probOutput`/`probEvent`/`Pr[…]` on
   `OracleComp spec` → `[IsProbabilitySpec spec]`; uniform cardinalities, `PMF.uniformOfFintype`,
   `support ↔ Pr ≠ 0` → `[IsUniformSpec spec]`. Plain `support` always works. Symptom: "failed to
   synthesize `MonadLiftT (OracleComp spec) SPMF` / `IsProbabilitySpec` / `IsUniformSpec` /
   `EvalDistCompatible`". Have `[spec.Fintype] [spec.Inhabited]`? local `IsUniformSpec.ofFintypeInhabited spec`.
2. **`autoImplicit = false` globally** (lakefile). Don't re-set per file. Symptom: "unknown identifier".
3. **`evalDist` IS `simulateQ`** (`m = PMF`, `IsProbabilitySpec.toPMF`); `evalDist_eq_simulateQ` is `rfl`.
4. **`++ₒ` is dead** → `+`.
5. **Delete obsolete commented-out code** (`[= x | …]`, `++ₒ`, `simulate'`, `getM`, `guard`); keep
   unfinished *live* attempts with `stop`. Canonical style: `Examples/OneTimePad/Basic.lean`.

## Type system
6. `query` = exported `HasQuery.query` (monadic, needs expected type); `spec.query t` /
   `OracleSpec.query t` is the primitive `OracleQuery` (for `liftM`, `.cont`, matching).
7. **Core types are reducible thin wrappers** over PFunctor (`OracleSpec`, `QueryImpl`,
   `OracleComp`, `OracleQuery`, `toPFunctor`). Use `OracleComp.inductionOn`/`construct`.
   - Dot notation on `oa >>= ob` fails (`Invalid field … PFunctor.FreeM.…`) — state lemmas prefix-form.
   - Never `attribute [local reducible]` a def that instance keys mention — instances like
     `MonadLiftT (OracleComp spec) SetM` silently vanish.
   - `OracleSpec.toPFunctor_add` is deliberately not `@[simp]`.
8. **`Fintype.ofFinite`-backed samplers are whnf-hostile** (`letI : SampleableType {v // P v} :=
   .ofFintype _` → `Fin (Fintype.card …)` whnf through `Classical.choice` → maxRecDepth/heartbeat).
   Workarounds: anonymous constructor instead of `where`; quantify abstractly and pin with
   `(h : x = concreteValue)` when callers can discharge it; pass `Classical.propDecidable`
   explicitly for `decide` over big props.
9. **Universes**: `OracleComp` 3 params, `SubSpec` 3 (`u v w`). Use `{ι : Type*}`, keep `α β : Type`.

## Proof patterns
10. **grind/simp split on probability lemmas**: `probOutput_bind_eq_tsum` is `@[grind =]` not simp
    (`rw` or `grind`); support-characterisation iffs are simp-only (see probability.md); opt in
    with `grind [lemma]`; downstream `grind [-l]`, `grind only […]`, `attribute [-grind] l`, `grind?`.
11. **Plain `vcstep` may solve a `Pr = Pr` goal you only wanted to rewrite** → `vcstep rw`,
    `vcstep rw under n`, `vcstep rw congr[']`. Manual: `simp only [← probEvent_eq_eq_probOutput]; rw [probEvent_bind_bind_swap]; simp only [probEvent_eq_eq_probOutput]`.
12. **Avoid `guard`** in experiments (`return (b == b')`, `return decide (r x w)`).
13. **`do` bind instance (Lean ≥ 4.29)** may differ from `Monad.toBind`, so `pure_bind`/`bind_assoc`/
    `bind_pure` don't fire → `LawfulMonad.do_pure_bind`, `do_bind_pure`, `do_bind_assoc`,
    `do_bind_pure_comp`, `do_map_bind`, `do_bind_map_left` (`ToMathlib.Control.Lawful.Basic`, all simp).
    **Verify first:** that file and those lemma names were not found at our pin `a5f474fd` nor on
    main `ea9916db` (2026-08-19) — the upstream doc is ahead of or stale vs. the code.
14. **Hypothesis satisfiability is a proof obligation.** Vacuous theorems pass `#print axioms`.
    Watch relation-pinning pairs `(hr : GenerableRelation _ _ r) (hGen : hr.gen = myGen)` (needs
    `gen_sound` compatible) and cardinality mismatches (small seed space ≠ uniform on bigger space).
    Ship a kernel-checked inhabitance witness for new bundles; label toy witnesses as such.

## Module structure
15. `EvalDist/` never imports `OracleComp/` (layering DAG in SKILL.md §5).
16. Preserve partial proofs with `stop`.
17. `OracleComp.inductionOn` is the canonical eliminator (`| pure x | query_bind t oa ih`, then
    `simulateQ_bind/query/pure`; see `simulateQ_id'` in `VCVio/OracleComp/SimSemantics/SimulateQ.lean`).
18. **Full cutover, no backward-compat shims** — update all call sites, no deprecated aliases.
19. **No thin re-export umbrellas** except top-level roots (`VCVio.lean`, `ToMathlib.lean`,
    `Extern.lean`, `HashSig.lean`, `Examples.lean`, `LatticeCrypto.lean`, `Interop.lean`,
    `VCVioWidgets.lean`, `VCVioTest.lean`, `LatticeCryptoTest.lean`). Import the specific submodule.

## Build and tooling
20. Always `lake exe cache get` before `lake build`.
21. Warm-start a new worktree: `mkdir -p new/.lake; test ! -e new/.lake/build; cp -a donor/.lake/build new/.lake/`
    then `lake exe cache get && lake build`. Doesn't replace the Mathlib cache.
22. **`lake env lean` / LSP can see stale oleans** → phantom timeouts, "unknown identifier",
    "already declared", section-dependence. Run `lake build <target>` first, then reproduce.
23. **Don't disable linters** (`set_option linter.* false`, `weak.linter.*`, lakefile lint-offs).
    Only documented exception: `weak.linter.unicodeLinter false` (FIPS-204 notation, diacritics).
24. After adding `.lean` files: `./scripts/update-lib.sh` (regenerates the root umbrellas).
25. **Active sources use module scopes**: `module`, deliberate `public import`, declarations in
    `public section` / `public meta section`; ordinary files `@[expose] public section`; runtime
    modules opaque `public section`. Never `backward.privateInPublic` / `backward.proofsInPublic`.
    `Interop` and `LibSodium/SHA2.lean` excluded; `LatticeCryptoTest.lean` is a curated umbrella.
26. Lean toolchain and Mathlib in sync (`lean-toolchain` + `require … mathlib @ git "v4.32.2"`).
27. Cite public papers (title/venue/URL) in shared docs, not repo-local paths.
28. Relational logic design authority: *A Quantitative Probabilistic Relational Hoare Logic* (ERHL25).
29. Agent guidance files must be committed (worktrees need them).
30. Restack with `git rebase --empty=drop --onto <new-base> <old-base-tip> <branch>`; check with
    `git range-diff`; tree identity `git diff <pre> <post> --quiet` only when the base changed
    solely by folding the same content.

## Ours (found building PqStealth against the pin; see `lean/docs/vcvio-upstream.md`)
- `mathlibStandardSet` linters + `#guard_msgs in #print axioms` on a continuation line = every audit
  block errors (`style.commandStart` captured). Keep `#print axioms` one-line; we enable only
  `linter.missingDocs`.
- `OracleSpec.randomOracle`, `DeferredSampling` (+ `ProbeEps`) not reachable from the root import
  at the pin — import explicitly; a rename fails at import resolution.
- "first byte of a uniform 32-byte vector is uniform" not provable in-tree at the pin
  (`Soundness.lean` carries it as a hypothesis).
- `LatticeCrypto/MLKEM/Security.lean` theorems (`kpke_ind_cpa_security`, `kpke_delta_correct`,
  `ind_cca_security`) are `sorry` at the pin — don't cite them as proved.
