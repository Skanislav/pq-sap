# ANO-CCA port to VCVio main (v4.36 idiom) — status

**2026-11-18.** `ANO.lean` is the ERC-8441 G2 work item: ANO-CPA/ANO-CCA key-privacy
notions for `KEMScheme`, rewritten in the idiom of current VCVio `main`
(`leanprover/lean4:v4.36.0`, measure-based probability, `OracleComp` games).
It is the port of the CI-proven SPMF-era layer on pq-sap branch
`feat/erc-8441-scheme3-lean` (`PqStealth/KEMAnonymity.lean`).

## What is in the file

- `ANO_Adversary`, `ANO_CPA_Experiment`, `ANO_CPA_Game`, `ANO_CPA_Advantage`
  (advantage = `(runtime.evalDist …).boolBias : ℝ≥0∞`)
- `ANO_CCA_oracleSpec` = `spec + ((Bool × C) →ₒ Option K)` with
  `ANO_CCA_preChallengeImpl` / `ANO_CCA_postChallengeImpl` handlers
  (`QueryImpl.add spec.passthrough …`, challenge ciphertext masked per branch)
- `ANO_CCA_Adversary`, `ANO_CCA_Game`, `ANO_CCA_Advantage`
- `ANO_Adversary.toANO_CCA` (CPA→CCA embedding; mirror of
  `IND_CPA_Adversary.toIND_CCA`) with `simulateQ_toANO_CCA`,
  `toANO_CCA_preChallenge/_postChallenge`
- `ANO_CPA_Game_eq_ANO_CCA_Game_toANO_CCA` — the mirror of upstream's
  `IND_CPA_Game_eq_IND_CCA_Game_toIND_CCA`

## Idiom conformance (verified against VCVio main AGENTS.md + code)

- games in `OracleComp spec Bool` (no `SPMF`; codemod reports 0 sites)
- advantage in `ℝ≥0∞` via `Measure.boolBias` (`ToMathlib.MeasureTheory.Measure.Bool`)
- hidden-bit law available upstream: `evalDist_boolBias_bind_uniformBool`
  (`VCVio/CryptoFoundations/SecExp/Measure.lean`)
- oracle union through `QueryImpl.add … passthrough` (mirrors IND_CCA handler
  style in `VCVio/CryptoFoundations/KeyEncapMech.lean`)
- reductions **named** (adversary structures, no `∃ B`); `autoImplicit = false`
  respected; no ASCII banners; `module`/`public section` scopes; Apache header.

## Verification status — HONEST

- **Not typechecked.** No box here can host the v4.36 toolchain + Mathlib cache
  (needs ~7+ GB; 29 GB disk at 96%). The file targets CI: it would be checked in
  VCVio's own `lake build` when opened as a PR (or on a fork runner).
- Static gates passed here: upstream codemod `migrate-native-probability.py
  --dry-run` → 0 sites to finish by hand; style conventions by direct inspection
  against `AGENTS.md` + `CONTRIBUTING.md`.
- Review gate (user rule): Kimi + GLM must review before any upstream filing.
- NOT placed in a public repo yet; `ANO.patch` is the file as a new-file diff
  for pasting into a PR review round.

## Provenance note

Definitions correspond 1:1 to the pq-sap branch layer that already carries
proofs (`ANO_CCA_Advantage_le_of_spr`, `ANO_CCA_Advantage_le_of_spr_full`,
zero sorry, CI-checked at the pin `a5f474fd`). The port carries the same
statement shapes; the two big SPR bound theorems are NOT yet restated here —
next step after review.
