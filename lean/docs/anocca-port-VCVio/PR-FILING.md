# ANO-CCA PR — filing instructions (VCVio upstream)

**Prepared:** 2026-11-19, commit `c7fdcd0` on `junketii-cubus/VCVio:feat/kem-ano-cca`.
**Everything is pushed and verified** — the branch on GitHub carries the exact
seven-review-round file; you only clone, (optionally mirror), and open the PR.

---

## State of the branch (already done — do not redo)

- Fork: `junketii-cubus/VCVio`, branch `feat/kem-ano-cca`, HEAD `c7fdcd0`
  (base: upstream `main` @ `f1e63c7`, current at preparation time).
- Commit contents (the whole diff is 2 files, +250):
  - `VCVio/CryptoFoundations/KeyEncapMech/ANO.lean` (249 lines, new file)
    — byte-identical to the reviewed file: check with
    `git show c7fdcd0:VCVio/CryptoFoundations/KeyEncapMech/ANO.lean | diff - ANO.lean`
  - `VCVio.lean` — one umbrella line added at 174:
    `public import VCVio.CryptoFoundations.KeyEncapMech.ANO`
- Commit message references #848 (tempcheck follow-up) and #801 (naming),
  plus `Co-authored-by: Skas <108791624+Skanislav@users.noreply.github.com>`.

The review history (7 rounds: Kimi-K3, deepseek-v4.1-flash via the `fv` agent
profile, GLM cross-checks) and the review package live in pq-sap at
`lean/docs/anocca-port-VCVio/` — not part of this PR, reference only.

---

## Step 1 — mirror the branch to your own fork (Skanislav)

The PR must open from your account. `gh` handles the mirror:

```sh
# one-time (skippable if you already forked VCVio before)
gh repo fork Verified-zkEVM/VCVio --clone=false

# sync your fork's main to upstream first (so the PR diff is only our 2-file change)
gh repo sync Skanislav/VCVio -b main

# create the branch on your fork from the cubus branch
gh api repos/Skanislav/VCVio/branches -f branch=feat/kem-ano-cca \
  -f sha=$(gh api repos/junketii-cubus/VCVio/branches/feat/kem-ano-cca --jq .commit.sha)
```

If `gh repo sync` complains your fork diverged, easiest clean path:
delete + re-fork, or push the branch directly:

```sh
git clone https://github.com/Skanislav/VCVio sk-vcvio && cd sk-vcvio
git remote add cubus https://github.com/junketii-cubus/VCVio
git fetch cubus feat/kem-ano-cca
git push origin cubus/feat/kem-ano-cca:refs/heads/feat/kem-ano-cca
```

## Step 2 — save the PR body

Create `pr-body.md` with the text below (verbatim).

## Step 3 — open the PR

```sh
gh pr create --repo Verified-zkEVM/VCVio \
  --base main --head Skanislav:feat/kem-ano-cca \
  --title "feat(CryptoFoundations): KEM recipient anonymity — ANO-CPA/ANO-CCA notions for KEMScheme" \
  --body-file pr-body.md
```

(If you push rather than mirror in step 1, use `--head Skanislav:feat/kem-ano-cca`
the same way — gh resolves any branch living on your fork.)

---

## pr-body.md (verbatim)

```markdown
## Summary

Adds key-privacy (recipient-anonymity) notions for `KEMScheme`, mirroring the
existing IND-CPA/IND-CCA architecture in `KeyEncapMech.lean`: an adversary
structure, hidden-bit games over `OracleComp`, advantage as
`Measure.boolBias` of `runtime.evalDist`, a dual-key decapsulation oracle
union `spec + ((Bool × C) →ₒ Option K)` answered through `QueryImpl.add`
with `spec.passthrough`, the challenge ciphertext excluded per branch, and a
CPA-to-CCA embedding with the corresponding game-equality theorem.

## Motivation

IND-CCA protects the encapsulated shared key; recipient anonymity hides
*which public key* a ciphertext was encapsulated under. They are independent:
registered public keys and announcements are public, so IND-CCA alone does
not give recipient privacy. This matters wherever ciphertexts are publicly
scanable, e.g. post-quantum stealth-address protocols (ERC-8441), whose
draft assumes ML-KEM provides both properties as separate claims.

Follows up on #848 (tempcheck; no objections were raised). Naming follows
#801's settled conventions; composition with the FO work remains #785's
orbit and is not touched here.

## What's in the file

- `ANO_Adversary` — two-phase ciphertext-only anonymity adversary (`ANO_CPA_*`)
- `ANO_CPA_Experiment` (fixed branch, verdict bit), `ANO_CPA_Game` (hidden
  bit, returns `b == b'`), `ANO_CPA_Advantage` (`boolBias` of the single
  game's `evalDist`, as for `IND_CPA_Advantage`)
- `ANO_CCA_oracleSpec = spec + ((Bool × C) →ₒ Option K)` with pre/post-challenge
  handlers: real decapsulation under the queried key; the challenge ciphertext
  is rejected by both post-challenge oracles
- `ANO_CCA_Adversary`, `ANO_CCA_Game`, `ANO_CCA_Advantage` — both decapsulation
  oracles stay live throughout
- The oracle-ignoring embedding `ANO_Adversary.toANO_CCA` (anonymity analogue
  of `toIND_CCA`), the general collapse lemma `simulateQ_add_liftM_left`, the
  phase lemmas `toANO_CCA_preChallenge`/`toANO_CCA_postChallenge`, and
  `ANO_CPA_Game_eq_ANO_CCA_Game_toANO_CCA` (mirroring
  `IND_CPA_Game_eq_IND_CCA_Game_toIND_CCA`)
- Advantage-unfolding companions `ANO_CPA_Advantage_eq_game_bias` /
  `ANO_CCA_Advantage_eq_game_bias` (by `unfold …; rfl`)

## Design decisions

- **Ciphertext-only shape**: the adversary sees the challenge ciphertext but
  never the encapsulated key. #848 also sketched a key-revealing variant; it
  is deliberately left out here so this PR carries one self-contained notion —
  the key-revealing variant plus the implication theorem would be a natural
  follow-up if wanted.
- **Both oracles live pre and post challenge**, masked per branch exactly at
  `bc.2 = cStar → none`; failure semantics of the KEM are preserved for every
  non-challenge ciphertext.
- **Advantage normalization** matches the house convention: `boolBias` of the
  single game's `evalDist`, with totality noted in the docstrings.
- Generic over `KEMScheme`; no ERC-specific definitions, no ML-KEM claims.

## Verification

- Not compiled locally; CI will provide the kernel verdict on all of the above.
- `scripts/migrate-native-probability.py --dry-run` → 0 sites.
- One known linter question: `ANO_Adversary.toANO_CCA` dot-notation mirrors
  upstream's `IND_CPA_Adversary.toIND_CCA` (which carries no baseline entry);
  if CI's `defsWithUnderscore` linter flags it, the in-file
  `attribute [nolint defsWithUnderscore]` is the ready fix.
- The umbrella line (`public import VCVio.CryptoFoundations.KeyEncapMech.ANO`
  in `VCVio.lean`) is included; if `scripts/check-imports.sh` wants a
  different order, `./scripts/update-lib.sh` regenerates it.
```

---

## After filing — expected CI outcomes

| Check | Expected | If it fails |
| --- | --- | --- |
| `lake build` | green (structurally verified vs live main sources; game-equality proof mirrors `KeyEncapMech.lean:185–207` line for line) | paste the error back to the agent — every repair so far was one-line-class |
| `defsWithUnderscore` lint on `toANO_CCA` | likely green (twin `toIND_CCA` carries no baseline entry) | add `attribute [nolint defsWithUnderscore] KEMScheme.ANO_Adversary.toANO_CCA` in-file; **not** a nolints.json row (CI forbids PR-time baseline edits) |
| `check-imports.sh` (umbrella) | green (line inserted alphabetically) | run `./scripts/update-lib.sh`, commit the regenerated `VCVio.lean` |
| expose-boundary / axiom sweep / interop isolation | green (one `public section`, no `sorry`, no imports beyond the DAG) | unlikely; paste error back |
| Mathlib cache / toolchain mismatch | green | sync `lean-toolchain` + Mathlib rev (only if upstream moved since `f1e63c7`) |

Drop the PR number back to the agent to watch CI.
