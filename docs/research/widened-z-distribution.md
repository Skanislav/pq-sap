# Widened-z distribution and signature-route distinguishability

Status: research note feeding the security-analysis write-up (the widened-z
distribution item of the EPF definition). It quantifies what the widened
signing gates do to the distribution of the response `z`, derives a concrete
distinguishing channel between widened (blinded-key) and stock ML-DSA
signatures, and maps the spend-side linkability channels — absorbing the
analyses behind issues #29 and #33 — against the proven announcement
unlinkability bound. Analysis only; no protocol change proposed.

Every displayed probability is exact (rational) and derived from the theorems
cited; decimal values are computed from the rationals, never hand-rounded.

## 1. Setup: the widened gates

Construction A spending blinds the recipient's ML-DSA key as
`(s₁+s′, s₂+e′)` with `(s′, e′)` derived from the shared secret. Both sums are
`2η`-short, so the challenge-product bound doubles:
`‖c·(s₁+s′)‖∞ ≤ β' = τ·2η = 2β`
(`WidenedSigning.lean:43` `widenedBeta_eq_tau_two_eta`; the bound itself is
`sampleInBall_smul_widened_bound`, `WidenedSigning.lean:102`). The widened
identification scheme therefore tightens both response gates to
`‖z‖∞ < γ₁ − β'` and `‖r₀‖∞ < γ₂ − β'` (`widenedIdentificationScheme`,
`WidenedSigning.lean` §6), and the blinded key satisfies the widened key
relation (`widenedValidKeyPair_blinded`, `WidenedSigning.lean:156`).

The mask `y` stays uniform over the FIPS 204 cube `[−(γ₁−1), γ₁]^(l·256)`
(`sampleMaskCube`). Widening shrinks the acceptance region; it does not change
the mask distribution.

## 2. The accepted-z distribution is exact and key-independent

Two theorems pin the distribution completely:

- **Acceptance probability.** For any fixed shift `δ = c·s₁` with
  `‖δ‖∞ ≤ β'`, a cube-uniform mask passes the `z` gate with probability
  exactly `((2(γ₁−β')−1)/(2γ₁))^(l·256)`, *independent of `δ`*
  (`cube_shift_accept_prob`, `WidenedSigning.lean:351`; instantiated as
  `widened_z_accepted_independent`, `WidenedSigning.lean:402`). For ML-DSA-65
  (`γ₁ = 2^19`, `β' = 392`, `l·256 = 1280`) that is
  `(1047791/1048576)^1280 ≈ 0.383425`, kept as an exact rational in
  `mldsa65_widened_z_accept_prob` (`WidenedSigning.lean:590`).
- **Conditional uniformity.** Each accepted `z` has exactly one mask
  preimage `y = z − δ` (`coefficient_preimage`, `WidenedSigning.lean:335`):
  for `|z| < γ₁ − β'` and `|δ| ≤ β'`, `|y| ≤ γ₁ − 1` lies in the cube, and
  the accepted set size is `2(γ₁−β')−1` per coefficient for *every* shift
  (`card_filter_cube`, `WidenedSigning.lean:293`). So, conditioned on
  acceptance, `z` is uniform on the full `(γ₁−β')`-ball — the key-dependent
  shift cancels. **The accepted-`z` marginal leaks nothing about the key.**

Concrete numbers (exact rationals; `E` = expected rejection rounds for the
`z` gate alone, `1/p`):

| Parameter set | β | β′ | per-coeff accept | sign-accept `p` | `E[z gate]` |
| --- | --- | --- | --- | --- | --- |
| ML-DSA-65 (L3) | 196 | 392 | 1047791/1048576 | 0.383425 | 2.61 |
| Level-2 deployed profile (Dilithium2 shape, `γ₁=2^17`, `l=4`) | 78 | 156 | 261831/262144 | 0.294232 | 3.40 |

Stock (unwidened) acceptance for comparison: ML-DSA-65
`(1048183/1048576)^1280 ≈ 0.618891` (`E` 1.62); level-2
`(261987/262144)^1024 ≈ 0.541471` (`E` 1.85).

**Reconciliation with the measured round counts.** The measured end-to-end
rejection rounds (`benchmarks/README.md`, `param_sweep.py`, mean of 50) are
24.8 vs stock 5.5 for L3 (4.5×) and 14.4 vs 4.6 for the level-2 shape (3.1×).
The `z` gate alone predicts a ratio of only 1.61 (L3) and 1.84 (level-2). The
residual factor — 2.8× at L3, 1.7× at level-2 — is the widened `r₀` gate and
hint check, which the exact `z`-gate theorem does not cover. The benchmark's
own note ("a tighter probabilistic norm bound would help L3 the most") is thus
*understated* for the `z` gate alone but correct in direction: most of the
widening cost lives in the `r₀`/hint gates, and any probabilistic shortness
bound should target those first.

## 3. Widened signatures are statistically distinguishable from stock

The tight `z` gate is a disclosure channel. Stock ML-DSA enforces
`‖z‖∞ < γ₁ − β`; a widened signer always produces
`‖z‖∞ < γ₁ − β' = γ₁ − 2β`. Both signatures verify against the same stock
verifier (the widened bound is strictly tighter, so widened signatures pass),
but their *supports differ*:

- Every coefficient of a widened signature avoids the band
  `[γ₁−β', γ₁−β)` by construction.
- A stock signature lands entirely below `γ₁−2β` with probability
  `((2(γ₁−2β)−1)/(2(γ₁−β)−1))^(l·256)` under the same uniformity argument as
  §2 — for ML-DSA-65: `(1047791/1048183)^1280 ≈ 0.619536`.

So the boolean test "all coefficients `< γ₁−2β`" distinguishes widened from
stock signing with advantage `1 − 0.619536 ≈ 0.3805` per signature at L3, and
`1 − 0.543393 ≈ 0.4566` at the level-2 shape. Independent signatures
amplify: the probability that at least one of `k` stock signatures exposes a
band coefficient is `1 − 0.619536^k`:

| k signatures | 1 | 2 | 4 | 8 |
| --- | --- | --- | --- | --- |
| advantage (L3) | 0.381 | 0.616 | 0.853 | 0.978 |
| advantage (level-2) | 0.457 | 0.705 | 0.913 | 0.992 |

Caveats, stated precisely:

- The exactness above is for the `z` gate alone. The published signature is
  additionally conditioned on the `r₀` and hint gates (a fresh `y` per retry),
  which couples `z` with `w = A·y` and perturbs the stock marginal. The
  *widened* side is unaffected — its gate forces the band-avoidance event with
  probability exactly 1 — so the per-signature numbers are exact for the
  widened signer and z-gate-model-exact for the stock signer; the direction of
  the full-gate perturbation of the stock probability is not analyzed here.
- **What leaks is the route class, not the recipient.** `z` is key-independent
  (§2), so the channel reveals "this signature was produced with a widened,
  i.e. blinded, key" — it does not by itself connect two widened signatures to
  the same recipient. But it marks every blinded-key spend as a
  Construction-A-family spend, narrowing an observer's candidate set to
  `0x01`-format recipients before any key is revealed. It composes with the
  two disclosure channels below rather than replacing them.
- This is the quantitative statement of why `widened_ids_hvzk` cannot be
  sharpened to zero (next section): a widened transcript is not distributed as
  a stock transcript.

## 4. Why `widenedHvzkDistance` is pinned trivial — and the concrete floor

The pinned HVZK simulator `widenedHvzkSimulator` (`WidenedSigning.lean:548`)
draws `z` uniform over the full ring `Rq` (modulus `q = 8 380 417` per
coefficient) and only then applies the widened gate. Its acceptance
probability is `(1047791/8380417)^1280 ≈ 10^−1156`: the simulator essentially
never outputs a transcript. The honest prover, by contrast, aborts a round with
probability `1 − 0.383425 ≈ 0.616575`. The abort marginals alone put the
transcript distance at `≥ 0.6166 − 10^−1156 ≈ 0.6166` — this is the concrete
content hidden in the trivial pin `widenedHvzkDistance = 1`
(`WidenedSigning.lean:568`).

The sharpening path is mechanical: draw the simulator's `z` from the cube
(`sampleMaskCube`) instead of the ring, resampling until the gate passes. Then
the `z` marginal matches the honest prover exactly (both are uniform on the
accepted ball, §2), and the remaining transcript distance collapses to the
`(w₁, h)`-vs-`z` coupling plus the `r₀`/hint gate conditioning — the same
shape as upstream `MLDSA.hvzkBoundReal`, which the pin's docstring names as
the intended target. Until that simulator lands, `CmaToNmaLossNN` consumes
`zetaWide = widenedHvzkDistance = 1` (`SpendSecurity.lean:255`) and the
signature-layer composition stays open, exactly as
`construction-a-security.md` §3 records.

## 5. Unlinkability across payments — the channel map

The proven statement is passive announcement unlinkability: for `q`
announcements to two fixed recipients,
`Adv_unlink_q ≤ q · ε_single` (`unlinkAdvantageMulti_le_mul`,
`MultiUnlink.lean:241`), with the single-announcement decomposition into KEM
IND-CPA, blinding, and SPR-to-MLWE terms at
`unlinkAdvantage_scheme_le` (`ConstructionA.lean:173`; announcement model
`ofKEMFull`, `KEMAnonymity.lean:145`; ROM query bound
`blindBadProb_le_queryBound`, `BlindingEntropy.lean:94`). Everything below is
a *spend-time* disclosure and does not touch that bound — but the security
write-up must state each channel as a property, because none of them is
covered by a theorem:

| Channel | Trigger | What it reveals | Evidence / status |
| --- | --- | --- | --- |
| Announcement transcript | passive observation of announcements | nothing beyond `ε_single` per announcement | Lean decomposition, sorry-free (`construction-a-security.md` §1–2) |
| `rho` carried verbatim in `stealth_pk` (#29) | any full-key disclosure: on-chain ML-DSA verify, `PKContract` deployment, key tables | the recipient's matrix seed = the meta-address's `rho`; all revealed keys of one recipient link to it and to each other | `test_construction_a_rho.py`; D-027 finding; recommendation: keep `0x01`, state as property |
| `spend_key` hash linkage (#33) | any direct ML-DSA-44 commit spend | revealed `pk` hashes to the published `spend_key`; all direct spends link from the first one | `test_profiles.py:262`, vectors' `linkage` block; recommendation: informative, not normative |
| Widened-`z` band (this note) | any published blinded signature | route class ("widened/blinded key"), not the recipient; per-signature advantage 0.38 (L3) / 0.46 (level-2) | §3 above; quantifies the trivial-HVZK gap |

Composed reading: a recipient who uses only the receive/scan path is covered
by the announcement bound. The first *direct* spend is linkable twice over
(`rho` + `spend_key` hash) and additionally flags the blinded route via the
`z` band. Unlinkable spending requires routes that never reveal the key
(ZK/preimage) — and even those, if they publish widened signatures, reveal the
route class. The ERC text (human-written, D-024) should carry this as one
security-considerations paragraph spanning #29/#33 and this note; the
accompanying decision record is drafted as D-030 on the #28/#33 branch.

## 6. What would change the numbers

- **Probabilistic `β'`.** A high-probability bound on `‖c·(s₁+s′)‖∞` tighter
  than the worst case `τ·2η` would shrink both the rejection-round penalty
  (§2) and the distinguishing band (§3) together, since both scale with
  `β'`. It would have to be re-proven — `sampleInBall_smul_widened_bound` is
  the worst-case statement the widened gates are defined against. The
  benchmark note in `python/benchmarks/README.md` calls for exactly this;
  §2's reconciliation says the payoff concentrates in the `r₀`/hint gates.
- **Simulator fix.** The cube-source simulator of §4 makes the `z` marginal
  exact and isolates the honest quantification of the remaining HVZK gap —
  prerequisite for any nontrivial `zetaWide` and hence for composing
  `CmaToNmaLossNN`.
- **QROM blinding.** Even with all of the above, key blinding for lattice
  schemes has no QROM proof — the open problem recorded in
  `research/key-blinding-bibliography.md` (Eaton et al.'s generic framework
  is symmetric-scheme-only; Balumuri et al. 2024/945 is MPCitH). The `z`
  analysis here is classical-ROM throughout.

## Reproduce

Every number above from exact rationals (no dependencies):

```python
from fractions import Fraction as F

# ML-DSA-65: gamma1=2^19, beta=196, beta'=392, l*256=1280
g1, b, wb, n = 2**19, 196, 392, 1280
p_wide  = F(2*(g1-wb)-1, 2*g1)**n     # widened accept      = 0.383425…
p_stock = F(2*(g1-b)-1,  2*g1)**n     # stock accept       = 0.618891…
band    = 1 - F(2*(g1-wb)-1, 2*(g1-b)-1)**n   # stock avoids band = 0.619536…
adv     = 1 - band                    # per-signature advantage = 0.380464…
abort   = 1 - p_wide                  # honest abort marginal = 0.616575…

# Level-2 shape (gamma1=2^17, beta=78, beta'=156, l*256=1024): 0.294232 / 0.543393 / adv 0.456607

# Simulator accept (z uniform over Rq, q=8380417): (F(2*(g1-wb)-1, 8380417))**n ~ 10^-1156
```

Cross-checks: the per-coefficient widened rational `1047791/1048576` is the
one stated in `mldsa65_widened_z_accept_prob` (`WidenedSigning.lean:590`);
the deployed-profile `β' = 156` is `python/scripts/spendable_helper.py:49`
(`tau * 2 * eta`); the measured round ratios are the `param_sweep.py` table in
`python/benchmarks/README.md` (L3 24.8/5.5, level-2-shape 14.4/4.6).