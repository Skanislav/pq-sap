# Devcon sharing cheatsheet — week by week

Companion to the Devcon talk preparation. Maps each EPF write-up to one
shareable beat, the artifact to put on screen, and the claim that must not be
overstated. Every figure below is cross-checked against a repo artifact, not
against the blog text.

Target window: Devcon(nect), November 2026.

## Cheatsheet

| Week | One thing worth the airtime | Show | Don't overclaim |
| --- | --- | --- | --- |
| W01 Ð-day | Why privacy migration ≠ signature migration | ePrint 2025/112 highlights PDF | "started on 8304" was a wrong turn — say so |
| W02 SSZfication | Log discovery is the actual bottleneck | EIP-7668 + execution-specs PR #3037 (merged) | bloom removal is not scheduled |
| W03 Scoping 8304 | A new state type was the original plan | 4788-style system-contract sketch | 8304 was later DFI'd — don't pitch it as shipping |
| W05 Marrying the proposals | Temporary verifiable state is cheaper than storage | Kurtosis/ethereum-package + re-org root posting | Vansh's Geth PoC is his work, not mine |
| W06 Back to the lattice | Live ML-KEM announcement on Sepolia | tx `0x2630…fc1c`, **67,580 gas** | 1,088-B ciphertext vs 33-B point is a cost, not a win |
| W07 Trees, hashes, Lean | Poseidon detour rejected on hash policy | D-015 (no arithmetization-oriented hashes) | never present Merkle-Poseidon as considered viable |
| W08 Bytes in, leverage out | ERC-7913 `(verifier, key)` as the spending boundary | repo + ERC-8373 vector PR | AI wrote code, not the design |
| W10–11 X-Wing, ecrecover, SPHINCS⁻ | The spend-route comparison table | blog table (linkage per route) | VCVio #583 merged, #582 only opened |
| W12–13 Framemogging | Spending is the cost wall; aggregation is the exit | ~$200/verify + EIP-8288 (3 k / 30 k per dependency) | the "Fireblocks 1.23 M" number is **not evidence** |
| W14–15 Inception | Scope discipline: KEM settled, spending to AA | `ml-dsa-44-commit/v0` profile + `StealthKeyExchange.sol` | trusted registrar on key setup; ML-DSA-65 verifier still open |
| W16 ERC-8441 | Someone else shipped a scheme first — here is what the review found | 10 comments + VCVio #848 | KEM anonymity is an *assumption*, not a proved result |

## Per week: the line to say

**W01** — "Ethereum's PQ roadmap says confidentiality breaks before
ownership. Funds migrate when the threat lands; harvested privacy is already
lost." Bridge: that makes stealth addresses the urgent PQ target, not
signatures.

**W02** — "Every stealth payment is a public, permanent announcement.
Discovery is an O(n) log scan, and trustless indexing is what makes it
light-client verifiable." Show the state-growth dashboard as the motivating
cost.

**W03** — "The first plan was EIP-8304 trustless log indexing, with table
roots as the integration point." One sentence, then pivot: the scheme work
turned out to be the better fit for the cohort.

**W05** — "8304's real insight was cheap temporary verifiable state — a
log-root table is far cheaper than storage slots." Honest caveat: re-org
handling and posting roots during block creation were the risky part, not the
encoding.

**W06** — The origin slide. Live PoC, announcement #0 at 67,580 gas, 1,088-byte
ML-KEM ciphertext against 33 bytes for secp256k1. Then the decision that shaped
everything: split PQ-safe key exchange (this project) from PQ-safe spending
(protocol level).

**W07** — "We considered Merklized Poseidon leaves for registry writes because
it is cheaper. We dropped it: no arithmetization-oriented hash in the hot path
(D-015)." A rejection that can be defended is the credibility beat.

**W08** — "Spending must be swappable, so I abstracted it as ERC-7913
`(verifier, pubkey)` and kept the KEM independent." Mention AI leverage
explicitly and where it stopped: design and review stayed human.

**W10–11** — Highest-value slide of the talk. Two pieces:

- Circle's `ecrecover` sentinel (`v = 27, s = 0`; `r` → signatureIndex ‖
  verificationFunctionId) keeps ERC-6538 alive without a registry migration.
- SPHINCS⁻ verify ≈ **188,092 gas** vs ML-DSA ERC-7913 ≈ **14.97 M** → ≈77×
  (D-018, measured on anvil; upstream Sepolia 188,278 corroborates).

**W12–13** — "Frames are SFI'd, devnets run them, and cost is still the wall."
Quote the arithmetic: ~$200 per signature verification. Then the exit:
EIP-8288 aggregation, where 3 k (leanSPHINCS) / 30 k (leanSTARK) per dependency
is a *proposed charge, not a measured total*.

**W14–15** — The "it became real" slide: commitment profile (`0x02`,
meta-address 5,633 → **1,217 B**), `StealthKeyExchange.sol` with a
dependency-free Lean model, hardened verify paths (gas exhaustion, registry
replacement, malformed ERC-7913 output). State the boundary in the same breath:
key setup trusts a registrar.

**W16** — Close on external validation. ERC-8441 (schemeId 3) = ML-KEM-768 +
secp256k1 ECDH through a SHA3-256 hybrid combiner. The contribution is the
review plus the formal gap:

- Asymmetry: if ECDH falls, ML-KEM keeps the secret *and* recipient anonymity;
  if ML-KEM shared-secret security fails, ECDH cannot repair anonymity.
- Anonymity is ANO-CCA, an *assumption* the ERC states (CRYPTREC-EX-3502-2025
  §4), and the naive FO lift is false under implicit rejection
  (Maram–Xagawa). That is VCVio #848.
- Reality check: one announcement in 24 h on the canonical announcer; the last
  ten span 24 days.

## Numbers to use vs. avoid

| Use | Value | Source |
| --- | --- | --- |
| Announce gas (PQ) | 67,580 (EIP-7623 calldata floor) | `python/benchmarks/onchain_results.json` |
| Announce gas (DKSAP) | 27,342 | same |
| Scan slope | 44.3 µs/announcement vs 27.5 µs DKSAP → 1.61×, R² > 0.999 | `python/benchmarks/registry_curve_20260802.json` |
| Per million announcements | ~44 s | derived from the slope |
| SPHINCS⁻ verify | 188,092 gas, ≈77× cheaper than 14.97 M | D-018 |
| Meta-address | 1,217 B (`0x02`), was 5,633 | D-024 |
| 8304 receipt bandwidth | 13,308 → 1,109 B ≈ 12× (measured) | `python/benchmarks/eip8304_poc_20260802.json` |

Avoid:

- "Fireblocks 1.23 M ML-DSA verify" — `docs/ml-dsa-commit-profile.md` records
  that no primary source, parameter set, or reproducible benchmark was
  evaluated: it is not evidence.
- "256× bandwidth win" as *measured*. The 8304 PoC measured ≈12×; 256× is a
  projection (`python/benchmarks/README.md`).
- Attributing the 77× figure to the proof-verified route — the 4.2 M figure is
  a separate route.

## Slide spine if the slot is 12 minutes

1. Harvest-now-decrypt-later → privacy before ownership (W01)
2. Announcements are the leak; discovery is O(n) (W02)
3. ML-KEM announcement live, 67,580 gas (W06)
4. Split: KEM here, spending at protocol level (W06 / W14)
5. Scan cost: 1.6× EC, linear over a 64× range (W10–11 + repo)
6. Spend cost wall → EIP-8288 is the only exit (W12–13)
7. Route table: what each spend reveals (W10–11)
8. Formal gap: anonymity ≠ IND-CCA; ANO-CCA is assumed (W16)
9. ERC-8441 landed; review + VCVio #848 (W16)
10. Ask: reviewer package + human-written ERC text, then community review
    (`docs/ERC_EVIDENCE.md`, `plan.md`)

## Fix before the talk

- The blog says ERC-8441 skips `schemeId` 2 while this repo's client uses `2n`
  as its own target ID (`js-client/src/sepolia.ts`). Expect the question; have
  the one-line answer ready.
- The W14–15 "two schemes" framing is superseded by D-024: one key-exchange
  subject, with spending delegated. Present the second scheme as *open*, not
  planned.

## Sources

- <https://skas.gwei.domains/epf/epf-week-1/>
- <https://skas.gwei.domains/epf/epf-week-2/>
- <https://skas.gwei.domains/epf/epf-week-3/>
- <https://skas.gwei.domains/epf/epf-week-5/>
- <https://skas.gwei.domains/epf/epf-week-6/>
- <https://skas.gwei.domains/epf/epf-week-7/>
- <https://skas.gwei.domains/epf/epf-week-8/>
- <https://skas.gwei.domains/epf/epf-week-10/>
- <https://skas.gwei.domains/epf/epf-week-13/>
- <https://skas.gwei.domains/epf/epf-week-14/>
- <https://skas.gwei.domains/epf/epf-week-16/>

No week-4, week-9, or week-17 page is published; the index jumps from W03 to
W05 and from W08 to W10–11.
