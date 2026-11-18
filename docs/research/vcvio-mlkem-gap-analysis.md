# VCVio ML-KEM gap analysis for ERC-8441 — formal verification and a compiled Lean implementation

*Status: analysis only, not committed. Sources verified 2026-11-17 against VCVio `main`
(tree + issue #785 + PR #1107 + recent `LatticeCrypto/MLKEM` history) and against our
pin (`a5f474fd`, 2026-07-15, documented in `vcvio-pin.md`).*

ERC-8441 needs two things from the Lean side:

1. **Formal verification** of the announcement layer: ML-KEM-768 IND-CCA, ML-KEM-768
   ANO-CCA (assumed, per the ERC's Security Considerations), the hybrid combiner's
   CCA theorem (SP 800-227 shape), and the DKSAP-style unlinkability of the additive
   derivation.
2. **A compiled implementation** of schemeId 3 from Lean as the second independent
   implementation (ERC-8441 reaching Final), alongside the first (namnc's Rust).

## Upstream state (verified 2026-11-17)

- The three ML-KEM security placeholders we watched (`kpke_ind_cpa_security`,
  `kpke_delta_correct`, `ind_cca_security`) are **no longer present**: #547 deleted
  them because their statements were vacuous or false. `LatticeCrypto/MLKEM/Security.lean`
  on `main` is now 71 lines of honest packaging (`prfJ`, `foKEMScheme`) plus a
  docstring listing exactly what is missing.
- Issue **#785** (quangvdao, 2026-09-22, updated by dtumad 2026-11-13) is the master
  tracking issue: "Restate and prove Fujisaki–Okamoto and ML-KEM security". It fixes
  the restatement requirements (nonnegative `ℝ≥0∞` slack tied to `deltaCorrect` /
  `gammaSpread`, `MakesAtMostQueries`-style bounds, named reduction functions, fixed
  CBD-noise MLWE problems, IND-CCA stated for the FIPS 203 `KEM.lean` construction)
  and a proof order: T-transform OW-PCVA → U-transform IND-CCA → composed FO →
  K-PKE δ-correctness + IND-CPA→MLWE → ML-KEM IND-CCA.
- Step 0 of that ladder has landed: **PR #1107** (merged 2026-11-16) rebuilds the
  OW-PCVA experiment per HHK17 Definition 2.1 / Figure 3 (validity oracle refuses
  the challenge, Pco game added, δ-relations, decryption-error gap term `OW_PCVA_DecryptionError`).
  The T-transform bound itself still needs HHK17's ROM correctness lemma (δ₁(q_G)),
  which the library does not have yet.
- Executable correctness is advancing in parallel: NTT loop-kernel proofs for ML-KEM
  landed 2026-11-09 (stages, negacyclic multiplication), and
  `LatticeCryptoTest/MLKEM/ACVPVectors.lean` pins NIST ACVP vectors as tests.
- The Oct 2026 probability rewrites (events as do-sequences, SPMF retired) are
  **breaking** for our carried lemmas: `PqStealth` is pinned before them.
- **Quantum/QROM landed upstream 2026-10-28** (#706 closed): quantum programs and
  runtimes with a private register (#850–#917), the simulation lemma, zero-query
  equality, QROM ≡ classical ROM for classical algorithms
  (`VCVio/Quantum/Oracle/Classical.lean`), and the compressed oracle as a runtime
  with the same law as the QROM (#855) with query-mass/square-root hybrid bounds,
  semi-classical O2H, measure-and-reprogram. The ecosystem spun out into
  `lean-crypto-foundations` (QuantumFoundations by Bas Spitters, merged-in-progress
  #1–#4; `QuantumCrypto` with semi-classical O2H, compressed oracle, and — per
  #706's thread — CatCrypt-core's **ML-KEM-512 IND-CCA in the QROM against quantum
  adversaries**, `mlkem512_qindcca_fips_two_pow`, pending the game-layer bridge).

## Gap table

| # | Gap | Blocks | Owner | Where | Status |
|---|---|---|---|---|---|
| G1 | ML-KEM-768 IND-CCA (FO bound + K-PKE δ-correctness + IND-CPA→MLWE with fixed instances) | Unconditional ERC security claims, schemeId 3 unlinkability | upstream | #785 steps 1–5 | step 0 merged (#1107); rest open |
| G2 | KEM anonymity (ANO-CPA/ANO-CCA) definitions in `KeyEncapMech.lean` | The ERC's explicit ANO-CCA assumption; our `KEM.AnonExp` is a downstream substitute | we offer PR | ported draft: `lean/docs/anocca-port-VCVio/ANO.lean` on `main` idiom (v4.36) | written + reviewed (fv agent rounds 1–3; verdict SHIP per 2026-11-18); not filed |
| G3 | Hybrid combiner theorem (IND-CCA of `Hash(DS‖ss_ec‖ss_pq‖epk‖ct‖ek_ec‖ek_pq)` if either KEM is IND-CCA) | schemeId 3's core claim | we | pq-sap `lean/PqStealth` track, on upstream KEM interfaces | ours to prove; interfaces exist |
| G4 | secp256k1 executables in our tree (ECDH, compressed encoding, address) | compiled schemeId 3 | we | thin `@[extern]` FFI to libsecp256k1 (Extern pattern) or reuse | small |
| G5 | Pure-Lean SHA3-256 export | combiner in pure-Lean route | upstream (small) or ours | `FFI.Hashing` already exports sha3_256/shake; pure-Lean def needs a home | FFI route ready |
| G6 | schemeId 3 scheme layer in Lean (seed envelope, meta codec, combiner, offset+view tag, sender/scanner/recipient) + ERC-8441's 29 vectors replayed | the compiled second implementation's conformance | we | pq-sap `lean/`, replaying `assets/erc-8441/vectors/` | not started; ACVPVectors is the template |
| G7 | Pin bump `a5f474fd` → current main | everything above lands in our tree | we | `vcvio-pin.md` procedure | substantial: Oct probability rewrite touches `Games`/`MultiUnlink`/`KEMAnonymity` idioms |
| G8 | Compiled-artifact packaging (Lean→C objects → native lib + Python/TS bindings, later wasm) | shipping the implementation | we | EthLib's lakefile/bindings pipeline is the proven template | not started |

Dependencies: G7 before adopting G1/G2 results; G3 and G6 are buildable now
(G3 against upstream interfaces at current pin shape, G6 on the pinned tree); G8
last. The unlinkability reduction and DKSAP-style address work (`DKSAP.lean`,
`DKSAPOracle.lean`) transfer to schemeId 3's derivation already.

## Notes

- Our upstream item 5 (`kem_ind_cpa_security`) and item 6 (un-sorry) in
  `vcvio-upstream.md` are now superseded by #785 — update that file when this lands.
- The maintainer conversation covers: downstream stability of `Extern/MLKEM`,
  the #785 roadmap, the ANO-CCA PR offer (G2), and `FFI.Hashing` as public API (G5).
- Model review before filing the G2 PR: Kimi + GLM cross-check of statements and
  proofs, per the agreed process; local `lake build` is unavailable on this machine
  (Pi, 7 GB), so machine-checking happens in CI once a fork branch is pushed.
