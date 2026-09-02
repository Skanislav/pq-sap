# Repository Guidelines

Guidance for AI coding assistants working in this repository. Everything here is
grounded in the configs, scripts, and docs of the repo — when in doubt, trust the
cited file.

## Project Overview

Post-quantum stealth addresses for Ethereum, registered as a new
[ERC-5564](https://eips.ethereum.org/EIPS/eip-5564) scheme ID (target ID `2`), working
against deployed ERC-5564/ERC-6538 contracts with no protocol changes.

- **Detection** (priority — "harvest now, decrypt later"): ML-KEM-768 (FIPS 203).
  The announcement's ephemeral key is a KEM ciphertext; the shared secret drives a
  one-byte view tag and the address derivation.
- **Spending**: ML-DSA-65 (FIPS 204) key **additively blinded** by values derived from
  the shared secret ("construction A" — see `docs/DECISIONS.md` D-003). Sender computes
  the recipient's one-time address without learning any secret; signatures verify under
  stock FIPS 204 verifiers with a widened bound `β' = τ·2η`. Interim spend routes:
  ERC-4337 / ERC-7913; target route: EIP-8141 frame transactions (D-020). A
  linkable-but-cheap SPHINCS-C13 ERC-7913 alternative exists in `js-client/` (D-018).

Design status: spec, ADR log, vectors, reference library, TS client, Lean core, and demo
UI all exist. Remaining: security write-up, community review, ERC text freeze. Do not
treat drafts as frozen.

## Architecture & Data Flow

**Python is the source of truth.** Every other implementation mirrors its byte-level
behavior; Lean proves the abstract algorithm; Solidity verifies on-chain; the wiki only
mirrors docs.

```
docs/*.md ──(wiki/scripts/sync.mjs)──> wiki/src/pages/** (generated, never hand-edited)

Recipient: gen_meta_address()  →  meta-address  = version(1) ‖ rho(32) ‖ pack23(t)(4,416) ‖ ML-KEM ek(1,184)  ≈ 5,633 B
Sender:    decode → ML-KEM-768.encaps(ek) → (ss, ct 1,088 B)
           → derive_stealth_pk(rho, t, ss) → (stealth_pk, t0) → keccak256(stealth_pk)[12:] = stealth address
           → view_tag = SHA-256(ss)[0] → announce(SCHEME_ID, addr, ct, view_tag)
Scan:      decaps(dk, ct) → ss → view-tag compare (cheap reject) → re-derive → address match → Payment
Spend:     derive_blinding(ss) → (s′, e′) → widened key (s1+s′, s2+e′, t0) → ML-DSA sign (β′ = 2τη)
           → ERC-4337 UserOp / ERC-7913 / EIP-8141 frame tx
```

| Layer | Path | Role |
| --- | --- | --- |
| Reference spec | `python/pq_stealth/` | Canonical algorithms + deterministic vector generator |
| TS client | `js-client/src/scheme.ts`, `mldsa65.ts`, `spend.ts`, `frame-tx/` | Byte-identical port; hand-written ML-DSA-65 polynomial layer |
| Demo UI | `ui/src/lib/` (`keygen.ts`, `scan-worker.ts`, `spend4337.ts`, `frames.ts`) | React app over the js-client scheme; scanning in a web worker |
| Proofs | `lean/PqStealth/` (`Blinding.lean`, `Invariants.lean`, `Games.lean`, `ConstructionA.lean`, `MLKEM.lean`, `DKSAP.lean`, …) | Lean 4 / VCVio: blinding identity, widened bound, unlinkability games, DKSAP break |
| On-chain | `js-client/contracts/src/*.sol` + vendored ZKNOX verifier | ERC-7913 accounts, registry, announcer, SSTORE2 key storage |
| ZK PoC | `noir/pq-stealth-ownership/src/main.nr` | Standalone MLWE-relation ownership proof (not wired into spend path) |
| Rust baseline | `pq-sap/` | **Third-party** reference clone (0x3327/pq-sap) — read-only context |
| Solidity verifier | `ETHDILITHIUM/` | **Third-party** ZKNOX clone, vendored into `js-client/contracts/lib/ETHDILITHIUM` at rev `df999ed` |

Key module callouts:

- `python/pq_stealth/__init__.py` — the entire public API (`send`, `scan`,
  `derive_blinding`, `sign_blinded`, `prove_possession`, encoders). Every randomized
  step accepts optional seeds (`zeta`, `kem_d`, `kem_z`) so vectors reproduce.
- `js-client/src/mldsa65.ts` — minimal ML-DSA-65 layer (NTT, `expandA`, `power2roundT1`,
  `packPk`); validated only against the Python vectors.
- Blinded signing is **not** done in TS: `js-client/src/spend.ts` and
  `ui/scripts/signer-service.mjs` shell out to Python
  (`python/scripts/spendable_helper.py`), which wraps the ZKNOX level-2 profile.

## Key Directories

| Directory | Purpose |
| --- | --- |
| `docs/` | Specs and decisions: `TECHNICAL_SPEC.md`, `erc-draft.md` (pre-freeze), `DECISIONS.md` (ADR log D-001–D-020 — read before changing scheme behavior), `SECURITY_ANALYSIS.md`, `research/` |
| `python/` | Executable spec, conformance vectors (`python/vectors/v0/`, `vectors/classical/v0/`), benchmarks, scripts that generate fixtures for TS tests |
| `js-client/` | TS scanning client, Foundry contracts (`js-client/contracts/`), anvil/fork e2e tests, devnet config |
| `ui/` | Vite + React demo (receive/send/scan/spend/frames), dev-chain bootstrapping, signer service |
| `lean/` | Lean 4 package `PqStealth` on pinned VCVio; `lean/docs/` design essays, `lean/docs-proofs/` generated |
| `wiki/` | Vocs site mirroring `docs/` + `lean/docs/`; everything under `wiki/src/pages/` is generated |
| `noir/` | Noir ZK ownership-proof PoC |
| `pq-sap/`, `ETHDILITHIUM/` | Third-party clones, gitignored at root — do not treat as project code to modify |
| `docs-review-ws/` | Doc-review scratch workspace, not a buildable subproject |

## Development Commands

Run these from the subproject directory unless noted.

```sh
# python/  (Python ≥3.10, pip)
pip install -e ".[dev]"          # add ",audit" for liboqs cross-check, ",bench" for coincurve
pytest -q                       # full suite (~18 tests)
ruff check .
python vectors/generate_vectors.py            # MUST be byte-identical to committed vectors/v0/vectors.json
python vectors/generate_classical_vectors.py  # same for vectors/classical/v0/vectors.json

# js-client/  (Node ≥26, npm)
nvm use && npm install
npm run typecheck               # tsc; "lint" is also just tsc
npm test                        # replays ../python/vectors/v0 — byte-for-byte
npm run build-contracts         # forge build --root contracts (needs Foundry)
npm run e2e                     # anvil-backed e2e (auto-boots anvil via test/util/anvil.ts)
npm run e2e-7913 | e2e-7913-classical | e2e-7913-sphincs | e2e-pointer-sig
npm run e2e:fork                # offline Sepolia fork replay; e2e:fork:record to re-record

# ui/  (Node ≥22.12, npm; needs ../js-client npm-installed)
npm install
npm run chain                   # terminal 1: anvil + deployments + seeded payments + signer service
npm run dev                     # terminal 2: Vite dev server
npm run signer                  # blinded-key signing service on 127.0.0.1:8546
npm run e2e | e2e:sepolia-fork | e2e:frames-pq | check-keygen | typecheck
SEPOLIA_DEPLOYER_KEY=0x… npm run deploy:sepolia    # live deployments need env keys

# lean/  (Lean 4 v4.32.0 via elan)
lake exe cache get              # mathlib oleans (~8.6k files) — first time only
lake build                      # full build incl. axiom audit
python3 scripts/check_citations.py   # doc citations resolve to real declarations
python3 scripts/check_sizes.py       # proved byte sizes match python/vectors

# wiki/  (Node 22, pnpm 10 — NOT npm)
pnpm install
pnpm dev | pnpm build           # both run "pnpm sync" first (generates pages/sidebar)
pnpm lint                       # biome; pnpm typecheck

# noir/pq-stealth-ownership/
python3 generate_prover.py 8 2 2 8   # toy params N=8,K=2,L=2 (full ML-DSA-65 needs ~15 GB)
nargo execute && bb prove …          # see noir/README.md

# ETHDILITHIUM/ (third-party, for reference/benchmarks)
make test          # FOUNDRY_PROFILE=lite forge test + pythonref unittest
make bench
```

CI (`.github/workflows/ci.yml`, `lean.yml`) runs: ruff + pytest + vector `cmp` (also in
Docker/liboqs), js-client typecheck/test/all e2e, wiki `pnpm lint`/`typecheck`/`build`,
noir toy proof, and `lake build` with **zero sorries/warnings** in `PqStealth/` plus both
Python checker scripts. If your change is in one of those areas, CI is the bar.

## Code Conventions & Common Patterns

**Cross-language naming.** The same crypto names recur everywhere — keep them:
`rho`, `t`, `t0`, `s1`/`s2`, `s′`/`e′` (often `s1p`/`e1p` in code), `viewTag`,
`stealthAddress`, `metaAddress`, `ephemeralPubKey`. Renaming these breaks the
spec-to-proof-to-impl correspondence.

- **Python** (`pq_stealth/`): snake_case, plain functions over dataclasses
  (`Announcement`, `Payment`, `ParamSet`), module docstrings carry cryptographic
  rationale — keep them. Errors: `None` for non-matching announcements, exceptions for
  caller misuse. Never hand-roll crypto: ML-KEM/ML-DSA delegate to `kyber_py` /
  `dilithium_py`; the protocol layer is ours.
- **TypeScript**: camelCase, `UPPER_SNAKE_CASE` constants, React components PascalCase.
  Node runs `.ts` directly (native type stripping) — no bundler for js-client tests;
  `strict` + `verbatimModuleSyntax` + `erasableSyntaxOnly` (js-client). Errors:
  exceptions + nullable returns (`checkAnnouncement → Payment | null`). Heavy async via
  viem clients; no DI framework — callers pass `PublicClient`/`WalletClient`/chain
  config explicitly. UI state: `useState`/`useEffect` hooks, wallet/network injected via
  `ui/src/lib/chain.ts` + `useWallet.ts`.
- **Lean** (`PqStealth/`): Mathlib-style theorem names, `UpperCamelCase` structures.
  **`simp only [...]` with explicit lists — no bare `simp`** (project policy, so an
  upstream rename fails by name). Never `set_option linter.* false` (only documented
  exception: `unicodeLinter`). Full cutover, no compat shims. Before any Lean work, read
  `.claude/skills/vcvio/SKILL.md` and `lean/docs/vcvio-pin.md`; the pinned VCVio is at
  `lean/.lake/packages/VCVio/`.
- **Solidity**: PascalCase contracts, custom errors (`error UnknownVersion()`), SSTORE2
  for bulky keys, assembly in hot paths (allowed — gas is the point). Constants
  `SCREAMING_SNAKE_CASE`.
- **Rust** (`pq-sap/` only, third-party): `Result<_, Box<dyn Error>>`; scanner skips
  malformed entries rather than aborting.

**Hard technical invariants** (from `docs/DECISIONS.md`):
- No arithmetization-oriented hashes (Poseidon etc.) anywhere — SHA-256 normative,
  SHAKE256 for KEM internals, BLAKE3 permitted internally (D-015).
- Standard hashes and FIPS 203/204 operations only; no rolled crypto (bind to audited
  libs, cross-check against `liboqs`).
- X-Wing decap key only ever stored/exchanged as the 32-byte seed (D-017).
- Keys never go in initcode — key/pointer lives in account state (D-020).
- Vectors are deterministic; regenerating them must be byte-identical or you broke the
  spec.

## Important Files

| File | Why it matters |
| --- | --- |
| `docs/DECISIONS.md` | ADR log (D-001–D-020). Read the relevant entry before changing scheme behavior; add an entry when a decision changes |
| `docs/TECHNICAL_SPEC.md`, `docs/erc-draft.md` | Working spec / ERC text (pre-freeze) |
| `python/pq_stealth/__init__.py` | Public API surface; the porting contract |
| `python/vectors/v0/vectors.json` | Conformance vectors consumed by pytest, js-client tests, ui e2e, and `lean/scripts/check_sizes.py` — the cross-language glue |
| `python/scripts/spendable_helper.py` | Blinded-key signer backing both TS spend paths |
| `js-client/src/scheme.ts` | Core TS scheme — mirror of the Python spec |
| `js-client/src/mldsa65.ts` | Hand-written ML-DSA-65 polynomial layer (validate against vectors, don't extend casually) |
| `js-client/contracts/foundry.toml` | solc 0.8.30, `evm_version prague`; SPHINCS path forced `via_ir`, 200 runs |
| `lean/PqStealth.lean` | Root import of the proof development |
| `lean/PqStealth/Axioms.lean` | `#guard_msgs #print axioms` audit — any new `sorry`/axiom in the cone is a **build error**. Never bypass |
| `lean/lakefile.toml`, `lean/lean-toolchain` | VCVio pin `a5f474fd`, Lean v4.32.0 — never `lake update` casually |
| `ui/src/App.tsx`, `ui/src/lib/chain.ts` | UI entry; network configs (anvil/Sepolia/frames) |
| `wiki/scripts/sync.mjs` | Doc mirroring; everything it generates is gitignored |

## Runtime/Tooling Preferences

| Subproject | Manager | Runtime / version pins |
| --- | --- | --- |
| `python/` | pip + setuptools | Python ≥3.10; ruff `line-length 88`, `target py310`, rules `E,F,I,RUF` |
| `js-client/` | **npm** | Node ≥26 (`.nvmrc`); TS 7; Foundry v1.4.1 (CI), solc 0.8.30 |
| `ui/` | **npm** | Node ≥22.12; Vite 7, React 19; no linter configured |
| `wiki/` | **pnpm 10.0.0** (never npm here) | Node 22 (`.nvmrc`); Vocs 2 / Vite 8; Biome 2.5.11, line width 120 |
| `lean/` | lake / elan | Lean `v4.32.0`; `autoImplicit = false`; deps pinned, manifest frozen |
| `noir/` | nargo + bb | Noir ≥1.0.0; CI runs toy params only (~15 GB for full circuit) |

Constraints an assistant must respect:

- Use each subproject's own package manager — mixing pnpm into `ui`/`js-client` or npm
  into `wiki` corrupts lockfiles.
- `.env` files are gitignored and hold real keys (`SEPOLIA_*`, `FRAMES_*`, `PINATA_JWT`).
  Never commit secrets; never print key material into logs, tests, or vectors.
- `pq-sap/` and `ETHDILITHIUM/` are third-party clones (root `.gitignore`). Modify
  project code in `python/`, `js-client/`, `ui/`, `lean/`, `wiki/`, `noir/`, `docs/`
  instead. The vendored verifier lives at `js-client/contracts/lib/ETHDILITHIUM`
  (rev `df999ed`, gitignored — restored via `git clone --recurse-submodules`, see
  `js-client/README.md`).
- Wiki pages under `wiki/src/pages/` and `lean/docs-proofs/` are generated — edit the
  source doc, then `pnpm sync`.
- Lean cold builds take hours (VCVio compiles from source; only mathlib is cached).
  `lake build <target>` before trusting a phantom LSP error.
- Licensing: no GPL/copyleft in the hot path; keep new runtime deps permissive.
- Authorship: humans are the authors of project-facing specs; do not add AI
  attribution/co-author lines. The repo already discloses AI assistance at repo level.
- **House rule**: prepare changes locally, show the diff, and get an explicit OK before
  any commit/push/PR — here or upstream.

## Testing & QA

No coverage tooling anywhere — quality is enforced structurally. Match these patterns
in new work:

- **Conformance vectors are the contract.** Python generates deterministic JSON
  (including negative cases: wrong view tag, wrong recipient, truncated/bit-flipped
  ciphertext, tampered address); js-client/ui replay them byte-identically;
  `lean/scripts/check_sizes.py` checks proved byte sizes against them. Changing the
  scheme means regenerating vectors and updating every consumer.
- **Cross-implementation checks**: Python `test_signing.py` validates blinded ML-DSA
  signatures against `liboqs` (`oqs.Signature("ML-DSA-65")`); Solidity tests are
  regenerated from Python KAT generators (`ETHDILITHIUM/pythonref/dilithium_py/generate_*.py`).
- **Fork e2e determinism**: Sepolia fork tests record/replay RPC through
  `js-client/scripts/rpc-proxy.mjs` (`FORK_RECORD=1` to re-record) so CI is offline.
- **Property/fuzz**: `pq-sap/` (third-party) uses proptest + cargo-fuzz with a committed
  seed corpus — replicate that style for any Rust protocol code.
- **Lean**: no test suite; `Axioms.lean` (axiom audit), `Demo.lean` (`#eval` behind
  `#guard_msgs`), and the no-sorry/no-warning CI assertion are the ratchet. A new
  theorem with a hypothesis bundle needs an inhabitance witness so the audit stays
  honest.
- **Skip cleanly when optional deps are absent**: `pytest.importorskip("coincurve")`
  pattern for classical benches; don't hard-require optional extras.