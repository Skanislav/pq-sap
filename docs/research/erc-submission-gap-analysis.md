# ERC submission gap analysis — what ethereum/ERCs requires, what we have, what we will contribute

*2026-08-07. Model: [ethereum/ERCs PR #1932](https://github.com/ethereum/ERCs/pull/1932) (ERC-8373, "Post-Quantum Anchored Key-Binding"), a current PQ-topic submission with all 9 CI checks green. Sources: PR metadata and file list via `gh`, raw `erc-8373.md` from the PR branch, ethereum/ERCs repo root listing, README, `erc-template.md`, the rendered EIP-5564 page, and `gh pr checks 1932`.*

**Settled decisions (this session):** deliverable for now is this report only; the future in-assets checker takes the vectors-with-intermediates + stdlib-Python approach; the scheme ID we declare is **`2`** (monotonic, per ERC-5564's own recommendation), replacing the `0x5567` placeholder.

---

## 1. The model: anatomy of PR #1932

ERC-8373 migrates on-chain/agent identity signatures to PQ via an anchored classical→PQ key binding plus a consumer-enforced cutoff. Its *shape* is what matters to us:

**Spec file** — `ERCS/erc-8373.md`, 138 lines. Complete preamble: assigned number, ≤44-char title, one-sentence description, four authors all with GitHub handles, `discussions-to` pointing at a live Ethereum Magicians thread, `status: Draft`, `type: Standards Track`, `category: ERC`, `created` date. Sections in template order: Abstract, Motivation, Specification (RFC 2119/8174 boilerplate, definitions table, normative field tables), Rationale, Backwards Compatibility, Test Cases, Reference Implementation, Security Considerations, Copyright (CC0). Cross-references are relative only (`[ERC-8004](./eip-8004.md)`, `[EIP-712](./eip-712.md)`, `../LICENSE.md`). External standards (FIPS 204/205, RFC 8785) are cited by name in prose, never linked.

**Assets** — `assets/erc-8373/`, 11 files, ~1,300 added lines total:

| File | Lines | Role |
|---|---|---|
| `pq-key-binding-v0.spec.md` | 146 | byte-level companion profile (canonicalization, content-address rules) |
| `pq-key-binding-v0.vectors.json` | 106 | binding-statement vectors — two independent implementations, two NIST families (ML-DSA-65, SLH-DSA-SHA2-192s), byte-compatible content-addresses |
| `pq-key-binding-v0.cutoff-vectors.json` | 62 | admit / reject / unverifiable cases |
| `pq-key-binding-v0.rotation{,-vectors}.json` | 30+48 | rotation chain + vectors |
| `pq-key-binding-v0.revocation{,-vectors}.json` | 29+45 | revocation record + vectors |
| `pq-key-binding-v0.per-agent-anchor.json` | 38 | anchor examples |
| `recovery-classes-vectors.json` | 594 | recovery-class suite |
| `cutoff_enforce.py` | 109 | **stdlib-Python executable checker** for the cutoff rule |
| `recovery_check.py` | 119 | **stdlib-Python executable checker** for recovery classes |

Notable properties we should mirror:

- **Vectors are grouped by behavior class**, each stating public inputs and the expected verdict; "conformance is exact reproduction".
- **Checkers are dependency-free** (stdlib Python) — reviewers run them with nothing installed. 8373 gets this cheaply because its crypto is just SHA-256 over canonical JSON; ours needs a deliberate design (§5).
- **Two independent implementations converging byte-for-byte** is presented as the credibility anchor. We already have exactly this: the TypeScript client reproduces the Python vectors byte-identically.
- The PR body itself is short: what it is, the one central design decision, discussion link, implementations, authorship confirmation.

## 2. What the ethereum/ERCs repo requires

- **Process order:** ideas MUST be discussed on Ethereum Magicians (or Ethereum Research) *before* the PR; `discussions-to` must point at that thread. EIP-1 governs the format; `erc-template.md` in the repo root is the skeleton.
- **Layout:** `ERCS/erc-<n>.md`; supporting material in `assets/erc-<n>/`, referenced from the spec as `../assets/erc-<n>/<file>`.
- **Numbering:** no formal registry or reservation step; current practice is that the author picks the next unused number (8373 sits in the live ~83xx range — consistent with EIP-8304 in our WG). Editors may reassign; the ERC number ≠ PR number (8373 came in PR 1932).
- **CI gauntlet** (all must pass): **EIP Walidator** (eipw — preamble fields, title/description limits, section order), **HTMLProofer** and **Link Check** (every link must resolve; external links are effectively prohibited — relative links to other EIPs/ERCs and to assets only), **Markdown Linter**, **CodeSpell**, **GitGuardian** (no secrets). Plus label/PR-number bookkeeping actions.
- **Template constraints:** title ≤ 44 characters and no standard numbers in it; description one full sentence; authors as `Name (@github-handle)` or `Name <email>` (at least one handle-bearing author is expected for editor pings); `requires` listing every EIP referenced in the Specification; Copyright = CC0 via `../LICENSE.md`.
- **License:** everything (spec + assets) is CC0 — publishing the vectors and checker waives rights.

## 3. Fix list for our current draft (`docs/erc-draft.md`)

The draft is structurally sound (correct section order, RFC 2119 boilerplate, relative `./eip-5564.md`-style links, CC0 footer, `requires: 5564, 6538`). What fails the gauntlet today:

1. **Title** — "Post-Quantum Stealth Addresses (ML-KEM scheme for ERC-5564)" is 60 chars **and** contains a standard number; both are walidator violations. Fix: `title: Post-Quantum Stealth Addresses` (31 chars); the ML-KEM/5564 detail already lives in the description.
2. **Author** — `Skas Merkushin <skas.merkushin@gmail.com>` is legal but handle-less; should become `Skas Merkushin (@<handle>)` (handle TBD — user to provide).
3. **`discussions-to: TBD`** — hard blocker; the magicians thread must exist first (user action, §6).
4. **`eip: TBD`** — pick the next unused number at PR time (check the ERCS/ dir and open PRs the same day).
5. **Test Cases section** — currently "published with the reference implementation"; must instead reference `../assets/erc-<n>/` files. External-repo pointers belong in the magicians thread, not the spec.
6. **Reference Implementation section** — same: describe what exists, link only assets. The Python/TS/Lean repo gets named in prose at most, linked from the discussion thread.
7. **Scheme ID** — replace the `0x5567` placeholder with the declared mapping **`schemeId = 2` → this ERC**. ERC-5564 has no registry mechanism; it requires exactly that "a mapping from the schemeId to its specification MUST be declared in the ERC" and recommends monotonically incrementing IDs (SECP256K1 = 1 is the only assigned ID). The reference implementation and vectors must be regenerated with `2` once adopted (vectors currently bake the placeholder only insofar as docs mention it — the vectors JSON itself carries no scheme ID field; verify at package time).

## 4. Gap table: what we have vs. what the package needs

| Package piece (8373 analogue) | Ours today | Status |
|---|---|---|
| `ERCS/erc-<n>.md` | `docs/erc-draft.md`, 160 lines | ✓ needs §3 fixes |
| Magicians thread (`discussions-to`) | none | ✗ **user action** |
| Assigned number | `TBD` | ✗ pick at PR time |
| Conformance vectors in assets | `python/vectors/v0/vectors.json` — 7 cases (2 positive incl. unlinkability of a second payment, 4 negative: wrong view tag / wrong recipient / truncated ct / bit-flipped ct, 1 possession proof), 61 KB, deterministic, byte-identical regeneration | ✓ copy in; size comparable to 8373's suite |
| Independent-implementation convergence | TS client replays vectors byte-for-byte (its own credibility line for the PR body) | ✓ exists |
| Stdlib executable checker(s) | none — our pytest suite needs kyber-py/dilithium-py | ✗ **the main build item** (§5) |
| Vector intermediates enabling a stdlib checker | absent — cases expose only announcement-level data (no shared secret, no derivation seeds, `stealth_pk` on one case only) | ✗ additive vectors change |
| Byte-level companion spec in assets | material exists in private `docs/TECHNICAL_SPEC.md` | optional; publication decision (§6) |
| PR body | — | write at PR time; 8373's is the template |

## 5. The planned contribution (settled design, future work)

- **`ERCS/erc-<n>.md`** — the draft with §3 fixes applied.
- **`assets/erc-<n>/vectors.json`** — the v0 vectors extended **additively** with an `intermediates` object per case: the encapsulated shared secret `ss`, the SHAKE256-derived `(s', e')` seed material, and `stealth_pk` for every positive case. Change lands in `python/vectors/generate_vectors.py`; determinism is preserved (additive fields, same seeds), but the file is no longer byte-identical to the committed v0 — bump the schema tag (`v0` → `v1` or `v0+intermediates`) and keep the TS replay green.
- **`assets/erc-<n>/check_vectors.py`** — dependency-free checker (stdlib + a ~60-line vendored pure-Python keccak-256, which is not in `hashlib`): verifies sizes and encodings (meta-address version byte and field lengths, announcement layout), view tags = SHA-256(ss)[0:1], the SHAKE256 derivation chain from `ss` (`hashlib.shake_256` is stdlib), stealth address = keccak256(stealth_pk)[12:32], and the expected verdicts on all negative cases that are checkable without decapsulation. **Explicitly out of scope:** the lattice algebra (ML-KEM decaps, the blinding `t' = A·s' + e' + t`) — stated in the checker's docstring as covered by the two reference implementations. This mirrors 8373's honesty about what recomputation covers.
- **Optional companion spec** — a byte-level packing profile (pack23 bit order, blinded-sk persistence format, M′ formatting) extracted from TECHNICAL_SPEC.md, if cleared for publication.

## 6. Prerequisites that are user actions

1. **Open the Ethereum Magicians thread** (the 8373 pattern: title stating the mechanism, first post ≈ the Abstract + Motivation + link to vectors). Must precede the PR; its URL becomes `discussions-to`.
2. **GitHub handle** for the author line.
3. **Publication clearance:** everything entering `assets/` becomes public CC0 — decide whether the companion spec (TECHNICAL_SPEC extract) ships in v1 of the PR or later. The vectors and checker themselves contain only test-seed-derived data (seeds are `0xa1a1…`-style constants) and are safe to publish.

## 7. Effort estimation

| Item | Estimate |
|---|---|
| Draft fixes (§3) | ~½ day |
| Vectors intermediates + regeneration + TS replay re-verified | ~½ day |
| Stdlib checker incl. vendored keccak + negative-case handling | ~1 day |
| Companion spec extraction (if cleared) | ~½–1 day |
| Magicians thread draft, number pick, fork/branch/PR mechanics, local eipw run | ~½ day |
| **Total** | **≈ 3–4 working days**, dominated by the checker |

Local pre-flight before the PR: run eipw against the adapted markdown (walidator is the pickiest gate), run `check_vectors.py` clean, and click-check every relative link.
