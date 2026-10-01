# Composing the scheme-2 spec into ethereum/ERCs, and where Lean evidence can live

Reviewed 2026-10-29 against `ethereum/ERCs` master `4878022` (626 `ERCS/*.md`,
221 `assets/erc-*` directories) and `ethereum/EIPs` master. This note records a
survey and a submission plan. It does not write the ERC text: under
[D-024](../DECISIONS.md) that stays human-written, and the local draft stays
empty.

## Verdict

1. `ethereum/ERCs` contains **no Lean and no formal-method artifact of any
   kind**, now or at any point in its history. The single occurrence of the
   word "Lean" in the repository is a citation title in
   `ERCS/erc-7573.md`: *"A Proposal for a Lean and Functional Delivery versus
   Payment across two Blockchains"* (SSRN `10.2139/ssrn.4628811`) — where
   "Lean" is the software-engineering adjective, not the proof assistant.
2. The nearest real precedent lives in `ethereum/EIPs`, not `ERCs`:
   EIP-8450 (leanXMSS) states *"specified and implemented in the leanVM
   repository, with a Lean 4 proof of its classical security"* in prose, ships
   no artifact, and adds *"That target is not a proved bound."* EIP-8222 ("Lean
   Staking") is about the leanVM proving system; also prose only.
3. Consequence for us: Lean evidence is admissible as **prose plus a citation
   object**, not as a vendored proof development. The ERC CI never builds
   anything in `assets/`, and its link linter rejects every external URL, so a
   vendored Lean tree would be unverified by CI, unbuildable for most
   reviewers, and would need a CC0 relicensing of the copies.

## What the gate actually enforces (measured, not quoted)

Local eipw (`eipw-lint-js` 0.11.0, run with the repository's own
`config/eipw.toml`), plus markdownlint and codespell with the ERC configs:

| Probe | Result |
| --- | --- |
| Extra H2 (`## Formal verification`) | `error[markdown-order-section]: body has extra section(s)` |
| External link to a GitHub blob URL | `error[markdown-rel-links]: non-relative link or image` |
| Missing `## Rationale` | `error[markdown-req-section]: body is missing section(s)` |
| `csl-json` footnote without `DOI` | `error[markdown-json-cite]: "DOI" is a required property` |
| `csl-json` footnote, `"type": "software"`, DOI + URL | **0 reports** |
| `../assets/eip-N/vectors/x.json` link inside `ERCS/*.md` | **0 reports** |
| `markdownlint-cli2` 0.18.1 + `config/.markdownlint.yaml` on `erc-8441.md` | 0 errors (MD013 off); the CI job does not cover this path at all |
| `codespell` 2.4.3 + `config/.codespell-whitelist` on `lean/PqStealth/*.lean` | 4 hits: `FO` ×1, `hEnc` ×3 |

Rules that follow directly:

- **Sections.** H2 set must be a subset of the template's nine
  (Abstract, Motivation, Specification, Rationale, Backwards Compatibility,
  Test Cases, Reference Implementation, Security Considerations, Copyright).
  Every extra topic — proof scope, profile selection, deployment binding — must
  be an **H3 inside `## Specification` or `## Security Considerations`**, never
  a new H2.
- **Links.** No external URLs except the allowlisted standards bodies. Internal
  references use `./eip-5564.md`; assets use `../assets/eip-N/...` **with the
  `eip-` prefix even in the ERCs repo** — the site build renames
  `assets/erc-N/` to `assets/eip-N/` during the EIPs merge, and `ERCS/*.md`
  contains 687 such links and zero `../assets/erc-` ones. On GitHub the
  `eip-` form 404s; in the rendered site it is the only form that resolves.
- **One legal external pointer.** A `csl-json` footnote with `DOI` and `URL`
  is the sole mechanism that passes the linter and still resolves to something
  outside the repository. `"type": "software"` is accepted.
- **The `markdownlint` job never sees `ERCS/`.** Its changed-file filter is
  `grep -E -x '[^/]+\.md|EIPS/eip-[0-9]+\.md'`, which matches only
  slash-free paths, so `ERCS/erc-N.md` and everything under `assets/` fall
  outside it. Markdown in `assets/` is still rendered as freestanding markdown,
  where MD041 wants a `#` H1 on line 1 — a Jekyll display rule, not a lint the
  PR will be failed on.
- **codespell** runs over every changed file whose name is not in its skip list;
  `.lean` is not skipped, and an inline `codespell:ignore` comment does not
  suppress a hit inside `.lean` (verified; a whitelist entry does). Our tree
  would need `FO` and `hEnc` handled before any Lean source could ship.
- **CI jobs:** `save-pr`, `htmlproofer`, `link-check`, `codespell`,
  `eipw-validator`, `markdownlint` (+ GitGuardian and label bots).
  `htmlproofer` does follow `assets/` links in the built site (its incremental
  path is disabled for any non-`ERCS/erc-*.md` change). Nothing runs `lake`,
  `forge`, or `npm` over `assets/`.

## Precedent to copy: ERC-8441 (merged 2026-10-29)

`ethereum/ERCs#2059` merged as `4878022`, three files: `ERCS/erc-8441.md` (735
lines) and two vector JSONs under `assets/erc-8441/vectors/`. All CI checks
green; the only change outside `ERCS/`+`assets/` contemplated was a
`config/.codespell-whitelist` entry for the author's first name. Its shape is
the one to mirror for our scheme ID:

- a comparison table of scheme 1 vs 3 sizes and gas in `## Specification`;
- vectors split per spec section, each row carrying `claim` / `given` /
  `expect` / `wrong` (the wrong output it distinguishes);
- an explicit `## Backwards Compatibility` paragraph declaring the deviation
  from ERC-5564's `n`/`2n` meta-address length rule;
- `## Security Considerations` opening with a "what this protects and does not
  protect" list.

Two review threads from that PR apply directly to us:

- SergeevDmitry: changing the combiner later changes the view tag and the
  derived address, so a replacement needs a **new scheme ID**, not an update.
  Our derivations must be frozen inside scheme 2 for the same reason.
- The maintainer's reply rejects EIP-8141/8288/8355 dependencies for now —
  supporting evidence for keeping spending out of our normative text.

## Composition plan for our spec

### Identifier

`schemeId` **2** is still unclaimed. The merged corpus declares only 1
(`erc-5564`) and 3 (`erc-8441`); a grep over all 323 open PR heads found no
`schemeId 2` claim; no Ethereum Magicians thread uses that identifier.
ERC-5564 recommends monotonic IDs, so 2 is both free and consistent.

A claim under 323 open PRs is only as good as the last fetch, so the text must
still re-check at PR time — but nothing else in this plan depends on the number.

### Files

| Path | Content | Source |
| --- | --- | --- |
| `ERCS/erc-<n>.md` | Human-written text; H3s for profile table, deployment binding, wire format | author |
| `assets/erc-<n>/vectors/commit.json` | Commitment-format vectors | [`python/vectors/v0/commit_vectors.json`](../../python/vectors/v0/commit_vectors.json) |
| `assets/erc-<n>/vectors/mldsa44.json` | Optional: ML-DSA-44 profile vectors | [`mldsa44_commit_vectors.json`](../../python/vectors/v0/mldsa44_commit_vectors.json) |
| `assets/erc-<n>/profile-v0.md` | Byte-level profile: domains, lengths, CREATE2 binding | [`TECHNICAL_SPEC.md`](../TECHNICAL_SPEC.md) §2–§4 |
| `assets/erc-<n>/check.py` | Dependency-free checker (stdlib + vendored keccak-256) | planned, see [gap analysis](erc-submission-gap-analysis.md) §5 |
| `assets/erc-<n>/lean/` | Optional: the dependency-free model only, 4 files / 765 lines | [`js-client/contracts/lean/`](../../js-client/contracts/lean) |
| `assets/erc-<n>/EVIDENCE.md` | Claim → declaration → file → assumption table | [`ERC_EVIDENCE.md`](../ERC_EVIDENCE.md) condensed |

### Methods ERC-5564 requires us to define

ERC-5564: *"The specification of a new stealth address scheme MUST specify the
implementation for each of these methods"* (`generateStealthAddress`,
`checkStealthAddress`, `computeStealthKey`). ERC-8441 could honor all three
because spending stays ECDSA. Our commitment flow cannot, and the text has to
say so rather than silently omit:

| Method | Our answer |
| --- | --- |
| `generateStealthAddress(meta)` | Sender side of [`commit.py`](../../python/pq_stealth/commit.py) `send_commit`: encapsulate `kem_ek`, derive opener and commitment, return the account address and `ct` as `ephemeralPubKey` |
| `checkStealthAddress(addr, epk, ...)` | Scanner side: decapsulate, compare the tag, re-derive the commitment and address **with the profile's deployment binding**; returns `false` only for a mismatch, fails on malformed keys |
| `computeStealthKey(...)` | **Not applicable**: there is no stealth private key. Spending is the account profile's authorization (D-027), so the text must state the method is undefined for scheme 2 and that its absence is what makes spending swappable |

Other deviations to declare in `## Backwards Compatibility`, mirroring 8441:

- meta-address is 1,217 B (`0x02 || spend_key(32) || ek(1184)`), not `n` or `2n`;
- `ephemeralPubKey` is the ML-KEM ciphertext alone (1,088 B), and the view tag
  is `SHA-256(ss)[0:1]` — the opener and tag hash `ss` only, with no transcript
  binding (D-029's recorded open obligation);
- the address is a CREATE2 account, not `keccak256(pubkey)[12:]`, so the
  deployment binding is part of the scheme, not an implementation detail.

### Where the Lean work attaches

Three routes, in increasing cost:

1. **Prose + revision hash** (EIP-8450 precedent). Under `## Security
   Considerations`, an H3 naming the game, the proved declarations, and the
   named residual assumptions, with the repository revision in backticks. No
   artifact, no CI cost, no relicensing. Reviewers fetch by hash.
2. **`csl-json` software citation.** Archive the proof tree to get a DOI, then a
   footnote with `"type": "software"`, `DOI`, `URL`, `version`. Verified to pass
   eipw with the repository's own config. Choose the archive licence
   deliberately; the citation is not a vendored file, but the archived copy is
   public.
3. **Vendor the dependency-free model only.** `js-client/contracts/lean/` is
   765 lines, no dependencies, and builds in 3.8 s here (`lake build`, 7 jobs) —
   fast enough that a reviewer on a laptop can replay it, unlike the 25-module,
   7,535-line `lean/PqStealth/` development, which needs VCVio plus mathlib's
   ~8.6k oleans (per [`lean/docs/tooling.md`](../../lean/docs/tooling.md)). It would ship as sources plus a `README.md` with the exact
   pin and the axiom-audit transcript; ERC CI would not build it, so the text
   must not imply that it does, and `FO`/`hEnc` need renaming or a whitelist
   entry first.

Do not ship `lean/PqStealth/` under `assets/`. It is unreplayable in a reviewer
environment, and per-file CC0 relicensing would need an explicit human decision.

## Human decisions this plan waits on

1. Ethereum Magicians thread (none exists for scheme 2) — it is a hard blocker,
   since `discussions-to` must point at a live thread.
2. ERC number at PR time; `schemeId 2` is free but a same-day check is cheap.
3. Whether the profile spec and the checker ship in the first PR or later.
4. CC0 relicensing of every file placed under `assets/` (this repository is
   MIT).
5. Lean evidence route 1, 2, or 3, and if 2, the archive.

## Reproduction

```sh
# survey
git clone --filter=blob:none --no-checkout https://github.com/ethereum/ERCs.git
git log --all --diff-filter=A -- '*.lean' 'lakefile*' 'lean-toolchain' '*.thy' '*.tla'   # empty
grep -rIl '\bLean\b' . --exclude-dir=.git                                                # erc-7573.md only

# gate
npm i eipw-lint-js@0.11.0 markdownlint-cli2 smol-toml   # then lint(files, config/eipw.toml)
/tmp/.../markdownlint-cli2 --config config/.markdownlint.yaml ERCS/erc-8441.md
codespell --ignore-words=config/.codespell-whitelist <changed files>

# the model we could ship
cd js-client/contracts/lean && lake build   # 7 jobs, ~4 s, no dependencies
```
