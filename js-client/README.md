# pq-stealth-client — TypeScript scanning client

Client-side (wallet/frontend) scanning for the post-quantum ERC-5564
stealth address scheme specified in
[`docs/TECHNICAL_SPEC.md`](../docs/TECHNICAL_SPEC.md).

The commitment route starts at `src/commit-scheme.ts`: decapsulate with the
viewing key, compare the tag, derive the commitment and account address using
the selected domains/deployment, then compare the announcement. It mirrors
Python `pq_stealth/commit.py`; scanning requires no spending secret.

`src/scheme.ts` and `src/mldsa65.ts` implement the separate Construction A
route, including a hand-port of the polynomial layer checked against Python
vectors. Spending helpers and account E2E tests are supporting research, not
requirements for commitment-format scanning. See
[ERC evidence](../docs/ERC_EVIDENCE.md) and
[spending research](../docs/SPENDING_RESEARCH.md).

## Toolchain

Node **>= 26** (`.nvmrc` provided) — tests run the `.ts` sources directly
via native type stripping, no build step. TypeScript **7** is used for
typechecking only (`strict` + `erasableSyntaxOnly` + `verbatimModuleSyntax`,
relative imports carry explicit `.ts` extensions).

## Run

```sh
nvm use
npm install
npm run typecheck       # tsc 7, noEmit
npm run test:commit     # commitment-format Python vector replay
npm run test:mldsa44    # ml-dsa-44-commit/v0 profile vector replay; every authorization
                        # payload re-verified with @noble/post-quantum ml_dsa44
npm test                # separate Construction A vector replay
npm run build-contracts # forge build (requires foundry)
npm run e2e             # spawns anvil, deploys the ERC-5564 announcer,
                        # announces the vectors on-chain, scans the logs
npm run e2e-7913        # ERC-7913 spend route (D-014): blinded sig verifies
                        # through the vendored ZKNOX verifier + an
                        # OpenZeppelin SignerERC7913 account
npm run e2e-7913-sphincs # hash-based spend (D-018): SPHINCS- C13 signature
                        # verifies through the vendored Verity-verified verifier,
                        # raw-key and committed ERC-7913 signers, same account
npm run e2e-mldsa44     # ml-dsa-44-commit/v0 (D-026): trusted-registrar key setup,
                        # committed-key ERC-7913 verify through the vendored ZKNOX
                        # ML-DSA-44 verifier, executeFrame through the unchanged
                        # Stealth8141ZkAccount; local only, nothing deployed
npm run e2e-pointer-sig # (v, r, s) pointer signatures with r = the C13 key
                        # (0x52) or its commitment (0x53); ML-DSA 0x50/0x51
                        # at recover level. Value lives in the vault — see
                        # docs/pointer-signatures-poc.md "Where the value lives"
npm run e2e:fork        # Sepolia-fork rehearsals (announce/verify + spend);
                        # replays test/state/*.rpc.json offline if present,
                        # otherwise records it (needs a Sepolia RPC)
npm run e2e:fork:record # force a fresh recording
```

The Construction A conformance test asserts that the JS-derived stealth public key is
byte-identical to the Python reference, and verifies the vectors'
possession proof with noble's stock ML-DSA-65 verifier.

## Reproducible fork state

The Sepolia-fork e2e tests (`test/e2e-sepolia-fork*.test.ts`,
`test/e2e-fork-pq-only.test.ts`) run anvil behind
`scripts/rpc-proxy.mjs`, which supports **record/replay** at the RPC
boundary (`test/util/anvil.ts` wires it up):

- **record** (first run, or `FORK_RECORD=1`): anvil forks the upstream
  pinned at a block (`--fork-block-number`, latest−5 at record time;
  `SEPOLIA_FORK_BLOCK` overrides) and every upstream response is saved to
  `test/state/<name>.rpc.json`, keyed by `(method, params)`. Upstream
  defaults to `ethereum-sepolia-rpc.publicnode.com`
  (`SEPOLIA_RPC_URL` overrides).
- **replay** (cache file exists): the proxy serves *only* from the cache —
  no network, no RPC quota, deterministic to the gas unit, ~17× faster.
  A cache miss (test changed, anvil version changed the fetch pattern)
  fails loudly with the missing key; re-record then.

The cache files are a few hundred KB of public Sepolia contract state and
are meant to be committed: anyone can rerun the fork rehearsals offline.
CI (`.github/workflows/ci.yml`) does exactly that — replay mode with
`SEPOLIA_RPC_URL` pointed at an unreachable address, so no run can
silently fall back to a live RPC.

Why record at the RPC boundary instead of anvil's native
`anvil_dumpState`/`--load-state`? Measured on anvil 1.4.1: a fork's dump
contains only accounts touched by local *transactions* — state reached
only via `eth_call`/`readContract` (e.g. the factory `getAddress` and
verifier `verify` steps here) is silently absent after `--load-state`,
and the fork's chain id is not preserved either. The RPC cache is
complete by construction. `--dump-state`/`--load-state`/`--state` remain
the right tool for *non-fork* chains, where the dump is total.

## Vendored verifier (not committed)

`npm run build-contracts` and the 7913 e2e expect the ZKNOX ETHDILITHIUM
sources (incl. their `lib/` dependencies: openzeppelin-contracts 5.5.0,
solady, forge-std, account-abstraction) at
`contracts/lib/ETHDILITHIUM`, pinned to rev `df999ed`. The tree is ~42 MB
and is gitignored; restore it with:

```sh
git clone --recurse-submodules https://github.com/ZKNoxHQ/ETHDILITHIUM \
  contracts/lib/ETHDILITHIUM
git -C contracts/lib/ETHDILITHIUM checkout --recurse-submodules df999ed
```

`contracts/lib/ETHDILITHIUM/VENDORED_REV.txt` records the pinned rev of a
restored tree.

## ML-DSA-44 committed key (D-026)

`src/profiles.ts` mirrors `python/pq_stealth/profiles.py`: explicit account
profiles over the 0x02 format, `spendKeyFromMlDsaPk`, `buildAuthorization`
(`pk || opener || sig`, pure ML-DSA-44, empty context, over the account's 32-byte
digest) and the reference `verifyAuthorization`. On chain,
`contracts/src/MlDsa44CommitSigner7913.sol` is the ERC-7913 verifier (`key` =
commitment), `contracts/src/MlDsa44KeyRegistry.sol` the one-time key setup
(recomputes `tr` and `t1` from the key bytes; **trusts its registrar for the
expanded matrix** because on-chain `ExpandA` costs ≈ 40 M gas with the vendored
SHAKE), and `contracts/src/frames/MlDsa44CommitFrameVerifier.sol` the adapter
that lets the existing `Stealth8141ZkFactory` bind it. A spend reveals the key
and links that recipient's spent addresses. Record, costs, and open items:
`docs/ml-dsa-commit-profile.md`.

## Vendored verifier (committed): SPHINCS- C13

`contracts/src/vendor/sphincs-minus/SPHINCs-C13Asm.sol` is the Verity Labs
machine-checked hash-based verifier from `lfglabs-dev/SPHINCS-` @ `2a40d0a`,
copied byte for byte (270 lines, MIT; sha256 and re-verification command in
`VENDORED_REV.txt` next to it). It is compiled with upstream's settings
(via-IR, 200 runs) through a per-path `compilation_restrictions` entry in
`contracts/foundry.toml`; everything else keeps the default profile.
`contracts/src/SphincsC13Signer7913.sol` wraps it as two ERC-7913 signers
(raw 32-byte key, and a commitment opened in the signature that makes the
stealth address sender-derivable at the cost of spend-time linkability —
see `docs/DECISIONS.md` D-018). Byte conventions: `src/sphincs.ts`.

The fixture `python/scripts/sphincs_c13_7913_demo.json` was produced by
`python/scripts/sphincs_c13_7913_demo.py` with upstream's Rust signer
(`cd signer-wasm && cargo build --release --bin signer-c13`; keygen 0.2 s,
one signature a few seconds); the script is deterministic, so a regenerated
file must be byte-identical.

The e2e test announces the two genuine payments plus the tampered variants
(wrong view tag, truncated ciphertext, bit-flipped ciphertext) through a
local ERC-5564 announcer on anvil, then scans the `Announcement` logs with
viem: recipient A finds exactly the two genuine payments, recipient B
finds nothing.
