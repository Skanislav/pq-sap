# pq-stealth-client — TypeScript scanning client

Client-side (wallet/frontend) scanning for the post-quantum ERC-5564
stealth address scheme specified in
[`docs/TECHNICAL_SPEC.md`](../docs/TECHNICAL_SPEC.md).

What it does with only the **viewing key**: decapsulate each announcement's
ML-KEM-768 ciphertext (`@noble/post-quantum`, audited), check the 1-byte
view tag, re-derive the blinded ML-DSA-65 stealth key, and match the
Ethereum address. Spending secrets never touch this code.

`src/mldsa65.ts` is a minimal hand-port of the FIPS 204 polynomial layer
(ExpandA, ExpandS, NTT, Power2Round, pk packing) — noble keeps these in
module closures, so they are re-implemented from the spec and validated
byte-for-byte against the Python reference vectors.

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
npm test                # conformance: replay ../python/vectors/v0 (8 cases)
npm run build-contracts # forge build (requires foundry)
npm run e2e             # spawns anvil, deploys the ERC-5564 announcer,
                        # announces the vectors on-chain, scans the logs
npm run e2e-7913        # ERC-7913 spend route (D-014): blinded sig verifies
                        # through the vendored ZKNOX verifier + an
                        # OpenZeppelin SignerERC7913 account
```

The conformance test asserts that the JS-derived stealth public key is
byte-identical to the Python reference, and verifies the vectors'
possession proof with noble's stock ML-DSA-65 verifier.

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

The e2e test announces the two genuine payments plus the tampered variants
(wrong view tag, truncated ciphertext, bit-flipped ciphertext) through a
local ERC-5564 announcer on anvil, then scans the `Announcement` logs with
viem: recipient A finds exactly the two genuine payments, recipient B
finds nothing.
