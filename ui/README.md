# PQ Stealth Address demo UI

A four-step demo wallet for the post-quantum stealth address scheme
(ERC-5564 scheme `2`): **Recipient** (generate keys + meta-address),
**Send** (encapsulate → pay → announce), **Scan** (detect payments with
the viewing key), **Spend** (both spend routes, below). It reuses
`../js-client/src` directly — the same code the conformance tests run —
and the forge-built contracts in `../js-client/contracts`.

## Run it

Requires node ≥ 22.12 (`nvm use 26`), `anvil` + `forge` on PATH, the
vendored ETHDILITHIUM lib (see js-client/README "Vendored verifier"), and
the python venv (`python/.venv` with kyber-py, eth-abi, polyntt — needed
only for the PQ spend route).

```sh
(cd ../js-client && npm install)   # the UI bundles ../js-client/src, which resolves viem/noble from there
cd ui
npm install
npm run chain    # terminal 1: anvil + deployments + seeded payments + signer service
npm run dev      # terminal 2: http://localhost:5173
```

`npm run chain` deploys the ERC-5564 announcer (deterministic first-tx
address), an ERC-4337 v0.8 EntryPoint, the ZKNOX ERC-7913 ML-DSA verifier,
and the `Stealth7913Factory`; seeds payments for all three profiles; and
starts the blinded-key signer service on :8546. In the browser: network
**Local anvil**, signer **anvil dev account**.

The signer is a property of the network and is managed only in the header:
Local anvil offers the dev account or a browser wallet, Sepolia a browser
wallet, and the Frames testnet an **in-page throwaway key** (browser wallets
can't sign type-0x06 frame transactions; the key lives in `localStorage` and
only ever holds faucet ETH). Every tab — Send, both Spend routes, Frame tx —
signs with that one wallet. The Spend tab switches between the classical and
PQ routes; on the frames PQ route a payment can be spent to any address, back
to the in-page wallet (**self**), or to a freshly derived stealth account
(**new stealth**, announced in the same frame tx), and **max** fills the whole
balance since the sponsor pays gas.

## Compact 65-byte meta-address (the "ecrecover trick")

The classical scheme's full meta-address is 1,218 B (version ‖ spend_pub ‖
1,184-B ML-KEM ek). The compact form is **65 bytes**: `spend_pub(33)` ‖
`registry_index(32)`. The spending pubkey rides inline — its SEC1 parity
prefix (0x02/0x03) doubles as the version byte, and stealth outputs are
ecrecover-compatible EOAs, so 32 bytes of pubkey are all the spend path
needs — while the bulky viewing key is fetched from the on-chain
`StealthKeyRegistry` by index. Register once (Spend tab → "Register viewing
key → compact meta-address"), then share the 65 bytes. Because the spend
pubkey is inline, a compromised registry can only *deny detection*, never
redirect funds.

## Running on Sepolia

Almost nothing needs deploying — the PQ account infrastructure is already
live (ethereum/kohaku, examples/pq-account) and reused as-is:

| Contract | Sepolia address | Source |
| --- | --- | --- |
| ERC-5564 announcer | `0x5564…5564` | canonical singleton |
| ERC-4337 EntryPoint v0.7 | `0x0000…da032` | canonical |
| ZKNOX MLDSA verifier | `0x092c…21ef` | kohaku (deployed) |
| ZKNOX mldsa_k1 factory | `0xF451…8C2e` | kohaku (deployed) |

`public/sepolia-deployment.json` (checked in) already points at these and at
the **hosted signer service** on Railway (`signerService`), so the Sepolia PQ
spend works with no local process — open the UI on Sepolia with a browser
wallet. To use a local signer instead:

```sh
npm run signer                                   # blinded-key service on 127.0.0.1:8546
VITE_SIGNER_URL=http://127.0.0.1:8546 npm run dev  # build-time override of signerService
```

On Sepolia the PQ route uses the **deployed ZKNOX hybrid account**
(ECDSA + ML-DSA-44/level-2): the userOp carries a classical signature plus
the blinded ML-DSA signature, verified on-chain (~8M gas). Two ways to pay
that gas:

- **Self-bundled** (default) — the op goes through the canonical EntryPoint
  and the stealth account pays its own gas prefund, so it must hold ETH
  beyond the amount it sends.
- **Gasless via Pimlico** (paste a Pimlico API key in the Spend tab) — a
  verifying paymaster sponsors the gas and Pimlico bundles the op, so the
  account needs only the value it sends. This also removes the privacy leak
  of funding the account's gas from a linkable EOA. Get a key at
  dashboard.pimlico.io; it's stored only in your browser. **Validated live on
  Sepolia** (tx
  [`0x4cde53ee…d948f4`](https://sepolia.etherscan.io/tx/0x4cde53eef9027514cbf181f2f0baf0980dc49cd4af28cdc53412f986bad948f4)):
  `pm_sponsorUserOperation` accepted the estimation dummy signature and
  sponsored ~9.3M gas of on-chain ML-DSA verification with no sponsorship
  policy — the account was debited only the value it sent.

The classical EOA route (ecrecover, 21k gas) needs nothing beyond the
announcer and works with any wallet.

Only the compact-meta `StealthKeyRegistry` is genuinely new; deploy just
that if you want compact meta-addresses on Sepolia:

```sh
SEPOLIA_DEPLOYER_KEY=0x… npm run deploy:sepolia   # deploys only the registry
```

The whole Sepolia PQ path is validated offline against the real deployed
contracts via the js-client fork-replay cache: `npm run signer` then
`npm run e2e:sepolia-fork` (this also proves the off-chain userOpHash — both
the self-bundled and the sponsored `paymasterAndData` forms — matches the
on-chain `EntryPoint.getUserOpHash`).

To exercise the gasless path against **real Sepolia + the real Pimlico API**,
`npm run e2e:sepolia-live` — gated behind `LIVE=1`, reads `PIMLICO_API_KEY`,
`SEPOLIA_PRIVATE_KEY`, and `SEPOLIA_RPC_URL` from the repo-root `.env`. It
announces, funds the stealth account with the (tiny) spend value, deploys it
if needed, then submits the sponsored userOp through Pimlico. Stage 1 is
idempotent and stage 2 is free/retryable, so re-runs cost almost nothing.

## Publishing the UI to IPFS (Pinata)

The production bundle is fully static (relative asset URLs, `base: './'`),
so it can be pinned as one folder and served from any IPFS gateway:

```sh
echo 'PINATA_JWT=eyJ…' >> .env       # API-key JWT (app.pinata.cloud → API Keys, pinFileToIPFS scope)
npm run build
npm run deploy:ipfs -- --dry-run   # lists the files that would be uploaded
npm run deploy:ipfs                # uploads dist/ → prints the folder CID + gateway URLs
```

The script pins `dist/` through Pinata's `pinFileToIPFS` as a CIDv1
directory named `pq-stealth-ui-<git sha>` (override with `PINATA_NAME`) and
prints `ipfs://<cid>` (usable as an ENS contenthash), the public gateway
URLs, and your dedicated gateway URL if `PINATA_GATEWAY` is set. Old pins
are never removed automatically.

Everything works from the gateway: key generation, meta-addresses, sending,
scanning, the classical EOA spend, and the Sepolia PQ route with a browser
wallet — `public/sepolia-deployment.json` ships inside the bundle and points
the PQ route at the hosted signer (next section). Only the "Local anvil"
network needs the dev chain running on the same machine.

## Hosting the signer service (Railway)

The PQ route's blinded-key signer (`scripts/signer-service.mjs` + the Python
helpers, fixed demo identity) runs as a container on Railway, project
`pq-stealth-signer`, service `signer`. `signer/Dockerfile` fetches
ETHDILITHIUM's `pythonref` at the vendored commit (it is gitignored here)
and installs its requirements plus `kyber-py`.

```sh
railway login && railway link      # once, from ui/ (project pq-stealth-signer)
npm run deploy:signer              # stages Dockerfile + python/scripts + signer-service.mjs, `railway up`
npm run deploy:signer -- --stage-only   # only assemble the build context (to docker build it yourself)
```

The script uploads a small staging directory (`--path-as-root`) rather than
the 17 GB checkout, then reads the service's public domain and writes it into
`public/sepolia-deployment.json` and `public/frames-deployment.json` — both
hosted-chain PQ routes call the same service (`--keep-local` skips that;
`deploy:frames` honours `SIGNER_URL` when regenerating its file). The container
binds `SIGNER_HOST=0.0.0.0` on `$PORT`; the same image runs anywhere with
`docker run -p 8546:8546`. Health check: `GET /` → `{"ok":true}`.

Honest caveat: a hosted signer holds the (demo) blinded secret and signs on
request — fine for the fixed demo identity, but the real fix is porting
blinded ML-DSA signing to the browser so no server exists at all.

## The two spend routes (Spend tab)

**Classical hybrid** (`secp256k1+ML-KEM-768`, 1,218 B meta-address):
discovery is post-quantum, the spending key is secp256k1 — the stealth
address is a plain EOA (`P = K + t·G`, `t = SHAKE256(domain ‖ ss)`), so
spending is one ordinary ECDSA transaction: ecrecover, exactly 21k gas,
entirely in the browser. Quantum-vulnerable ownership, HNDL-safe
unlinkability (threat model D-001).

**PQ route** (D-014, ZKNOX level-2 profile — the deployed verifier's
parameter set): the announced stealth address is the **counterfactual
address** of an ERC-4337 account bound to the blinded ML-DSA key, so
discovery, funding, and spending agree on one address and no EOA key
exists. Spending deploys the account via a factory and submits a
self-bundled userOp whose validation runs the real lattice verifier
on-chain. Blinded signing runs in the local Python service — key material
never reaches the browser. Two backends by network:

- **Local dev chain** — a self-contained `Stealth7913Account4337`
  (ERC-7913 single-signer, signer = `verifier ‖ PKContract`, 40 B),
  deployed by `Stealth7913Factory` (~6.5M gas), spend ~15.2M gas.
- **Sepolia** — the **already-deployed ZKNOX hybrid account**
  (ethereum/kohaku): ECDSA + ML-DSA-44, factory `0xF451…8C2e`, verifier
  `0x092c…21ef`. Nothing to deploy; createAccount ~710k gas, spend ~8.35M
  gas. This is the same path `js-client/src/spend.ts` and its fork test use.

## Checks

```sh
npm run typecheck      # tsc over the app (follows into js-client sources)
npm run check-keygen   # both schemes vs python vectors, byte-identical
npm run chain          # then, in another terminal:
npm run e2e            # headless run of all three flows incl. both spends
npm run build          # production bundle
```

## What is real and what is demo-grade

Real: key generation for both schemes, meta-address encodings, sender
derivations, view-tag scanning, the classical EOA spend, the counterfactual
account derivation, and the on-chain blinded ML-DSA verification — all
byte-compatible with the Python reference (see `scripts/check-keygen.ts`).

Demo-grade / honest caveats: seeds persist in `localStorage`; the PQ spend
runs at the ZKNOX **level-2** profile because that is the parameter set of
the only deployed on-chain verifier — a stateless ML-DSA-65 ERC-7913
verifier is the unclaimed deliverable that would make the default scheme
spendable on-chain; the main ML-DSA-65 scheme's announcements still use the
`keccak(stealth_pk)` address rule (counterfactual-address derivation for it
is a spec-level change to fold into the ERC draft).
