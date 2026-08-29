#!/usr/bin/env node
/**
 * Prepare the UI for Sepolia. The PQ spend infrastructure is ALREADY
 * deployed (ethereum/kohaku, examples/pq-account) and reused as-is:
 *
 *   - ERC-5564 announcer singleton      0x5564…5564
 *   - ERC-4337 v0.7 EntryPoint          0x0000…da032
 *   - ZKNOX MLDSA verifier (v0.0.10)    0x092c…21ef
 *   - ZKNOX mldsa_k1 hybrid factory      0xF451…8C2e
 *
 * So there is nothing PQ-specific to deploy. The ONLY genuinely-new
 * contract is StealthKeyRegistry (for the classical route's 65-byte
 * compact meta-address); this script deploys just that and writes
 * ui/public/sepolia-deployment.json with the kohaku addresses + registry.
 *
 * Run with a funded deployer key in the environment (never on the CLI):
 *   SEPOLIA_DEPLOYER_KEY=0x…  SEPOLIA_RPC_URL=https://…  npm run deploy:sepolia
 * Skip the registry (compact meta) entirely with SKIP_REGISTRY=1 — then no
 * deployment or key is needed at all; the checked-in file already works.
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { createPublicClient, createWalletClient, http, getAddress } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { sepolia } from 'viem/chains';

const KOHAKU = {
  announcer: '0x55649E01B5Df198D18D95b5cc5051630cfD45564',
  entryPoint: '0x0000000071727De22E5E9d8BAf0edAc6f37da032', // v0.7
  verifier: '0x092c5d82069de997E34Ce2505CA7D5042f3721ef',   // ZKNOX_MLDSA_VERIFIER_V0_0_10
  factory: '0xF45104FCfBB9233cEa6D516d71ba57F6961B8C2e',    // ZKNOX_MLDSA_K1_FACTORY_V0_0_10
};

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
const OUT = here('../../js-client/contracts/out');
const RPC = process.env.SEPOLIA_RPC_URL ?? 'https://ethereum-sepolia-rpc.publicnode.com';

let registry = null;
if (!process.env.SKIP_REGISTRY) {
  const KEY = process.env.SEPOLIA_DEPLOYER_KEY;
  if (!KEY || !/^0x[0-9a-fA-F]{64}$/.test(KEY)) {
    console.error('Set SEPOLIA_DEPLOYER_KEY=0x<64 hex> (a funded Sepolia key), or SKIP_REGISTRY=1');
    console.error('to write the deployment file without the compact-meta registry.');
    process.exit(1);
  }
  const rel = 'StealthKeyRegistry.sol/StealthKeyRegistry.json';
  if (!existsSync(`${OUT}/${rel}`)) {
    console.error(`missing artifact ${rel} — run: forge build (in js-client/contracts)`);
    process.exit(1);
  }
  const art = JSON.parse(readFileSync(`${OUT}/${rel}`, 'utf8'));
  const account = privateKeyToAccount(KEY);
  const publicClient = createPublicClient({ chain: sepolia, transport: http(RPC) });
  const walletClient = createWalletClient({ chain: sepolia, transport: http(RPC), account });
  const balance = await publicClient.getBalance({ address: account.address });
  console.log(`deployer ${account.address} — ${(Number(balance) / 1e18).toFixed(4)} ETH`);
  if (balance === 0n) { console.error('deployer has no Sepolia ETH'); process.exit(1); }

  process.stdout.write('deploying StealthKeyRegistry… ');
  const hash = await walletClient.deployContract({ abi: art.abi, bytecode: art.bytecode.object });
  const rcpt = await publicClient.waitForTransactionReceipt({ hash });
  if (rcpt.status !== 'success') { console.error('deploy failed'); process.exit(1); }
  registry = getAddress(rcpt.contractAddress);
  console.log(`${registry} (${rcpt.gasUsed} gas)`);
}

const deployment = {
  mode: 'zknox-hybrid',
  chainId: sepolia.id,
  announcer: getAddress(KOHAKU.announcer),
  entryPoint: getAddress(KOHAKU.entryPoint),
  verifier: getAddress(KOHAKU.verifier),
  factory: getAddress(KOHAKU.factory),
  registry,
  signerService: 'http://127.0.0.1:8546',
};
mkdirSync(here('../public'), { recursive: true });
writeFileSync(here('../public/sepolia-deployment.json'),
  JSON.stringify(deployment, null, 2) + '\n');

console.log(`
ui/public/sepolia-deployment.json written (reusing the deployed kohaku pq-account):
  announcer   ${deployment.announcer}  (canonical)
  entryPoint  ${deployment.entryPoint}  (canonical v0.7)
  verifier    ${deployment.verifier}  (ZKNOX MLDSA v0.0.10)
  factory     ${deployment.factory}  (ZKNOX mldsa_k1 hybrid)
  registry    ${registry ?? '(skipped — compact meta unavailable on Sepolia)'}

Next: run \`npm run signer\` (blinded-key service) and open the UI on Sepolia
with a browser wallet. Classical EOA spend (ecrecover, 21k gas) works with
any wallet; the PQ hybrid spend is ~8M gas and self-bundles through the
canonical EntryPoint.`);
