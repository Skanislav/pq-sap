/**
 * End-to-end against a local anvil chain:
 *
 *   1. spawn anvil, deploy the ERC-5564 announcer (forge artifact)
 *   2. emit the conformance vectors' announcements on-chain — the two
 *      genuine payments to recipient A plus the tampered variants
 *   3. fetch Announcement logs with viem and scan them with the TS client
 *   4. recipient A must find exactly the two genuine payments;
 *      recipient B must find none
 *
 * Requires `anvil` on PATH and `forge build` run in contracts/ first.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  createPublicClient, createWalletClient, http, getAddress,
  type AbiEvent, type Hex,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';

import { decodeMetaAddress, scan, type AnnouncementData } from '../src/scheme.ts';
import { startAnvil, type Anvil } from './util/anvil.ts';

const PORT = 8547;
// anvil's first default funded account
const ANVIL_KEY =
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
// placeholder scheme id — real value assigned via the ERC-5564 registry
const SCHEME_ID = 2n;

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const artifact = JSON.parse(readFileSync(
  here('../contracts/out/ERC5564Announcer.sol/ERC5564Announcer.json'), 'utf8'));
const vectors = JSON.parse(readFileSync(
  here('../../python/vectors/v0/vectors.json'), 'utf8'));

const unhex = (s: string): Uint8Array =>
  Uint8Array.from(Buffer.from(s.slice(2), 'hex'));
const tohex = (b: Uint8Array): string => '0x' + Buffer.from(b).toString('hex');

const ANNOUNCEMENT_EVENT = {
  type: 'event',
  name: 'Announcement',
  inputs: [
    { name: 'schemeId', type: 'uint256', indexed: true },
    { name: 'stealthAddress', type: 'address', indexed: true },
    { name: 'caller', type: 'address', indexed: true },
    { name: 'ephemeralPubKey', type: 'bytes', indexed: false },
    { name: 'metadata', type: 'bytes', indexed: false },
  ],
} as const satisfies AbiEvent;

async function setup() {
  const anvil: Anvil = await startAnvil(PORT);
  const publicClient = createPublicClient({ chain: foundry, transport: http(anvil.rpc) });
  const walletClient = createWalletClient({
    chain: foundry, transport: http(anvil.rpc),
    account: privateKeyToAccount(ANVIL_KEY),
  });

  const hash = await walletClient.deployContract({
    abi: artifact.abi, bytecode: artifact.bytecode.object,
  });
  const rcpt = await publicClient.waitForTransactionReceipt({ hash });
  return { anvil, publicClient, walletClient, announcer: rcpt.contractAddress! };
}

/** Announcements worth putting on-chain: unique valid + tampered ones. */
interface OnchainCase {
  name: string;
  announcement: {
    stealth_address: string; ephemeral_pub_key: string; view_tag: string;
  };
}

function onchainCases(): OnchainCase[] {
  const wanted = ['positive/basic-match', 'positive/second-payment-unlinkable',
    'negative/wrong-view-tag', 'negative/truncated-ciphertext',
    'negative/bitflipped-ciphertext'];
  return vectors.cases.filter((c: OnchainCase) => wanted.includes(c.name));
}

test('announce vectors on-chain, scan as recipients A and B', async () => {
  const { anvil, publicClient, walletClient, announcer } = await setup();
  try {
    for (const c of onchainCases()) {
      const a = c.announcement;
      const hash = await walletClient.writeContract({
        address: announcer, abi: artifact.abi, functionName: 'announce',
        args: [SCHEME_ID, getAddress(a.stealth_address),
          a.ephemeral_pub_key as Hex, a.view_tag as Hex], // metadata[0] = view tag
      });
      await publicClient.waitForTransactionReceipt({ hash });
    }

    const logs = await publicClient.getLogs({
      address: announcer, event: ANNOUNCEMENT_EVENT, fromBlock: 0n,
    });
    assert.equal(logs.length, onchainCases().length);

    const announcements: AnnouncementData[] = logs
      .filter((l) => l.args.schemeId === SCHEME_ID)
      .map((l) => ({
        stealthAddress: unhex(l.args.stealthAddress!.toLowerCase()),
        ephemeralPubKey: unhex(l.args.ephemeralPubKey!),
        viewTag: unhex(l.args.metadata!).slice(0, 1),
      }));

    const scanAs = (name: string) => {
      const rec = vectors.recipients[name];
      return scan(decodeMetaAddress(unhex(rec.meta_address)),
        unhex(rec.kem_dk), announcements);
    };

    const hitsA = scanAs('A');
    assert.equal(hitsA.length, 2, 'A must detect exactly the 2 genuine payments');
    const found = new Set(hitsA.map((h) => tohex(h.announcement.stealthAddress)));
    const expected = new Set<string>(
      vectors.cases.filter((c: OnchainCase) => c.name.startsWith('positive/'))
        .map((c: OnchainCase) => c.announcement.stealth_address));
    assert.deepEqual(found, expected);

    assert.equal(scanAs('B').length, 0, 'B must detect nothing');
  } finally {
    anvil.stop();
  }
});
