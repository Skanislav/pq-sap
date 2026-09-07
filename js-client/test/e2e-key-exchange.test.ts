/**
 * End-to-end for the on-chain key-exchange layer (contracts/src/StealthKeyExchange.sol)
 * on a local anvil chain:
 *
 *   1. deploy the ERC-5564 announcer and StealthKeyExchange pointing at it
 *   2. register recipient A's ML-KEM-768 encapsulation key (the tail of the
 *      vectors' meta-address) — index 0, typed MLKEM768, reads back byte-identical
 *   3. announce the conformance vectors THROUGH the wrapper: the genuine payments
 *      and the wire-valid negatives (wrong view tag, bit flip) are forwarded; the
 *      truncated ciphertext is rejected on-chain with UnsupportedCiphertextLength
 *   4. scan the singleton's log filtered by `caller == keyExchange` with the TS
 *      client: A finds exactly the two genuine payments, B finds none
 *
 * The Lean model (contracts/lean/) states the same outcomes for the same
 * vectors as build-checked `#guard`s; the Foundry suite runs them against the
 * bytecode. Requires `anvil` on PATH and `forge build` run in contracts/ first.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  createPublicClient, createWalletClient, http, getAddress, BaseError, ContractFunctionRevertedError,
  type AbiEvent, type Address, type Hex,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';

import { decodeMetaAddress, scan, type AnnouncementData } from '../src/scheme.ts';
import {
  KEY_EXCHANGE_ABI, KEM_ORDER, SCHEME_ID, announceViaKeyExchange, isValidAnnouncement,
  kemOfCiphertextLength, registerViewingKey,
} from '../src/key-exchange.ts';
import { startAnvil, type Anvil } from './util/anvil.ts';

const PORT = 8551;
const ANVIL_KEY =
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const artifact = (rel: string) => JSON.parse(readFileSync(here(`../contracts/out/${rel}`), 'utf8'));
const announcerArt = artifact('ERC5564Announcer.sol/ERC5564Announcer.json');
const kxArt = artifact('StealthKeyExchange.sol/StealthKeyExchange.json');
const vectors = JSON.parse(readFileSync(here('../../python/vectors/v0/vectors.json'), 'utf8'));

const unhex = (s: string): Uint8Array => Uint8Array.from(Buffer.from(s.slice(2), 'hex'));

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

interface Case {
  name: string;
  expect: string;
  announcement: { stealth_address: string; ephemeral_pub_key: string; view_tag: string };
}

const ONCHAIN = ['positive/basic-match', 'positive/second-payment-unlinkable',
  'negative/wrong-view-tag', 'negative/truncated-ciphertext', 'negative/bitflipped-ciphertext'];

async function setup() {
  const anvil: Anvil = await startAnvil(PORT);
  const publicClient = createPublicClient({ chain: foundry, transport: http(anvil.rpc) });
  const walletClient = createWalletClient({
    chain: foundry, transport: http(anvil.rpc), account: privateKeyToAccount(ANVIL_KEY),
  });
  const deploy = async (art: { abi: unknown; bytecode: { object: Hex } }, args: unknown[] = []) => {
    const hash = await walletClient.deployContract({
      abi: art.abi as never, bytecode: art.bytecode.object, args: args as never,
    });
    const rcpt = await publicClient.waitForTransactionReceipt({ hash });
    return rcpt.contractAddress!;
  };
  const announcer = await deploy(announcerArt);
  const keyExchange = await deploy(kxArt, [announcer]);
  return { anvil, publicClient, walletClient, announcer, keyExchange };
}

test('key-exchange contract: register ek, announce vectors through the wrapper, scan', async () => {
  const { anvil, publicClient, walletClient, announcer, keyExchange } = await setup();
  try {
    assert.equal(await publicClient.readContract({
      address: keyExchange, abi: KEY_EXCHANGE_ABI, functionName: 'ANNOUNCER' }), getAddress(announcer));
    assert.equal(await publicClient.readContract({
      address: keyExchange, abi: KEY_EXCHANGE_ABI, functionName: 'SCHEME_ID' }), SCHEME_ID);

    // -- 2. registry: A's ek is the tail of its meta-address -------------------
    const metaA = unhex(vectors.recipients.A.meta_address);
    const ek = decodeMetaAddress(metaA).kemEk;
    assert.equal(ek.length, 1184);
    const reg = await registerViewingKey(publicClient, walletClient, foundry, keyExchange, ek);
    assert.equal(reg.index, 0n);
    assert.equal(reg.kem, 'MLKEM768');
    const [kem, stored] = await publicClient.readContract({
      address: keyExchange, abi: KEY_EXCHANGE_ABI, functionName: 'viewingKeyOf', args: [0n] });
    assert.equal(KEM_ORDER[kem], 'MLKEM768');
    assert.deepEqual(unhex(stored), ek);
    assert.equal(KEM_ORDER[await publicClient.readContract({
      address: keyExchange, abi: KEY_EXCHANGE_ABI, functionName: 'kemOfMetaAddress',
      args: [vectors.recipients.A.meta_address as Hex] })], 'MLKEM768');

    // -- 3. announce through the wrapper ---------------------------------------
    const cases: Case[] = vectors.cases.filter((c: Case) => ONCHAIN.includes(c.name));
    let forwarded = 0;
    for (const c of cases) {
      const a = c.announcement;
      const ann = {
        stealthAddress: getAddress(a.stealth_address) as Address,
        ephemeralPubKey: unhex(a.ephemeral_pub_key), viewTag: unhex(a.view_tag),
      };
      const valid = isValidAnnouncement(ann.ephemeralPubKey, ann.viewTag);
      assert.equal(valid, c.name !== 'negative/truncated-ciphertext', c.name);
      assert.equal(await publicClient.readContract({
        address: keyExchange, abi: KEY_EXCHANGE_ABI, functionName: 'isValidAnnouncement',
        args: [a.ephemeral_pub_key as Hex, a.view_tag as Hex] }), valid, c.name);
      if (valid) {
        assert.equal(kemOfCiphertextLength(ann.ephemeralPubKey.length), 'MLKEM768');
        await announceViaKeyExchange(publicClient, walletClient, foundry, keyExchange, ann);
        forwarded++;
      } else {
        // the truncated vector (1,087 B) never reaches the log
        await assert.rejects(
          announceViaKeyExchange(publicClient, walletClient, foundry, keyExchange, ann),
          (err: unknown) => {
            const revert = err instanceof BaseError
              ? err.walk((e) => e instanceof ContractFunctionRevertedError) : null;
            assert.ok(revert instanceof ContractFunctionRevertedError, `expected a custom-error revert: ${err}`);
            assert.equal(revert.data?.errorName, 'UnsupportedCiphertextLength');
            assert.deepEqual(revert.data?.args, [BigInt(ann.ephemeralPubKey.length)]);
            return true;
          });
      }
    }
    assert.equal(forwarded, 4);

    // -- 4. scan the singleton's log, wrapper-validated entries only ------------
    const logs = await publicClient.getLogs({
      address: announcer, event: ANNOUNCEMENT_EVENT, fromBlock: 0n,
      args: { schemeId: SCHEME_ID, caller: keyExchange },
    });
    assert.equal(logs.length, forwarded);
    const announcements: AnnouncementData[] = logs.map((l) => ({
      stealthAddress: unhex(l.args.stealthAddress!.toLowerCase()),
      ephemeralPubKey: unhex(l.args.ephemeralPubKey!),
      viewTag: unhex(l.args.metadata!).slice(0, 1),
    }));
    const scanAs = (name: string) => {
      const rec = vectors.recipients[name];
      return scan(decodeMetaAddress(unhex(rec.meta_address)), unhex(rec.kem_dk), announcements);
    };
    const hitsA = scanAs('A');
    assert.equal(hitsA.length, 2);
    const genuine = cases.filter((c) => c.expect === 'match')
      .map((c) => c.announcement.stealth_address.toLowerCase());
    for (const h of hitsA) {
      assert.ok(genuine.includes('0x' + Buffer.from(h.announcement.stealthAddress).toString('hex')));
    }
    assert.equal(scanAs('B').length, 0);
  } finally {
    anvil.stop();
  }
});
