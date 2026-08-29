/** Shared announcement-log fetching (chunked where the RPC caps ranges). */

import { parseAbiItem, type PublicClient } from 'viem';

import type { AnnouncementData } from '../../../js-client/src/scheme.ts';
import { SCHEME_ID, type ChainConfig } from './chain.ts';
import { fromHex } from './hex.ts';

export const ANNOUNCEMENT_EVENT = parseAbiItem(
  'event Announcement(uint256 indexed schemeId, address indexed stealthAddress, address indexed caller, bytes ephemeralPubKey, bytes metadata)');

export interface OnchainAnnouncement extends AnnouncementData {
  blockNumber: bigint;
  txHash: string;
}

export async function fetchAnnouncements(
  cfg: ChainConfig, publicClient: PublicClient,
  onProgress?: (msg: string) => void,
): Promise<{ announcements: OnchainAnnouncement[]; fromBlock: bigint; toBlock: bigint }> {
  const latest = await publicClient.getBlockNumber();
  const fromBlock = cfg.scanFromBlock < 0n
    ? (latest + cfg.scanFromBlock < 0n ? 0n : latest + cfg.scanFromBlock)
    : cfg.scanFromBlock;
  const spans: Array<[bigint, bigint]> = [];
  if (cfg.logChunk == null) {
    spans.push([fromBlock, latest]);
  } else {
    for (let b = fromBlock; b <= latest; b += cfg.logChunk)
      spans.push([b, b + cfg.logChunk - 1n < latest ? b + cfg.logChunk - 1n : latest]);
  }
  const announcements: OnchainAnnouncement[] = [];
  for (const [from, to] of spans) {
    onProgress?.(`Fetching logs… block ${from} → ${to} (of ${latest})`);
    const logs = await publicClient.getLogs({
      address: cfg.announcer, event: ANNOUNCEMENT_EVENT,
      args: { schemeId: SCHEME_ID }, fromBlock: from, toBlock: to,
    });
    for (const l of logs) {
      if (!l.args.ephemeralPubKey || !l.args.metadata || !l.args.stealthAddress) continue;
      announcements.push({
        stealthAddress: fromHex(l.args.stealthAddress.toLowerCase()),
        ephemeralPubKey: fromHex(l.args.ephemeralPubKey),
        viewTag: fromHex(l.args.metadata).slice(0, 1),
        blockNumber: l.blockNumber, txHash: l.transactionHash,
      });
    }
  }
  return { announcements, fromBlock, toBlock: latest };
}
