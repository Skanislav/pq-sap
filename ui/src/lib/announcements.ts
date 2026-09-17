/** Shared announcement-log fetching (chunked where the RPC caps ranges). */

import { type PublicClient, parseAbiItem } from 'viem'

import type { AnnouncementData } from '../../../js-client/src/scheme.ts'
import { type ChainConfig, SCHEME_ID } from './chain.ts'
import { fromHex } from './hex.ts'

export const ANNOUNCEMENT_EVENT = parseAbiItem(
  'event Announcement(uint256 indexed schemeId, address indexed stealthAddress, address indexed caller, bytes ephemeralPubKey, bytes metadata)',
)

export interface OnchainAnnouncement extends AnnouncementData {
  blockNumber: bigint
  txHash: string
}

/**
 * The announcer must actually be a contract: `announce` returns nothing, so a
 * call to a code-less address (a reset testnet, a stale config) *succeeds* and
 * emits no log — the payment is then unfindable with no error anywhere. Fail
 * before broadcasting instead.
 */
export async function requireAnnouncer(cfg: ChainConfig, publicClient: PublicClient): Promise<void> {
  const code = await publicClient.getCode({ address: cfg.announcer })
  if (code && code.length > 2) return
  throw new Error(
    `No contract at the announcer ${cfg.announcer} on ${cfg.label} — announcing there would emit no event and the ` +
      `payment could never be found. The network was probably reset; redeploy the announcer and update ` +
      `ui/src/lib/chain.ts (announcer + scanFromBlock).`,
  )
}

export async function fetchAnnouncements(
  cfg: ChainConfig,
  publicClient: PublicClient,
  onProgress?: (msg: string) => void,
): Promise<{ announcements: OnchainAnnouncement[]; fromBlock: bigint; toBlock: bigint }> {
  const latest = await publicClient.getBlockNumber()
  const fromBlock =
    cfg.scanFromBlock < 0n ? (latest + cfg.scanFromBlock < 0n ? 0n : latest + cfg.scanFromBlock) : cfg.scanFromBlock
  // An empty range used to yield zero spans, zero logs and a cheerful "no
  // payments found" — the signature of a chain reset, not of an empty chain.
  // Not clamped to 0: the config is wrong and should say so.
  if (fromBlock > latest)
    throw new Error(
      `scanFromBlock ${fromBlock} is past the head of ${cfg.label} (block ${latest}), so there is no range to scan. ` +
        `The network was probably reset; update scanFromBlock (and the announcer address) in ui/src/lib/chain.ts.`,
    )
  const spans: Array<[bigint, bigint]> = []
  if (cfg.logChunk == null) {
    spans.push([fromBlock, latest])
  } else {
    for (let b = fromBlock; b <= latest; b += cfg.logChunk)
      spans.push([b, b + cfg.logChunk - 1n < latest ? b + cfg.logChunk - 1n : latest])
  }
  const announcements: OnchainAnnouncement[] = []
  for (const [from, to] of spans) {
    onProgress?.(`Fetching logs… block ${from} → ${to} (of ${latest})`)
    const logs = await publicClient.getLogs({
      address: cfg.announcer,
      event: ANNOUNCEMENT_EVENT,
      args: { schemeId: SCHEME_ID },
      fromBlock: from,
      toBlock: to,
    })
    for (const l of logs) {
      if (!l.args.ephemeralPubKey || !l.args.metadata || !l.args.stealthAddress) continue
      announcements.push({
        stealthAddress: fromHex(l.args.stealthAddress.toLowerCase()),
        ephemeralPubKey: fromHex(l.args.ephemeralPubKey),
        viewTag: fromHex(l.args.metadata).slice(0, 1),
        blockNumber: l.blockNumber,
        txHash: l.transactionHash,
      })
    }
  }
  return { announcements, fromBlock, toBlock: latest }
}
