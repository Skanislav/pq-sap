/**
 * Scanner flow: fetch Announcement logs from the announcer, decapsulate
 * each ciphertext with the viewing key in a web worker, and list the
 * payments that belong to this recipient.
 */

import { useEffect, useRef, useState } from 'react';
import { formatEther } from 'viem';

import { publicClientFor, type ChainConfig } from '../lib/chain.ts';
import { fromHex, toHex } from '../lib/hex.ts';
import { parseTxError } from '../lib/errors.ts';
import { usd } from '../lib/useEthUsd.ts';
import type { RecipientKeys } from '../lib/keygen.ts';
import type { ScanResponse, ScanHit } from '../lib/scan-worker.ts';
import { fetchAnnouncements, type OnchainAnnouncement } from '../lib/announcements.ts';
import { AddressChip, Note } from './bits.tsx';

interface FoundPayment {
  announcement: OnchainAnnouncement;
  sharedSecret: Uint8Array;
  stealthPk: Uint8Array;
  balanceWei: bigint | null;
}

interface ScanStats {
  announcements: number;
  elapsedMs: number;
  fromBlock: bigint;
  toBlock: bigint;
}

export function ScanTab({ cfg, keys, ethUsd }: {
  cfg: ChainConfig;
  keys: RecipientKeys | null;
  ethUsd: number | null;
}) {
  const [metaHex, setMetaHex] = useState('');
  const [dkHex, setDkHex] = useState('');
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const [hits, setHits] = useState<FoundPayment[] | null>(null);
  const [stats, setStats] = useState<ScanStats | null>(null);
  const workerRef = useRef<Worker | null>(null);

  // prefill from the recipient tab's keys
  useEffect(() => {
    if (keys) {
      setMetaHex(toHex(keys.metaAddress));
      setDkHex(toHex(keys.kemDk));
    }
  }, [keys]);

  useEffect(() => () => workerRef.current?.terminate(), []);

  const scan = async () => {
    setError(null);
    setHits(null);
    setStats(null);
    setScanning(true);
    const publicClient = publicClientFor(cfg);
    try {
      const metaAddress = fromHex(metaHex.trim());
      const kemDk = fromHex(dkHex.trim());

      // 1. fetch announcements (chunked where the RPC caps ranges)
      const { announcements, fromBlock, toBlock: latest } =
        await fetchAnnouncements(cfg, publicClient, setStatus);

      // 2. decapsulate + check in the worker
      setStatus(`Scanning ${announcements.length} announcements…`);
      const worker = new Worker(
        new URL('../lib/scan-worker.ts', import.meta.url), { type: 'module' });
      workerRef.current = worker;
      const result = await new Promise<{ hits: ScanHit[]; elapsedMs: number }>(
        (resolve, reject) => {
          worker.onmessage = (ev: MessageEvent<ScanResponse>) => {
            const m = ev.data;
            if (m.type === 'progress')
              setStatus(`Scanning… ${m.done}/${m.total}`);
            else if (m.type === 'done') resolve(m);
            else reject(new Error(m.message));
          };
          worker.onerror = (e) => reject(new Error(e.message));
          worker.postMessage({
            metaAddress, kemDk,
            announcements: announcements.map(
              ({ stealthAddress, ephemeralPubKey, viewTag }) =>
                ({ stealthAddress, ephemeralPubKey, viewTag })),
          });
        });
      worker.terminate();
      workerRef.current = null;

      // 3. balances for the hits
      const found: FoundPayment[] = [];
      for (const h of result.hits) {
        const ann = announcements[h.index]!;
        let balanceWei: bigint | null = null;
        try {
          balanceWei = await publicClient.getBalance({
            address: toHex(ann.stealthAddress) as `0x${string}` });
        } catch { /* balance is decoration; the detection already happened */ }
        found.push({
          announcement: ann, sharedSecret: h.sharedSecret,
          stealthPk: h.stealthPk, balanceWei,
        });
      }
      setHits(found);
      setStats({
        announcements: announcements.length,
        elapsedMs: result.elapsedMs, fromBlock, toBlock: latest,
      });
      setStatus(null);
    } catch (e) {
      setError(parseTxError(e));
      setStatus(null);
    } finally {
      setScanning(false);
    }
  };

  return (
    <section>
      <h2>Scan for your payments</h2>
      <p className="lede">
        The scanner decapsulates every announcement's ML-KEM ciphertext with your
        viewing key, filters on the 1-byte view tag, and re-derives the blinded
        stealth key for candidates. Spending keys are never touched.
      </p>

      <label className="field">
        <span>Meta-address</span>
        <textarea
          rows={3} spellCheck={false} placeholder="0x01…"
          value={metaHex} onChange={(e) => setMetaHex(e.target.value)}
        />
      </label>
      <label className="field">
        <span>Viewing key (ML-KEM decapsulation key, 2,400 bytes hex)</span>
        <textarea
          rows={3} spellCheck={false} placeholder="0x…"
          value={dkHex} onChange={(e) => setDkHex(e.target.value)}
        />
      </label>

      <div className="row">
        <button disabled={scanning || !metaHex.trim() || !dkHex.trim()} onClick={scan}>
          {scanning ? (status ?? 'Scanning…') : 'Scan'}
        </button>
      </div>

      {error && <Note kind="error">{error}</Note>}

      {stats && hits && (
        <>
          <Note kind={hits.length ? 'ok' : 'info'}>
            {hits.length
              ? `Found ${hits.length} payment${hits.length === 1 ? '' : 's'}`
              : 'No payments found'}
            {' '}in {stats.announcements} announcement{stats.announcements === 1 ? '' : 's'}
            {' '}(blocks {stats.fromBlock.toString()}–{stats.toBlock.toString()},
            {' '}{stats.elapsedMs.toFixed(1)} ms
            {stats.announcements > 0 &&
              `, ${(stats.elapsedMs * 1000 / stats.announcements).toFixed(0)} µs/announcement`}).
          </Note>
          {hits.map((h) => {
            const addr = toHex(h.announcement.stealthAddress);
            const eth = h.balanceWei != null ? Number(formatEther(h.balanceWei)) : null;
            return (
              <div className="hit" key={addr + h.announcement.txHash}>
                <div>
                  <AddressChip address={addr} explorer={cfg.explorer} />
                  <span className="hexmeta"> block {h.announcement.blockNumber.toString()}</span>
                </div>
                <div>
                  {h.balanceWei != null
                    ? <strong>{formatEther(h.balanceWei)} ETH{usd(eth!, ethUsd)}</strong>
                    : <span className="hexmeta">balance unavailable</span>}
                </div>
                <div className="fine">
                  view tag <code>{toHex(h.announcement.viewTag)}</code>
                  {' · '}announcement {cfg.explorer
                    ? <a href={`${cfg.explorer}/tx/${h.announcement.txHash}`} target="_blank" rel="noreferrer">
                        {h.announcement.txHash.slice(0, 10)}…</a>
                    : <code>{h.announcement.txHash.slice(0, 10)}…</code>}
                  {' · '}blinded stealth pk derived ({h.stealthPk.length} B) — spendable via
                  the ERC-7913 account path
                </div>
              </div>
            );
          })}
        </>
      )}
    </section>
  );
}
