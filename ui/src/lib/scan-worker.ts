/**
 * Web worker: run the full scan off the main thread.
 * One ML-KEM decapsulation per announcement; blinded-key derivation only
 * on view-tag hits — same hot path the wallet client would run.
 */

import { type AnnouncementData, checkAnnouncement, decodeMetaAddress } from '../../../js-client/src/scheme.ts'

export interface ScanRequest {
  metaAddress: Uint8Array
  kemDk: Uint8Array
  announcements: AnnouncementData[]
}

export interface ScanHit {
  index: number
  sharedSecret: Uint8Array
  stealthPk: Uint8Array
}

export type ScanResponse =
  | { type: 'progress'; done: number; total: number }
  | { type: 'done'; hits: ScanHit[]; elapsedMs: number }
  | { type: 'error'; message: string }

self.onmessage = (ev: MessageEvent<ScanRequest>) => {
  const { metaAddress, kemDk, announcements } = ev.data
  const post = (m: ScanResponse) => (self as unknown as Worker).postMessage(m)
  try {
    const meta = decodeMetaAddress(metaAddress)
    const hits: ScanHit[] = []
    const t0 = performance.now()
    for (let i = 0; i < announcements.length; i++) {
      const payment = checkAnnouncement(meta, kemDk, announcements[i]!)
      if (payment) hits.push({ index: i, ...payment })
      if ((i + 1) % 25 === 0) post({ type: 'progress', done: i + 1, total: announcements.length })
    }
    post({ type: 'done', hits, elapsedMs: performance.now() - t0 })
  } catch (e) {
    post({ type: 'error', message: e instanceof Error ? e.message : String(e) })
  }
}
