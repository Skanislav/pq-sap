/** Small shared UI pieces: copyable hex, address chip, field row. */

import { type ReactNode, useState } from 'react'

import { shortHex } from '../lib/hex.ts'

export function CopyButton({ text, label }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      className="ghost"
      type="button"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text)
          setCopied(true)
          setTimeout(() => setCopied(false), 1200)
        } catch {
          /* clipboard unavailable */
        }
      }}
    >
      {copied ? 'Copied ✓' : (label ?? 'Copy')}
    </button>
  )
}

export function HexBlob({ label, value, secret }: { label: string; value: string; secret?: boolean }) {
  const [revealed, setRevealed] = useState(false)
  const shown = secret && !revealed ? '•'.repeat(24) : shortHex(value, 14, 10)
  return (
    <div className="hexblob">
      <span className="hexlabel">{label}</span>
      <code title={secret && !revealed ? undefined : value}>{shown}</code>
      <span className="hexmeta">{(value.length - 2) / 2} B</span>
      {secret && (
        <button className="ghost" type="button" onClick={() => setRevealed(!revealed)}>
          {revealed ? 'Hide' : 'Reveal'}
        </button>
      )}
      <CopyButton text={value} />
    </div>
  )
}

export function AddressChip({ address, explorer }: { address: string; explorer: string | null }) {
  return (
    <span className="addr">
      <code title={address}>{shortHex(address, 6, 4)}</code>
      {explorer && (
        <a href={`${explorer}/address/${address}`} target="_blank" rel="noreferrer">
          ↗
        </a>
      )}
      <CopyButton text={address} />
    </span>
  )
}

export function Note({ kind, children }: { kind: 'info' | 'warn' | 'error' | 'ok'; children: ReactNode }) {
  return <div className={`note note-${kind}`}>{children}</div>
}
