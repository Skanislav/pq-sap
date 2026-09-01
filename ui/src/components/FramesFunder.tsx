import { formatEther } from 'viem'

import type { ThrowawayWallet } from '../lib/throwaway.ts'
import { AddressChip, CopyButton, Note } from './bits.tsx'

/**
 * Compact throwaway-wallet strip for the frame-transaction paths. Browser
 * wallets can't sign type 0x06, so an in-page key (persisted in localStorage)
 * signs; the user funds it by hand at the faucet — never automatically.
 */
export function FramesFunder({
  tw,
  balance,
  explorer,
  role = 'Frame transactions are signed by a throwaway in-page wallet',
}: {
  tw: ThrowawayWallet
  balance: bigint | null
  explorer: string | null
  /** what this wallet is for, shown before the wallet exists */
  role?: string
}) {
  if (!tw.address)
    return (
      <div className="panel">
        <p className="fine" style={{ margin: 0 }}>
          {role} (browser wallets can't sign type <code>0x06</code>). Generate one, then fund it at the faucet.
        </p>
        <div className="row">
          <button type="button" onClick={tw.generate}>
            Generate throwaway wallet
          </button>
        </div>
      </div>
    )
  const funded = balance !== null && balance > 0n
  return (
    <div className="panel">
      <div className="kv">
        <span className="addr">
          <AddressChip address={tw.address} explorer={explorer} /> <CopyButton text={tw.address} />
        </span>
        <span className={funded ? 'val' : 'val dim'}>{balance === null ? '…' : `${formatEther(balance)} ETH`}</span>
      </div>
      {!funded && (
        <Note kind="warn">
          Fund this wallet: copy the address, open the{' '}
          <a href="https://faucet.frames.ethrex.xyz/" target="_blank" rel="noreferrer">
            frames faucet ↗
          </a>
          , paste it and request test ETH.
        </Note>
      )}
      <div className="row">
        <button type="button" className="secondary" onClick={tw.generate}>
          New wallet
        </button>
        <button type="button" className="ghost" onClick={tw.clear}>
          Forget
        </button>
      </div>
    </div>
  )
}
