/**
 * The one place a signer is managed. The network picks the signer (see
 * useWallet): anvil dev account or browser wallet locally, browser wallet on
 * Sepolia, the in-page throwaway key on the frames testnet. Every tab reads
 * the same `wallet`, so no tab carries its own wallet panel.
 */

import { formatEther } from 'viem'

import { CHAINS, type ChainConfig, type ChainKey } from '../lib/chain.ts'
import { MODE_LABEL, type Wallet, type WalletMode } from '../lib/useWallet.ts'
import { AddressChip, Note } from './bits.tsx'

export const FAUCET_URL = 'https://faucet.frames.ethrex.xyz/'

export function WalletBar({
  cfg,
  chainKey,
  setChainKey,
  wallet,
}: {
  cfg: ChainConfig
  chainKey: ChainKey
  setChainKey: (k: ChainKey) => void
  wallet: Wallet
}) {
  const gate = wallet.gate(cfg)
  const balance = wallet.balance === null ? '…' : `${formatEther(wallet.balance)} ETH`
  return (
    <div className="walletbox">
      <select value={chainKey} aria-label="Network" onChange={(e) => setChainKey(e.target.value as ChainKey)}>
        {Object.values(CHAINS).map((c) => (
          <option key={c.key} value={c.key}>
            {c.label}
          </option>
        ))}
      </select>
      {wallet.modes.length > 1 ? (
        <select value={wallet.mode} aria-label="Signer" onChange={(e) => wallet.setMode(e.target.value as WalletMode)}>
          {wallet.modes.map((m) => (
            <option key={m} value={m} disabled={m === 'injected' && !wallet.hasInjected}>
              {MODE_LABEL[m]}
              {m === 'injected' && !wallet.hasInjected ? ' (none found)' : ''}
            </option>
          ))}
        </select>
      ) : (
        <span className="signerkind">{MODE_LABEL[wallet.mode]}</span>
      )}
      {gate === 'connect' ? (
        <button type="button" disabled={wallet.connecting} onClick={() => wallet.connect().catch(() => {})}>
          {wallet.mode === 'throwaway' ? 'Generate wallet' : wallet.connecting ? 'Connecting…' : 'Connect wallet'}
        </button>
      ) : (
        <span className="signer">
          {wallet.address && <AddressChip address={wallet.address} explorer={cfg.explorer} />}
          <span className="val dim">{balance}</span>
          {gate === 'switch' && (
            <button type="button" className="secondary" onClick={() => wallet.switchChain(cfg).catch(() => {})}>
              Switch to {cfg.label}
            </button>
          )}
          {wallet.mode === 'throwaway' && (
            <>
              <button type="button" className="ghost" onClick={wallet.throwaway.generate}>
                New
              </button>
              <button type="button" className="ghost" onClick={wallet.throwaway.clear}>
                Forget
              </button>
            </>
          )}
        </span>
      )}
    </div>
  )
}

/** Signer guidance under the header — only what the current state needs. */
export function WalletNotes({ cfg, wallet }: { cfg: ChainConfig; wallet: Wallet }) {
  if (wallet.mode !== 'throwaway') return null
  if (!wallet.address)
    return (
      <Note kind="info">
        {cfg.label} carries type-<code>0x06</code> frame transactions, which browser wallets can't sign — this network
        signs with a random in-page key kept in this browser's storage. Generate one (header), then fund it at the{' '}
        <a href={FAUCET_URL} target="_blank" rel="noreferrer">
          frames faucet ↗
        </a>
        ; it only ever holds faucet ETH.
      </Note>
    )
  if (wallet.balance === 0n)
    return (
      <Note kind="warn">
        The in-page wallet is empty. Copy its address from the header, open the{' '}
        <a href={FAUCET_URL} target="_blank" rel="noreferrer">
          frames faucet ↗
        </a>
        , paste it and request test ETH — the balance updates here automatically.
      </Note>
    )
  return null
}
