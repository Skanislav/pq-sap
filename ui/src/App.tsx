import { useState } from 'react'
import { AddressChip, Note } from './components/bits.tsx'
import { FramesTab } from './components/FramesTab.tsx'
import { RecipientTab } from './components/RecipientTab.tsx'
import { ScanTab } from './components/ScanTab.tsx'
import { SendTab } from './components/SendTab.tsx'
import { SpendTab } from './components/SpendTab.tsx'
import { WalletBar, WalletNotes } from './components/WalletBar.tsx'
import { CHAINS, type ChainConfig, type ChainKey } from './lib/chain.ts'
import { toHex } from './lib/hex.ts'
import type { RecipientKeys } from './lib/keygen.ts'
import { useEthUsd } from './lib/useEthUsd.ts'
import { useWallet } from './lib/useWallet.ts'

type Tab = 'recipient' | 'send' | 'scan' | 'spend' | 'frames'

const TAB_LABEL: Record<Tab, string> = {
  recipient: '1 · Recipient',
  send: '2 · Send',
  scan: '3 · Scan',
  spend: '4 · Spend',
  frames: '5 · Frame tx',
}

export default function App() {
  const [tab, setTab] = useState<Tab>('recipient')
  const [chainKey, setChainKey] = useState<ChainKey>('anvil')
  const [keys, setKeys] = useState<RecipientKeys | null>(null)
  const cfg: ChainConfig = CHAINS[chainKey]
  const wallet = useWallet(cfg)
  const ethUsd = useEthUsd()

  return (
    <div className="app">
      <header>
        <div>
          <h1>PQ Stealth Addresses</h1>
          <p className="tagline">ERC-5564 scheme 2 — ML-KEM-768 discovery + ML-DSA-65 key blinding</p>
        </div>
        <WalletBar cfg={cfg} chainKey={chainKey} setChainKey={setChainKey} wallet={wallet} />
      </header>

      <WalletNotes cfg={cfg} wallet={wallet} />

      <nav className="tabs">
        {(Object.keys(TAB_LABEL) as Tab[]).map((t) => (
          <button type="button" key={t} className={t === tab ? 'tab active' : 'tab'} onClick={() => setTab(t)}>
            {TAB_LABEL[t]}
          </button>
        ))}
      </nav>

      {tab === 'frames' && !cfg.frames && (
        <Note kind="info">Frame transactions live only on the Frames testnet — switch the Network selector above.</Note>
      )}

      <main>
        {tab === 'recipient' && <RecipientTab keys={keys} setKeys={setKeys} />}
        {tab === 'send' && (
          <SendTab cfg={cfg} wallet={wallet} ethUsd={ethUsd} myMetaAddress={keys ? toHex(keys.metaAddress) : null} />
        )}
        {tab === 'scan' && <ScanTab cfg={cfg} keys={keys} ethUsd={ethUsd} />}
        {tab === 'spend' && <SpendTab cfg={cfg} wallet={wallet} ethUsd={ethUsd} />}
        {tab === 'frames' && <FramesTab cfg={CHAINS.frames} wallet={wallet} />}
      </main>

      <footer>
        <span>
          Announcer <AddressChip address={cfg.announcer} explorer={cfg.explorer} /> on {cfg.label}
        </span>
        <span className="fine">Reference UI — keys are demo-grade browser storage. Spec: docs/erc-draft.md</span>
      </footer>
    </div>
  )
}
