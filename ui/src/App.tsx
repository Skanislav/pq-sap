import { useState } from 'react';

import { CHAINS, type ChainConfig } from './lib/chain.ts';
import { toHex } from './lib/hex.ts';
import { useWallet } from './lib/useWallet.ts';
import { useEthUsd } from './lib/useEthUsd.ts';
import type { RecipientKeys } from './lib/keygen.ts';
import { AddressChip, Note } from './components/bits.tsx';
import { RecipientTab } from './components/RecipientTab.tsx';
import { SendTab } from './components/SendTab.tsx';
import { ScanTab } from './components/ScanTab.tsx';
import { SpendTab } from './components/SpendTab.tsx';

type Tab = 'recipient' | 'send' | 'scan' | 'spend';

export default function App() {
  const [tab, setTab] = useState<Tab>('recipient');
  const [chainKey, setChainKey] = useState<'anvil' | 'sepolia'>('anvil');
  const [keys, setKeys] = useState<RecipientKeys | null>(null);
  const wallet = useWallet();
  const ethUsd = useEthUsd();
  const cfg: ChainConfig = CHAINS[chainKey];

  return (
    <div className="app">
      <header>
        <div>
          <h1>PQ Stealth Addresses</h1>
          <p className="tagline">
            ERC-5564 scheme 2 — ML-KEM-768 discovery + ML-DSA-65 key blinding
          </p>
        </div>
        <div className="walletbox">
          <select
            value={chainKey} aria-label="Network"
            onChange={(e) => setChainKey(e.target.value as 'anvil' | 'sepolia')}
          >
            {Object.values(CHAINS).map((c) => (
              <option key={c.key} value={c.key}>{c.label}</option>
            ))}
          </select>
          <select
            value={wallet.mode} aria-label="Signer"
            onChange={(e) => wallet.setMode(e.target.value as 'dev' | 'injected')}
          >
            <option value="dev">anvil dev account</option>
            <option value="injected" disabled={!wallet.hasInjected}>
              browser wallet{wallet.hasInjected ? '' : ' (none found)'}
            </option>
          </select>
          {wallet.mode === 'injected' && !wallet.address ? (
            <button disabled={wallet.connecting} onClick={() => wallet.connect().catch(() => {})}>
              {wallet.connecting ? 'Connecting…' : 'Connect wallet'}
            </button>
          ) : wallet.address ? (
            <AddressChip address={wallet.address} explorer={cfg.explorer} />
          ) : null}
        </div>
      </header>

      {wallet.mode === 'dev' && chainKey !== 'anvil' && (
        <Note kind="warn">
          The anvil dev account only works on the local chain — switch the signer to a
          browser wallet to use {cfg.label}.
        </Note>
      )}

      <nav className="tabs">
        {(['recipient', 'send', 'scan', 'spend'] as const).map((t) => (
          <button
            key={t}
            className={t === tab ? 'tab active' : 'tab'}
            onClick={() => setTab(t)}
          >
            {t === 'recipient' ? '1 · Recipient' : t === 'send' ? '2 · Send'
              : t === 'scan' ? '3 · Scan' : '4 · Spend'}
          </button>
        ))}
      </nav>

      <main>
        {tab === 'recipient' && <RecipientTab keys={keys} setKeys={setKeys} />}
        {tab === 'send' && (
          <SendTab
            cfg={cfg} wallet={wallet} ethUsd={ethUsd}
            myMetaAddress={keys ? toHex(keys.metaAddress) : null}
          />
        )}
        {tab === 'scan' && <ScanTab cfg={cfg} keys={keys} ethUsd={ethUsd} />}
        {tab === 'spend' && <SpendTab cfg={cfg} wallet={wallet} ethUsd={ethUsd} />}
      </main>

      <footer>
        <span>
          Announcer <AddressChip address={cfg.announcer} explorer={cfg.explorer} /> on {cfg.label}
        </span>
        <span className="fine">
          Reference UI — keys are demo-grade browser storage. Spec: docs/erc-draft.md
        </span>
      </footer>
    </div>
  );
}
