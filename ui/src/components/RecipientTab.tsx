/**
 * Recipient flow: generate (or load) the PQ stealth keypair set and
 * publish the meta-address. Scanning needs only the ML-KEM viewing key.
 */

import { useEffect, useState } from 'react';

import { deriveMetaAddress, randomSeeds, type RecipientKeys } from '../lib/keygen.ts';
import { fromHex, toHex } from '../lib/hex.ts';
import { loadSeeds, saveSeeds, clearSeeds } from '../lib/storage.ts';
import { HexBlob, Note } from './bits.tsx';

export function RecipientTab({ keys, setKeys }: {
  keys: RecipientKeys | null;
  setKeys: (k: RecipientKeys | null) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // restore persisted seeds once on mount
  useEffect(() => {
    if (keys) return;
    const seeds = loadSeeds();
    if (!seeds) return;
    try { setKeys(deriveMetaAddress(seeds)); } catch { clearSeeds(); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const generate = (seedSource: 'random' | 'vector-a') => {
    setBusy(true);
    setError(null);
    // yield to the event loop so the button repaints before the key math
    setTimeout(async () => {
      try {
        let k: RecipientKeys;
        if (seedSource === 'vector-a') {
          const vectors = (await import('../../../python/vectors/v0/vectors.json')).default;
          const s = (vectors as {
            recipients: Record<string, { seeds: { zeta: string; kem_d: string; kem_z: string } }>;
          }).recipients.A!.seeds;
          k = deriveMetaAddress({
            zeta: fromHex(s.zeta), kemD: fromHex(s.kem_d), kemZ: fromHex(s.kem_z) });
        } else {
          k = deriveMetaAddress(randomSeeds());
        }
        saveSeeds(k.seeds);
        setKeys(k);
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setBusy(false);
      }
    }, 20);
  };

  return (
    <section>
      <h2>Your stealth identity</h2>
      <p className="lede">
        One ML-DSA-65 spending key (kept as full-precision <code>t</code>) and one
        ML-KEM-768 viewing key. The <strong>meta-address</strong> below is the only
        thing you publish — via the ERC-6538 registry, ENS, or any side channel.
      </p>

      <div className="row">
        <button disabled={busy} onClick={() => generate('random')}>
          {busy ? 'Deriving…' : keys ? 'Generate new keys (replaces current)' : 'Generate keys'}
        </button>
        <button className="secondary" disabled={busy} onClick={() => generate('vector-a')}>
          Load test recipient A
        </button>
        {keys && (
          <button
            className="secondary" disabled={busy}
            onClick={() => { clearSeeds(); setKeys(null); }}
          >
            Forget keys
          </button>
        )}
      </div>

      {error && <Note kind="error">{error}</Note>}

      {keys && (
        <>
          <h3>Publish</h3>
          <HexBlob label="Meta-address" value={toHex(keys.metaAddress)} />
          <p className="fine">
            5,633 bytes: version <code>0x01</code> ‖ ρ (32 B) ‖ t packed at 23 bits/coeff
            (4,416 B) ‖ ML-KEM ek (1,184 B). Anyone holding this can pay you; nobody can
            link the payments.
          </p>

          <h3>Keep secret</h3>
          <HexBlob label="Viewing key (ML-KEM dk)" value={toHex(keys.kemDk)} secret />
          <HexBlob label="Key seed ζ (ML-DSA)" value={toHex(keys.seeds.zeta)} secret />
          <Note kind="warn">
            Demo storage only: seeds live in this browser's localStorage. The viewing key
            can detect your payments but cannot spend; the ζ seed derives the spending key.
          </Note>
        </>
      )}

      {!keys && !busy && (
        <Note kind="info">
          No keys yet. Generate a fresh identity, or load deterministic test
          recipient A (matches <code>python/vectors/v0</code> byte-for-byte — the
          dev chain's seeded announcements pay this identity).
        </Note>
      )}
    </section>
  );
}
