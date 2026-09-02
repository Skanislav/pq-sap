/**
 * A throwaway browser wallet for the frames testnet demo: a random secp256k1
 * key generated in-page and persisted in localStorage. Testnet only — this key
 * never holds anything but faucet funds, and the frames tab signs 0x06
 * transactions with it (browser wallets can't sign type 0x06).
 *
 * The wallet survives reloads and tab switches, and stays in sync across tabs.
 */

import { useCallback, useEffect, useMemo, useState } from 'react'
import { type Address, type Hex } from 'viem'
import { generatePrivateKey, privateKeyToAddress } from 'viem/accounts'

export const STORAGE_KEY = 'frames-throwaway-key-v1'

const isKey = (v: unknown): v is Hex => typeof v === 'string' && /^0x[0-9a-f]{64}$/i.test(v)

/** Read the persisted key, or null if absent/invalid/unavailable. */
export function loadStoredKey(): Hex | null {
  try {
    const v = localStorage.getItem(STORAGE_KEY)
    return isKey(v) ? v : null
  } catch {
    return null // storage disabled (private mode, SSR, etc.)
  }
}

/** Persist a key. No-op if storage is unavailable (key then lives in memory). */
export function storeKey(pk: Hex): void {
  try {
    localStorage.setItem(STORAGE_KEY, pk)
  } catch {
    /* ignore */
  }
}

/** Remove the persisted key. */
export function clearStoredKey(): void {
  try {
    localStorage.removeItem(STORAGE_KEY)
  } catch {
    /* ignore */
  }
}

export interface ThrowawayWallet {
  address: Address | null
  privateKey: Hex | null
  /** create a fresh random key (replaces any existing one) */
  generate: () => void
  /** forget the current key */
  clear: () => void
}

export function useThrowawayWallet(): ThrowawayWallet {
  const [privateKey, setPrivateKey] = useState<Hex | null>(() => loadStoredKey())

  // Keep multiple tabs consistent: react to localStorage changes elsewhere.
  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key === STORAGE_KEY) setPrivateKey(loadStoredKey())
    }
    window.addEventListener('storage', onStorage)
    return () => window.removeEventListener('storage', onStorage)
  }, [])

  const generate = useCallback(() => {
    const pk = generatePrivateKey()
    storeKey(pk)
    setPrivateKey(pk)
  }, [])

  const clear = useCallback(() => {
    clearStoredKey()
    setPrivateKey(null)
  }, [])

  const address = privateKey ? privateKeyToAddress(privateKey) : null
  return useMemo(() => ({ address, privateKey, generate, clear }), [address, privateKey, generate, clear])
}
