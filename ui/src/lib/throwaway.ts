/**
 * A throwaway browser wallet for the frames testnet demo: a random secp256k1
 * key generated in-page and kept in localStorage. Testnet only — this key never
 * holds anything but faucet funds, and the frames tab signs 0x06 transactions
 * with it (browser wallets can't sign type 0x06).
 */

import { useCallback, useState } from 'react'
import { type Address, type Hex } from 'viem'
import { generatePrivateKey, privateKeyToAddress } from 'viem/accounts'

const STORAGE_KEY = 'frames-throwaway-key-v1'

export interface ThrowawayWallet {
  address: Address | null
  privateKey: Hex | null
  /** create a fresh random key (replaces any existing one) */
  generate: () => void
  /** forget the current key */
  clear: () => void
}

function load(): Hex | null {
  try {
    const v = localStorage.getItem(STORAGE_KEY)
    return v && /^0x[0-9a-f]{64}$/i.test(v) ? (v as Hex) : null
  } catch {
    return null
  }
}

export function useThrowawayWallet(): ThrowawayWallet {
  const [privateKey, setPrivateKey] = useState<Hex | null>(() => load())

  const generate = useCallback(() => {
    const pk = generatePrivateKey()
    try {
      localStorage.setItem(STORAGE_KEY, pk)
    } catch {
      /* storage disabled — key lives in memory for this session only */
    }
    setPrivateKey(pk)
  }, [])

  const clear = useCallback(() => {
    try {
      localStorage.removeItem(STORAGE_KEY)
    } catch {
      /* ignore */
    }
    setPrivateKey(null)
  }, [])

  const address = privateKey ? privateKeyToAddress(privateKey) : null
  return { address, privateKey, generate, clear }
}
