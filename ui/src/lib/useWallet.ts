/**
 * Wallet state: injected wallet (EIP-1193) or the anvil dev account.
 * The dev account keeps the local demo one-click; injected is the real path.
 */

import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  type Address,
  createWalletClient,
  custom,
  type EIP1193Provider,
  http,
  numberToHex,
  type WalletClient,
} from 'viem'
import { privateKeyToAccount } from 'viem/accounts'

import { ANVIL_DEV_KEY, type ChainConfig } from './chain.ts'

declare global {
  interface Window {
    ethereum?: EIP1193Provider
  }
}

export type WalletMode = 'injected' | 'dev'

export interface Wallet {
  mode: WalletMode
  setMode: (m: WalletMode) => void
  hasInjected: boolean
  address: Address | null
  chainId: number | null // injected wallet's current chain
  connecting: boolean
  connect: () => Promise<void>
  switchChain: (cfg: ChainConfig) => Promise<void>
  /** wallet client bound to cfg, or null when not ready */
  clientFor: (cfg: ChainConfig) => WalletClient | null
  /** what the primary action button should do first (four-state flow) */
  gate: (cfg: ChainConfig) => 'connect' | 'switch' | 'ready'
}

const devAccount = privateKeyToAccount(ANVIL_DEV_KEY)

export function useWallet(): Wallet {
  const hasInjected = typeof window !== 'undefined' && !!window.ethereum
  const [mode, setMode] = useState<WalletMode>('dev')
  const [address, setAddress] = useState<Address | null>(null)
  const [chainId, setChainId] = useState<number | null>(null)
  const [connecting, setConnecting] = useState(false)

  useEffect(() => {
    const eth = window.ethereum
    if (!eth) return
    const onAccounts = (accounts: unknown) => {
      const list = accounts as string[]
      setAddress(list.length ? (list[0] as Address) : null)
    }
    const onChain = (id: unknown) => setChainId(parseInt(id as string, 16))
    eth.on('accountsChanged', onAccounts)
    eth.on('chainChanged', onChain)
    // pick up an already-authorized connection without prompting
    eth
      .request({ method: 'eth_accounts' })
      .then(onAccounts)
      .catch(() => {})
    eth
      .request({ method: 'eth_chainId' })
      .then(onChain)
      .catch(() => {})
    return () => {
      eth.removeListener('accountsChanged', onAccounts)
      eth.removeListener('chainChanged', onChain)
    }
  }, [])

  const connect = useCallback(async () => {
    const eth = window.ethereum
    if (!eth) throw new Error('no injected wallet found')
    setConnecting(true)
    try {
      const accounts = (await eth.request({ method: 'eth_requestAccounts' })) as string[]
      setAddress(accounts.length ? (accounts[0] as Address) : null)
      const id = (await eth.request({ method: 'eth_chainId' })) as string
      setChainId(parseInt(id, 16))
    } finally {
      setConnecting(false)
    }
  }, [])

  const switchChain = useCallback(async (cfg: ChainConfig) => {
    const eth = window.ethereum
    if (!eth) return
    const hexId = numberToHex(cfg.chain.id)
    try {
      await eth.request({
        method: 'wallet_switchEthereumChain',
        params: [{ chainId: hexId }],
      })
    } catch (e) {
      // 4902 = unknown chain — offer to add it (relevant for local anvil)
      if ((e as { code?: number }).code === 4902) {
        await eth.request({
          method: 'wallet_addEthereumChain',
          params: [
            {
              chainId: hexId,
              chainName: cfg.label,
              nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
              rpcUrls: [cfg.rpcUrl],
            },
          ],
        })
      } else throw e
    }
  }, [])

  const clientFor = useCallback(
    (cfg: ChainConfig): WalletClient | null => {
      if (mode === 'dev') {
        if (cfg.key !== 'anvil') return null
        return createWalletClient({
          chain: cfg.chain,
          transport: http(cfg.rpcUrl),
          account: devAccount,
        })
      }
      if (!window.ethereum || !address) return null
      return createWalletClient({
        chain: cfg.chain,
        transport: custom(window.ethereum),
        account: address,
      })
    },
    [mode, address],
  )

  const gate = useCallback(
    (cfg: ChainConfig): 'connect' | 'switch' | 'ready' => {
      if (mode === 'dev') return cfg.key === 'anvil' ? 'ready' : 'connect'
      if (!address) return 'connect'
      if (chainId !== cfg.chain.id) return 'switch'
      return 'ready'
    },
    [mode, address, chainId],
  )

  return useMemo(
    () => ({
      mode,
      setMode,
      hasInjected,
      address: mode === 'dev' ? devAccount.address : address,
      chainId,
      connecting,
      connect,
      switchChain,
      clientFor,
      gate,
    }),
    [mode, hasInjected, address, chainId, connecting, connect, switchChain, clientFor, gate],
  )
}
