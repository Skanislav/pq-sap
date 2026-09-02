/**
 * Wallet state — one signer per network, chosen by the network:
 *
 *   anvil    the anvil dev account (one-click local demo) or an injected
 *            EIP-1193 wallet
 *   sepolia  an injected EIP-1193 wallet
 *   frames   the in-page throwaway key — browser wallets can't sign type-0x06
 *            frame transactions, so a random secp256k1 key kept in
 *            localStorage signs on the frames testnet (faucet funds only)
 *
 * The three signers replace one another; the header is the only place they
 * are managed. `clientFor` hands every route a viem wallet client for the
 * active signer, and the frames routes read the raw key via `throwaway`.
 */

import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  type Address,
  createWalletClient,
  custom,
  type EIP1193Provider,
  type Hex,
  http,
  numberToHex,
  type WalletClient,
} from 'viem'
import { privateKeyToAccount } from 'viem/accounts'

import { ANVIL_DEV_KEY, type ChainConfig } from './chain.ts'
import { useNativeBalance } from './frames.ts'
import { type ThrowawayWallet, useThrowawayWallet } from './throwaway.ts'

declare global {
  interface Window {
    ethereum?: EIP1193Provider
  }
}

export type WalletMode = 'injected' | 'dev' | 'throwaway'

export const MODE_LABEL: Record<WalletMode, string> = {
  dev: 'anvil dev account',
  injected: 'browser wallet',
  throwaway: 'in-page frames wallet',
}

export interface Wallet {
  /** the signer in effect on the current network */
  mode: WalletMode
  /** signers the current network admits (the first is the default) */
  modes: WalletMode[]
  /** pick between the admitted signers (a no-op when there is only one) */
  setMode: (m: WalletMode) => void
  hasInjected: boolean
  address: Address | null
  /** native balance of `address` on the current network, null while unknown */
  balance: bigint | null
  chainId: number | null // injected wallet's current chain
  connecting: boolean
  /** injected: request accounts; throwaway: generate the in-page key */
  connect: () => Promise<void>
  switchChain: (cfg: ChainConfig) => Promise<void>
  /** wallet client bound to cfg, or null when not ready */
  clientFor: (cfg: ChainConfig) => WalletClient | null
  /** what the primary action button should do first (four-state flow) */
  gate: (cfg: ChainConfig) => 'connect' | 'switch' | 'ready'
  /** the in-page key (frames networks); address/privateKey null until generated */
  throwaway: ThrowawayWallet
  /** the active signer's raw key when it lives in the page (dev, throwaway) */
  privateKey: Hex | null
}

const devAccount = privateKeyToAccount(ANVIL_DEV_KEY)

export function modesFor(cfg: ChainConfig): WalletMode[] {
  if (cfg.frames) return ['throwaway']
  if (cfg.key === 'anvil') return ['dev', 'injected']
  return ['injected']
}

export function useWallet(cfg: ChainConfig): Wallet {
  const hasInjected = typeof window !== 'undefined' && !!window.ethereum
  const [preferred, setPreferred] = useState<WalletMode>('dev')
  const [injectedAddress, setInjectedAddress] = useState<Address | null>(null)
  const [chainId, setChainId] = useState<number | null>(null)
  const [connecting, setConnecting] = useState(false)
  const throwaway = useThrowawayWallet()

  const modes = useMemo(() => modesFor(cfg), [cfg])
  const mode: WalletMode = modes.includes(preferred) ? preferred : modes[0]!

  useEffect(() => {
    const eth = window.ethereum
    if (!eth) return
    const onAccounts = (accounts: unknown) => {
      const list = accounts as string[]
      setInjectedAddress(list.length ? (list[0] as Address) : null)
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

  const address: Address | null =
    mode === 'dev' ? devAccount.address : mode === 'throwaway' ? throwaway.address : injectedAddress
  const balance = useNativeBalance(cfg.rpcUrl, address)

  const connect = useCallback(async () => {
    if (mode === 'throwaway') {
      if (!throwaway.address) throwaway.generate()
      return
    }
    const eth = window.ethereum
    if (!eth) throw new Error('no injected wallet found')
    setConnecting(true)
    try {
      const accounts = (await eth.request({ method: 'eth_requestAccounts' })) as string[]
      setInjectedAddress(accounts.length ? (accounts[0] as Address) : null)
      const id = (await eth.request({ method: 'eth_chainId' })) as string
      setChainId(parseInt(id, 16))
    } finally {
      setConnecting(false)
    }
  }, [mode, throwaway])

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
        return createWalletClient({ chain: cfg.chain, transport: http(cfg.rpcUrl), account: devAccount })
      }
      if (mode === 'throwaway') {
        if (!throwaway.privateKey) return null
        return createWalletClient({
          chain: cfg.chain,
          transport: http(cfg.rpcUrl),
          account: privateKeyToAccount(throwaway.privateKey),
        })
      }
      if (!window.ethereum || !injectedAddress) return null
      return createWalletClient({ chain: cfg.chain, transport: custom(window.ethereum), account: injectedAddress })
    },
    [mode, injectedAddress, throwaway.privateKey],
  )

  const gate = useCallback(
    (cfg: ChainConfig): 'connect' | 'switch' | 'ready' => {
      if (mode === 'dev') return cfg.key === 'anvil' ? 'ready' : 'connect'
      if (mode === 'throwaway') return throwaway.address ? 'ready' : 'connect'
      if (!injectedAddress) return 'connect'
      if (chainId !== cfg.chain.id) return 'switch'
      return 'ready'
    },
    [mode, injectedAddress, chainId, throwaway.address],
  )

  return useMemo(
    () => ({
      mode,
      modes,
      setMode: setPreferred,
      hasInjected,
      address,
      balance,
      chainId,
      connecting,
      connect,
      switchChain,
      clientFor,
      gate,
      throwaway,
      privateKey: mode === 'dev' ? ANVIL_DEV_KEY : mode === 'throwaway' ? throwaway.privateKey : null,
    }),
    [mode, modes, hasInjected, address, balance, chainId, connecting, connect, switchChain, clientFor, gate, throwaway],
  )
}
