/**
 * EIP-8141 frame-transaction networks.
 *
 * T-pub: the public ethrex frames testnet (faucet https://faucet.frames.ethrex.xyz/).
 *   ethrex-only, single proposer, default MAX_VERIFY_GAS — good for the wire
 *   format, receive, cheap/non-PQ frames; cannot admit PQ verify frames.
 * T-enc: the local kurtosis enclave (devnet/enclave.json), needed for PQ spends
 *   (raised MAX_VERIFY_GAS on Nethermind) and cross-client consensus checks.
 */

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export interface FramesNetwork {
  name: string;
  chainId: bigint;
  rpcUrl: string;
  explorerTx?: (hash: string) => string;
}

export const FRAMES_PUBLIC: FramesNetwork = {
  name: 'frames-testnet',
  chainId: 81410n,
  rpcUrl: 'https://rpc1.frames.ethrex.xyz',
  explorerTx: (h) => `https://dora.frames.ethrex.xyz/tx/${h}`,
};

/** Well-known ethereum-package genesis key, funded on both T-pub and any enclave. */
export const DEV_KEY = {
  address: '0x8943545177806ED17B9F23F0a21ee5948eCaa776',
  privateKey: '0xbcdf20249abf0ed6d944c0288fad489e33f66b3960d9e6229c1cd214ed3bbe31',
} as const;

const ENCLAVE_PATH = fileURLToPath(new URL('../../devnet/enclave.json', import.meta.url));

/** The local enclave's Nethermind RPC (raised MAX_VERIFY_GAS), if devnet/up.mjs has run. */
export function enclaveNethermind(): FramesNetwork | null {
  if (!existsSync(ENCLAVE_PATH)) return null;
  const j = JSON.parse(readFileSync(ENCLAVE_PATH, 'utf8')) as
    { chainId: number; nethermind: { rpc: string | null } };
  if (!j.nethermind?.rpc) return null;
  return { name: 'frames-enclave-nethermind', chainId: BigInt(j.chainId), rpcUrl: j.nethermind.rpc };
}
