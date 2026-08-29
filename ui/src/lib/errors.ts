import { BaseError, ContractFunctionRevertedError, UserRejectedRequestError } from 'viem';

/** Translate wallet/contract failures into something a person can read. */
export function parseTxError(e: unknown): string {
  if (e instanceof BaseError) {
    if (e.walk((x) => x instanceof UserRejectedRequestError))
      return 'Transaction rejected in the wallet.';
    const revert = e.walk((x) => x instanceof ContractFunctionRevertedError);
    if (revert instanceof ContractFunctionRevertedError)
      return `Contract reverted: ${revert.reason ?? revert.shortMessage}`;
    return e.shortMessage;
  }
  if (e instanceof Error) return e.message;
  return 'Unknown error — see the browser console.';
}
