// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Account} from "@openzeppelin/contracts/account/Account.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IEntryPoint} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";

import {Pq7913Signer} from "./Pq7913Signer.sol";

/// @title Stealth7913Account4337
/// @notice ERC-4337 stealth account for the ERC-7913 spend route (D-014):
///         OpenZeppelin `Account` provides userOp validation and prefund
///         payment, `SignerERC7913` validates against the immutable signer
///         bytes `verifier || key` (40 B with the ETHDILITHIUM pointer-key
///         encoding), so the blinded post-quantum stealth key alone
///         authorizes spends. The EntryPoint is constructor-provided so the
///         account works on chains where the canonical singleton is absent
///         (local anvil).
///
///         `Pq7913Signer` (issue #32): a verifier call that does not complete
///         (gas exhaustion under the EntryPoint's verification-gas cap)
///         reverts `VerifierCallFailed` on the ERC-1271 surface, and through
///         `Account._validateUserOp` the EntryPoint sees a reverted validation
///         (time-0 failure) instead of a silent "signature invalid". Both are
///         failures — but an integrator decoding the revert can tell
///         underfunding from forgery.
contract Stealth7913Account4337 is Account, Pq7913Signer, IERC1271 {
    IEntryPoint private immutable _entryPoint;

    constructor(bytes memory signer_, IEntryPoint entryPoint_) Pq7913Signer(signer_) {
        _entryPoint = entryPoint_;
    }

    function entryPoint() public view override returns (IEntryPoint) {
        return _entryPoint;
    }

    /// @notice Minimal execution surface, EntryPoint-gated (matches the
    ///         `execute(address,uint256,bytes)` ABI the client builds).
    function execute(address target, uint256 value, bytes calldata data)
        external
        onlyEntryPointOrSelf
    {
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 0x20), mload(ret))
            }
        }
    }

    /// @notice ERC-1271 surface over the ERC-7913 signer.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        return _rawSignatureValidation(hash, signature) ? IERC1271.isValidSignature.selector : bytes4(0xffffffff);
    }
}
