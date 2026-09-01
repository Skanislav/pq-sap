// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SignerERC7913} from "@openzeppelin/contracts/utils/cryptography/signers/SignerERC7913.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

import {IFrameTxContext} from "./IFrameTxContext.sol";

/// @title Stealth8141Account
/// @notice Stealth account spent through an EIP-8141 frame transaction, authorized by a
///         post-quantum ERC-7913 signature (the blinded ML-DSA stealth key) and paid for
///         by anyone — the D-020 "frames instead of 4337" spend route, in the shape that
///         a public network admits today.
///
///         The account is NOT the frame tx's `sender` and never calls APPROVE. A sponsor
///         (any EOA; the demo uses the wallet's own throwaway key) is sender and payer,
///         so the mempool-bounded validation prefix (MAX_VERIFY_GAS = 100k) holds only
///         the sponsor's protocol-checked secp256k1 signature. The ML-DSA verification
///         (several million gas) then runs in a post-prefix execution frame, where only
///         the block gas limit applies. A self-paying PQ account — APPROVE(EXECUTION)
///         inside a VERIFY frame — is the same contract minus the sponsor, but needs a
///         node with a raised MAX_VERIFY_GAS (the local Nethermind enclave).
///
///         Authorization of `executeFrame`:
///           * `msg.sender` must be the protocol ENTRY_POINT, i.e. this call IS a DEFAULT
///             frame of the current transaction. Its calldata — (sigIndex, to, value, data)
///             — is therefore the frame's `data`, which `sig_hash` commits to.
///           * the ARBITRARY-scheme signature at `sigIndex` in `tx.signatures` must be a
///             valid ERC-7913 signature over `sig_hash` (TXPARAM 0x08), which commits to
///             the chain id, the sponsor and its nonce, and every frame; only the raw
///             signature bytes themselves are elided. The digest comes from the protocol,
///             never from calldata (cf. the calldata-digest replay flaw in
///             nconsigny/SPHINCS-'s frame account).
///         So the PQ signature authorizes exactly one (sponsor, nonce, frames) tuple: it
///         cannot be replayed, re-sponsored, or attached to an altered spend.
contract Stealth8141Account is SignerERC7913, IERC1271 {
    /// @notice EIP-8141 ENTRY_POINT: the caller of DEFAULT and VERIFY frames.
    address public constant ENTRY_POINT = address(0xaa); // 0x…00aa

    IFrameTxContext public immutable FRAME_CTX;

    error NotEntryPoint(address caller);
    error NotAuthorized();
    error CallFailed(bytes returnData);

    constructor(bytes memory signer_, IFrameTxContext frameCtx_) SignerERC7913(signer_) {
        FRAME_CTX = frameCtx_;
    }

    receive() external payable {}

    /// @notice Execute `to.call{value}(data)` from this account, inside a frame
    ///         transaction, authorized by the PQ signature at `sigIndex`.
    function executeFrame(uint256 sigIndex, address to, uint256 value, bytes calldata data) external {
        if (msg.sender != ENTRY_POINT) revert NotEntryPoint(msg.sender);
        bytes32 digest = FRAME_CTX.sigHash();
        bytes memory sig = FRAME_CTX.signature(sigIndex);
        // same ERC-7913 path as _rawSignatureValidation, for a memory signature
        if (!SignatureChecker.isValidSignatureNow(signer(), digest, sig)) revert NotAuthorized();
        (bool ok, bytes memory ret) = to.call{value: value}(data);
        if (!ok) revert CallFailed(ret);
    }

    /// @notice ERC-1271 surface over the ERC-7913 signer.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        return _rawSignatureValidation(hash, signature) ? IERC1271.isValidSignature.selector : bytes4(0xffffffff);
    }
}
