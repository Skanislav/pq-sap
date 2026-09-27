// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {IERC7913SignatureVerifier} from "@openzeppelin/contracts/interfaces/IERC7913.sol";

import {IProofVerifier} from "./Stealth8141ZkAccount.sol";

/// @title MlDsa44CommitFrameVerifier
/// @notice Adapts the `ml-dsa-44-commit/v0` ERC-7913 signer to the `IProofVerifier`
///         surface of `Stealth8141ZkAccount`, so the existing account, factory, and
///         CREATE2 binding (`Stealth8141ZkFactory(commitment, verifier, frameCtx)`,
///         salt 0) are reused unchanged: the "proof" is the direct authorization
///         payload `pk || opener || sig`, and the public inputs are the account's
///         `[digest_hi, digest_lo, commitment_hi, commitment_lo]` halves.
///
///         The account's `verifier` immutable-at-creation pointer is this adapter, and
///         this adapter's SIGNER is immutable, so a funded counterfactual address is
///         bound to exactly one authorization policy: a different signer, registry, or
///         verifier is a different adapter address, hence a different account address.
///         Rotation stays what the account defines (a self-call authorized under the
///         current policy).
///
///         This is a signature route, not a zero-knowledge one: `pk` is revealed on
///         spend and links the spent addresses of one recipient (see the signer).
contract MlDsa44CommitFrameVerifier is IProofVerifier {
    IERC7913SignatureVerifier public immutable SIGNER;

    constructor(IERC7913SignatureVerifier signer) {
        SIGNER = signer;
    }

    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool) {
        if (publicInputs.length != 4) return false;
        for (uint256 i = 0; i < 4; i++) {
            if (uint256(publicInputs[i]) >> 128 != 0) return false;
        }
        bytes32 digest = bytes32((uint256(publicInputs[0]) << 128) | uint256(publicInputs[1]));
        bytes32 commitment = bytes32((uint256(publicInputs[2]) << 128) | uint256(publicInputs[3]));
        return SIGNER.verify(abi.encodePacked(commitment), digest, proof) == IERC7913SignatureVerifier.verify.selector;
    }
}
