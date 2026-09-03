// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

import {IFrameTxContext} from "./IFrameTxContext.sol";
import {IProofVerifier, Stealth8141ZkAccount} from "./Stealth8141ZkAccount.sol";

/// @title Stealth8141ZkFactory
/// @notice CREATE2 factory for `Stealth8141ZkAccount`, keyed by the D-018 commitment
///         `keccak256("pq-stealth/sphincs-c13/commit/v0" || pk || opener)`: the announced
///         stealth address is the counterfactual account of that commitment, which the
///         sender computes from the meta-address key and the KEM shared secret and the
///         scanner re-derives. Nothing about the key is on chain until it is never revealed
///         at all — spends carry a proof, not the key.
contract Stealth8141ZkFactory {
    IProofVerifier public immutable verifier;
    IFrameTxContext public immutable frameCtx;

    constructor(IProofVerifier verifier_, IFrameTxContext frameCtx_) {
        verifier = verifier_;
        frameCtx = frameCtx_;
    }

    function getAccountAddress(bytes32 commitment) public view returns (address) {
        bytes32 initHash = keccak256(abi.encodePacked(
            type(Stealth8141ZkAccount).creationCode, abi.encode(commitment, verifier, frameCtx)));
        return Create2.computeAddress(bytes32(0), initHash, address(this));
    }

    /// @notice Deploy the account for `commitment`. Idempotent; small enough (no key
    ///         material) to be the first frame of the spending transaction.
    function createAccount(bytes32 commitment) external returns (address account) {
        account = getAccountAddress(commitment);
        if (account.code.length > 0) return account;
        account = address(new Stealth8141ZkAccount{salt: bytes32(0)}(commitment, verifier, frameCtx));
    }
}
