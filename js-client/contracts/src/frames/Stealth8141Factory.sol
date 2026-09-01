// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {PKContract} from "ethdilithium/ZKNOX_PKContract.sol";

import {IFrameTxContext} from "./IFrameTxContext.sol";
import {Stealth8141Account} from "./Stealth8141Account.sol";

/// @title Stealth8141Factory
/// @notice CREATE2 factory for `Stealth8141Account`, the frame-transaction twin of
///         `Stealth7913Factory`: the announced stealth address IS the counterfactual
///         account address bound to the blinded ML-DSA key (via its PKContract), so
///         sender and scanner derive it from the key material alone. Same ABI as the
///         4337 factory, so the client code is shared. Both deployments use salt 0.
contract Stealth8141Factory {
    address public immutable verifier;
    IFrameTxContext public immutable frameCtx;

    constructor(address verifier_, IFrameTxContext frameCtx_) {
        verifier = verifier_;
        frameCtx = frameCtx_;
    }

    /// @notice Counterfactual address of the key's PKContract (the ERC-7913 `key`).
    function getPKAddress(uint256[][][] memory aHat, bytes memory tr, uint256[][] memory t1)
        public
        view
        returns (address)
    {
        bytes32 initHash = keccak256(
            abi.encodePacked(type(PKContract).creationCode, abi.encode(aHat, tr, t1)));
        return Create2.computeAddress(bytes32(0), initHash, address(this));
    }

    /// @notice Counterfactual stealth account address — what gets announced.
    function getAccountAddress(uint256[][][] memory aHat, bytes memory tr, uint256[][] memory t1)
        public
        view
        returns (address)
    {
        bytes memory signer = abi.encodePacked(verifier, getPKAddress(aHat, tr, t1));
        bytes32 initHash = keccak256(abi.encodePacked(
            type(Stealth8141Account).creationCode, abi.encode(signer, frameCtx)));
        return Create2.computeAddress(bytes32(0), initHash, address(this));
    }

    /// @notice Deploy PKContract + account for the key. Idempotent — safe as the first
    ///         frame of the spending tx itself.
    function createAccount(uint256[][][] memory aHat, bytes memory tr, uint256[][] memory t1)
        external
        returns (address account)
    {
        account = getAccountAddress(aHat, tr, t1);
        if (account.code.length > 0) return account;

        address pk = getPKAddress(aHat, tr, t1);
        if (pk.code.length == 0) {
            pk = address(new PKContract{salt: bytes32(0)}(aHat, tr, t1));
        }
        bytes memory signer = abi.encodePacked(verifier, pk);
        account = address(new Stealth8141Account{salt: bytes32(0)}(signer, frameCtx));
    }
}
