// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {IEntryPoint} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {PKContract} from "ethdilithium/ZKNOX_PKContract.sol";

import {Stealth7913Account4337} from "./Stealth7913Account4337.sol";

/// @title Stealth7913Factory
/// @notice CREATE2 factory binding a stealth account address to the blinded
///         stealth key: the announced stealth address IS the counterfactual
///         account address — derivable by sender and scanner alike from the
///         derived key material, and spendable through ERC-4337 once the
///         recipient deploys it. Both deployments use salt 0: the addresses
///         are already fully determined by the key material in the initcode.
contract Stealth7913Factory {
    address public immutable verifier;
    IEntryPoint public immutable entryPoint;

    constructor(address verifier_, IEntryPoint entryPoint_) {
        verifier = verifier_;
        entryPoint = entryPoint_;
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
            type(Stealth7913Account4337).creationCode, abi.encode(signer, entryPoint)));
        return Create2.computeAddress(bytes32(0), initHash, address(this));
    }

    /// @notice Deploy PKContract + account for the key. Idempotent.
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
        account = address(new Stealth7913Account4337{salt: bytes32(0)}(signer, entryPoint));
    }
}
