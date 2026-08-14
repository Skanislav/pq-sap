// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SignerERC7913} from "@openzeppelin/contracts/utils/cryptography/signers/SignerERC7913.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

/// @title Stealth7913Account
/// @notice Minimal stealth-account harness for the ERC-7913 spend route (D-014):
///         the account holds only the signer bytes `verifier || key`, all
///         verification logic lives in the shared stateless verifier. With the
///         ETHDILITHIUM pointer-key encoding the signer is 40 bytes, so account
///         initcode stays far below the EIP-3860 cap regardless of PQ key sizes
///         (contrast D-005, where initcode-embedded keys overflowed it).
contract Stealth7913Account is SignerERC7913, IERC1271 {
    constructor(bytes memory signer_) SignerERC7913(signer_) {}

    /// @notice ERC-1271 surface over the ERC-7913 signer.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        return _rawSignatureValidation(hash, signature) ? IERC1271.isValidSignature.selector : bytes4(0xffffffff);
    }
}
