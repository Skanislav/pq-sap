// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

import {Pq7913Signer} from "./Pq7913Signer.sol";

/// @title Stealth7913Account
/// @notice Minimal stealth-account harness for the ERC-7913 spend route (D-014):
///         the account holds only the signer bytes `verifier || key`, all
///         verification logic lives in the shared stateless verifier. With the
///         ETHDILITHIUM pointer-key encoding the signer is 40 bytes, so account
///         initcode stays far below the EIP-3860 cap regardless of PQ key sizes
///         (contrast D-005, where initcode-embedded keys overflowed it).
///
///         `Pq7913Signer` (issue #32): a verifier call that does not complete
///         (gas exhaustion under a caller's cap) reverts `VerifierCallFailed`
///         instead of reporting "invalid" — through both the ERC-1271 and the
///         ERC-4337 surfaces.
contract Stealth7913Account is Pq7913Signer, IERC1271 {
    constructor(bytes memory signer_) Pq7913Signer(signer_) {}

    /// @notice ERC-1271 surface over the ERC-7913 signer.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        return _rawSignatureValidation(hash, signature) ? IERC1271.isValidSignature.selector : bytes4(0xffffffff);
    }
}
