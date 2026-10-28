// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SignerERC7913} from "@openzeppelin/contracts/utils/cryptography/signers/SignerERC7913.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {IERC7913SignatureVerifier} from "@openzeppelin/contracts/interfaces/IERC7913.sol";
import {Bytes} from "@openzeppelin/contracts/utils/Bytes.sol";

/// @title Pq7913Signer
/// @notice `SignerERC7913` with verifier failures NOT swallowed: an ERC-7913
///         verifier call that does not complete (out of gas under a caller's gas
///         cap, or a malformed return) reverts with `VerifierCallFailed`, instead
///         of collapsing into "signature invalid" (issue #32).
///
///         Why: OpenZeppelin's `SignatureChecker.isValidSignatureNow` treats any
///         inner revert as "not authorized", so an integrator calling under a gas
///         cap cannot distinguish resource exhaustion from forgery, and gas
///         estimation settles on the cheap failure path. Here the distinction is
///         observable:
///
///           verifier call completes, answers != magic  ->  false ("invalid")
///           verifier call does not complete            ->  revert VerifierCallFailed
///
///         A gas-starved frame still reverts generically when even this revert
///         cannot be paid for; the window fixed is the practical one — the
///         account has gas for its own logic, the verifier does not. Where the
///         backend is pinned at account creation (`Stealth8141ZkAccount`), a gas
///         floor check makes underfunding cheap and self-describing; here the
///         verifier is caller-chosen (any `verifier || key` bytes at deployment),
///         so no floor is checkable. Consumers that catch reverts (an ERC-4337
///         EntryPoint treating a reverted `validateUserOp` as validation failure)
///         still see a failure — now an honest "this account was underfunded",
///         not a forged verdict.
///
///         Documented minimum gas for the shipped verifiers (whole-call, forge,
///         solc 0.8.30/prague; measured in GasExhaustion.t.sol and the ZkAccount
///         suites):
///           SphincsC13Asm.verify (vendored, via_ir)  ~110 k exec / ~188 k tx
///                                                        (C13 routes; D-019)
///           preimage-ownership proof, executeFrame    ~3.0 M  (ZK route)
///           UltraHonk C13 proof, executeFrame         ~3.6 M  (ZK route)
///           ZKNOX ML-DSA-44 (df999ed, stock, per verify)  ~16 M (D-027 route)
///           ZKNOX ML-DSA-65 (df999ed, stock, per verify)  ~15 M (frames route)
abstract contract Pq7913Signer is SignerERC7913 {
    /// @notice The ERC-7913 verifier call did not complete (out of gas, or a
    ///         malformed return); distinct from an invalid signature. Same shape
    ///         as `MlDsa44CommitSigner7913.VerifierCallFailed` so spend tooling
    ///         decodes one error across the layers.
    error VerifierCallFailed(bytes returnData);

    constructor(bytes memory signer_) SignerERC7913(signer_) {}

    /// @dev OZ's 7913 path, minus the revert swallowing. The `signer.length == 20`
    ///      branch (a plain address, ECDSA/ERC-1271) is delegated unchanged.
    function _rawSignatureValidation(bytes32 hash, bytes calldata signature) internal view override returns (bool) {
        return _validate7913(hash, signature);
    }

    /// @dev Memory-signature entry (frame signatures arrive as `bytes memory`).
    function _validate7913(bytes32 hash, bytes memory signature) internal view returns (bool) {
        bytes memory signer = signer();
        if (signer.length < 20) return false;
        if (signer.length == 20) return SignatureChecker.isValidSignatureNow(address(bytes20(signer)), hash, signature);
        (bool ok, bytes memory ret) = address(bytes20(signer)).staticcall(
            abi.encodeCall(IERC7913SignatureVerifier.verify, (Bytes.slice(signer, 20), hash, signature)));
        if (!ok) revert VerifierCallFailed(ret);
        // A completed call must answer exactly one canonical word: the ERC-7913
        // magic selector, ABI-encoded as a lone bytes4 (selector left-aligned,
        // 28 zero bytes after). Shorter, longer, or non-canonical returns are
        // malformed responses — a verifier malfunction, not a forgery verdict
        // (review F5, 2026-10-01).
        if (ret.length != 32) revert VerifierCallFailed(ret);
        bytes32 response = abi.decode(ret, (bytes32));
        if (uint224(uint256(response)) != 0) revert VerifierCallFailed(ret);
        return bytes4(response) == IERC7913SignatureVerifier.verify.selector;
    }
}
