// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {IERC7913SignatureVerifier} from "@openzeppelin/contracts/interfaces/IERC7913.sol";

import {IMlDsa44ExpandedKeys} from "./MlDsa44KeyRegistry.sol";

/// @dev The 3-argument ERC-7913 surface of the vendored `ZKNOX_dilithium` (df999ed):
///      `pk` is the 20-byte `PKContract` pointer, `m` is hashed as M' = 0x00 || 0x00 || m
///      (FIPS 204 pure ML-DSA, empty context). Kept as an interface so this wrapper can
///      point at an already-deployed verifier instance.
interface IMlDsa44Erc7913Verifier {
    function verify(bytes calldata pk, bytes32 m, bytes calldata signature) external view returns (bytes4);
}

/// @title MlDsa44CommitSigner7913
/// @notice ERC-7913 signer for the `ml-dsa-44-commit/v0` account profile: the `key`
///         is a hiding commitment to a canonical ML-DSA-44 public key, opened inside
///         the signature.
///
///           spend_key  = keccak256("pq-stealth/ml-dsa-44/key/v0" || pk)         pk: 1,312 B
///           key        = keccak256("pq-stealth/ml-dsa-44/commit/v0" || spend_key || opener)
///           signature  = pk(1312) || opener(32) || sig(2420)                    3,764 B
///           hash       = the account's canonical operation digest (frame sig_hash /
///                        userOpHash); signed as-is with pure ML-DSA-44, empty ctx
///
///         The sender knows `pk`'s commitment (`spend_key` is in the meta-address) and
///         derives `opener` from the ML-KEM shared secret, so it can form `key`, the
///         account initcode, and the CREATE2 address without the signing key. The
///         recipient recovers `opener` on detection. Neither the shared secret nor the
///         opener is a credential: step 4 below needs the ML-DSA-44 signing key.
///
///         Verification, in order:
///           1. exact lengths for ML-DSA-44 (`key` 32 B, `signature` 3,764 B);
///           2. recompute `spend_key` and the commitment; must equal `key`;
///           3. resolve the expanded key for `keccak256(pk)` through KEYS (see
///              `TrustedMlDsa44KeyRegistry` for the trust assumption this carries);
///           4. verify `sig` over `hash` under that key with the ZKNOX ML-DSA-44 verifier.
///         Steps 1-3 and a verifier that answers "invalid" return a uniform 0xffffffff.
///         Step 4 costs ~15 M gas; if the verifier call itself fails (out of gas, or
///         a verifier that returns garbage) this contract REVERTS with
///         `VerifierCallFailed` instead of returning 0xffffffff, so a caller under a
///         gas cap sees resource exhaustion, not "signature invalid", and gas
///         estimation cannot settle on the cheap failure path. Wrappers that swallow
///         reverts (OpenZeppelin's `ERC7913Utils.isValidSignatureNow`,
///         `Stealth8141ZkAccount._verify`) collapse it back to "not authorized";
///         that is their contract, and callers of those must budget the gas.
///         Nonce, replay, chain, destination and value binding are the account's job:
///         they are what `hash` commits to. This contract never hashes `hash` again.
///
///         Privacy boundary: a spend reveals `pk`, whose hash is the recipient's
///         published `spend_key`. Every spent address of one recipient is linkable to
///         the meta-address from the first spend; unspent addresses are not (receive
///         time reveals only the commitment). This is the same trade-off as
///         `SphincsC13CommitSigner7913` (D-018) and is documented, not hidden.
contract MlDsa44CommitSigner7913 is IERC7913SignatureVerifier {
    bytes public constant KEY_DOMAIN = "pq-stealth/ml-dsa-44/key/v0";
    bytes public constant COMMIT_DOMAIN = "pq-stealth/ml-dsa-44/commit/v0";

    uint256 public constant PUBLIC_KEY_LENGTH = 1312;
    uint256 public constant OPENER_LENGTH = 32;
    uint256 public constant ML_DSA_44_SIGNATURE_LENGTH = 2420;
    uint256 public constant PAYLOAD_LENGTH = PUBLIC_KEY_LENGTH + OPENER_LENGTH + ML_DSA_44_SIGNATURE_LENGTH;

    bytes4 internal constant FAIL = 0xffffffff;
    bytes4 internal constant MAGIC = IERC7913SignatureVerifier.verify.selector;

    IMlDsa44Erc7913Verifier public immutable VERIFIER;
    IMlDsa44ExpandedKeys public immutable KEYS;

    /// @notice The ML-DSA-44 verifier call did not complete (out of gas, or a
    ///         malformed return); distinct from an invalid signature.
    error VerifierCallFailed(bytes returnData);

    constructor(IMlDsa44Erc7913Verifier verifier, IMlDsa44ExpandedKeys keys) {
        VERIFIER = verifier;
        KEYS = keys;
    }

    /// @notice The 32-byte value a recipient publishes in its 0x02 meta-address.
    function spendKey(bytes calldata pk) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(KEY_DOMAIN, pk));
    }

    /// @notice The `key` an account holds for `spendKey_` under `opener`.
    function commitment(bytes32 spendKey_, bytes32 opener) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(COMMIT_DOMAIN, spendKey_, opener));
    }

    /// @inheritdoc IERC7913SignatureVerifier
    function verify(bytes calldata key, bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        if (key.length != 32 || signature.length != PAYLOAD_LENGTH) return FAIL;
        bytes calldata pk = signature[0:PUBLIC_KEY_LENGTH];
        bytes32 opener = bytes32(signature[PUBLIC_KEY_LENGTH:PUBLIC_KEY_LENGTH + OPENER_LENGTH]);
        bytes calldata sig = signature[PUBLIC_KEY_LENGTH + OPENER_LENGTH:];

        if (commitment(spendKey(pk), opener) != bytes32(key)) return FAIL;

        address pointer = KEYS.expandedKey(keccak256(pk));
        if (pointer == address(0)) return FAIL;

        (bool ok, bytes memory ret) = address(VERIFIER).staticcall(
            abi.encodeWithSelector(IMlDsa44Erc7913Verifier.verify.selector, abi.encodePacked(pointer), hash, sig)
        );
        if (!ok || ret.length != 32) revert VerifierCallFailed(ret);
        return abi.decode(ret, (bytes4)) == MAGIC ? MAGIC : FAIL;
    }
}
