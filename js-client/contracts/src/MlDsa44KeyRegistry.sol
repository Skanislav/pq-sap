// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {PKContract} from "ethdilithium/ZKNOX_PKContract.sol";
import {CtxShake, shakeUpdate, shakeDigest} from "ethdilithium/ZKNOX_shake.sol";
import {bitUnpackAtOffset} from "ethdilithium/ZKNOX_dilithium_utils.sol";

/// @notice Where a committed-key verifier finds the expanded form of a canonical
///         ML-DSA-44 public key: `keccak256(pk)` -> ZKNOX `PKContract` pointer
///         (aHat in the NTT domain, tr, plain t1), or zero when unknown.
interface IMlDsa44ExpandedKeys {
    function expandedKey(bytes32 pkHash) external view returns (address);
}

/// @title TrustedMlDsa44KeyRegistry
/// @notice One-time key setup for the `ml-dsa-44-commit/v0` profile, under an
///         explicit trust assumption.
///
///         The vendored ZKNOX verifier (df999ed) verifies against an *expanded* key
///         `(aHat, tr, t1)` read from a `PKContract`, not against the 1,312-byte
///         FIPS 204 public key the profile commits to. Binding the two needs
///         `aHat = ExpandA(rho)`: 16 SHAKE128 polynomial expansions, which cost
///         ~40 M gas with the vendored Solidity Keccak-f (one SHAKE256 over the
///         1,312-byte key alone is ~4.4 M). That is above what one transaction can
///         do today, so this registry does NOT recompute `aHat`. It recomputes what
///         is cheap and exact — `tr = SHAKE256(pk, 64)` and `t1` unpacked from the
///         key bytes — and trusts a single REGISTRAR for `aHat`.
///
///         Trust boundary (state it, do not hide it): a dishonest or compromised
///         registrar can register an `aHat` of its own choosing for the recipient's
///         `pk`, and then produce signatures the verifier accepts for every account
///         committed to that key. Anyone can check a registration off chain
///         (`PKContract.getPublicKey().aHat == ExpandA(pk[0:32])`), but nothing on
///         chain does. This is therefore a key-setup adapter for local and
///         reviewed deployments, not a trustless spend route; replacing it with an
///         on-chain expansion or a verifier that takes the raw key is the open
///         item recorded in docs/ml-dsa-commit-profile.md.
///
///         The pointer is a CREATE2 `PKContract` salted by `keccak256(pk)`, so a
///         registered key has one address per registry and cannot be re-bound.
contract TrustedMlDsa44KeyRegistry is IMlDsa44ExpandedKeys {
    uint256 public constant PUBLIC_KEY_LENGTH = 1312;
    uint256 public constant TR_LENGTH = 64;
    uint256 internal constant K = 4;
    uint256 internal constant L = 4;
    uint256 internal constant T1_BITS = 10;
    uint256 internal constant N = 256;

    address public immutable REGISTRAR;
    mapping(bytes32 pkHash => address pointer) public expandedKey;

    event KeyRegistered(bytes32 indexed pkHash, address pointer);

    error NotRegistrar(address caller);
    error BadKeyLength(uint256 length);
    error BadMatrixShape();
    error AlreadyRegistered(bytes32 pkHash);

    constructor(address registrar) {
        REGISTRAR = registrar;
    }

    /// @notice Register the expanded form of `pk`. `aHat` is attested by the
    ///         registrar (see the contract note); `tr` and `t1` are derived here.
    function register(bytes calldata pk, uint256[][][] calldata aHat) external returns (address pointer) {
        if (msg.sender != REGISTRAR) revert NotRegistrar(msg.sender);
        if (pk.length != PUBLIC_KEY_LENGTH) revert BadKeyLength(pk.length);
        if (aHat.length != K) revert BadMatrixShape();
        for (uint256 i = 0; i < K; i++) {
            if (aHat[i].length != L) revert BadMatrixShape();
            for (uint256 j = 0; j < L; j++) {
                if (aHat[i][j].length != 32) revert BadMatrixShape();
            }
        }
        bytes32 pkHash = keccak256(pk);
        if (expandedKey[pkHash] != address(0)) revert AlreadyRegistered(pkHash);

        bytes memory tr = trOf(pk);
        uint256[][] memory t1 = unpackT1(pk);
        pointer = address(new PKContract{salt: pkHash}(aHat, tr, t1));
        expandedKey[pkHash] = pointer;
        emit KeyRegistered(pkHash, pointer);
    }

    /// @notice FIPS 204 `tr = H(pk, 64)` with H = SHAKE256, computed with the
    ///         vendored sponge (the same one the verifier hashes `mu` with).
    function trOf(bytes calldata pk) public pure returns (bytes memory) {
        CtxShake memory ctx;
        ctx = shakeUpdate(ctx, pk);
        return shakeDigest(ctx, TR_LENGTH);
    }

    /// @notice `t1` from the key bytes (`pk = rho(32) || t1` packed 10 bits per
    ///         coefficient, FIPS 204 Algorithm 22), in the ZKNOX compact layout:
    ///         four polynomials of 32 words, eight 32-bit coefficients per word.
    function unpackT1(bytes calldata pk) public pure returns (uint256[][] memory t1) {
        bytes memory packed = pk[32:];
        t1 = new uint256[][](K);
        for (uint256 i = 0; i < K; i++) {
            uint256[] memory coeffs = bitUnpackAtOffset(packed, T1_BITS, i * N * T1_BITS, N);
            uint256[] memory words = new uint256[](32);
            for (uint256 w = 0; w < 32; w++) {
                uint256 acc = 0;
                for (uint256 j = 0; j < 8; j++) {
                    acc |= coeffs[8 * w + j] << (32 * j);
                }
                words[w] = acc;
            }
            t1[i] = words;
        }
    }
}
