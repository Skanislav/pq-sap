// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {SSTORE2} from "solady/utils/SSTORE2.sol";
import {PubKey, d, expandVec} from "ethdilithium/ZKNOX_dilithium_utils.sol";
import {nttFw} from "ethdilithium/ZKNOX_NTT_dilithium.sol";

/// @title PKContractNtt — ML-DSA public key with NTT(t1·2^d) precomputed at key setup
/// @notice Drop-in for the vendored `PKContract` (same constructor ABI, same `getPublicKey()`
///         shape) that stores `t1` already scaled by 2^d and in the NTT domain. The matching
///         verifier (`ZKNOX_dilithium_ntt`) therefore skips the four forward NTTs the stock
///         df999ed verifier recomputes on every `verify` — the key-dependent half of the
///         spend cost moves to this one-time deployment (spike for D-022).
/// @dev `t1` is public, so this is a representation choice, not a scheme change: `tr` is still
///      the FIPS 204 `H(pk)` over the plain packed key, and the message hash is untouched.
contract PKContractNtt {
    address private immutable aHatPointer;
    address private immutable t1HatPointer;
    bytes32 private immutable trPart1;
    bytes32 private immutable trPart2;

    /// @param _aHat A_hat matrix, NTT domain, 8×32-bit lanes per word (uint256[4][4][32])
    /// @param _tr   64-byte tr
    /// @param _t1   t1 vector, PLAIN (uint256[4][32]) — exactly what `PKContract` takes
    constructor(uint256[][][] memory _aHat, bytes memory _tr, uint256[][] memory _t1) {
        require(_tr.length == 64, "tr must be 64 bytes");

        aHatPointer = SSTORE2.write(abi.encode(_aHat));
        t1HatPointer = SSTORE2.write(abi.encode(precomputeT1Hat(_t1)));

        bytes32 part1;
        bytes32 part2;
        assembly {
            part1 := mload(add(_tr, 32))
            part2 := mload(add(_tr, 64))
        }
        trPart1 = part1;
        trPart2 = part2;
    }

    /// @notice NTT_FW((1 << d) * t1) for each row, re-packed into the 32-word lane format.
    function precomputeT1Hat(uint256[][] memory t1Compact) public pure returns (uint256[][] memory out) {
        uint256[][] memory t1 = expandVec(t1Compact);
        out = new uint256[][](4);
        for (uint256 i = 0; i < 4; i++) {
            uint256[] memory row = t1[i];
            for (uint256 j = 0; j < 256; j++) {
                row[j] <<= d;
            }
            out[i] = compact(nttFw(row));
        }
    }

    /// @dev Inverse of `expand`: 256 coefficients (< 2^32) -> 32 words, 8 lanes of 32 bits.
    function compact(uint256[] memory a) public pure returns (uint256[] memory b) {
        require(a.length == 256, "Input array must have exactly 256 elements");
        b = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            uint256 w = 0;
            for (uint256 j = 0; j < 8; j++) {
                w |= (a[(i << 3) + j] & 0xffffffff) << (j << 5);
            }
            b[i] = w;
        }
    }

    /// @return PubKey with `t1` = NTT(t1·2^d) in the lane format `expandVec` understands.
    function getPublicKey() external view returns (PubKey memory) {
        uint256[][][] memory aHat = abi.decode(SSTORE2.read(aHatPointer), (uint256[][][]));
        uint256[][] memory t1Hat = abi.decode(SSTORE2.read(t1HatPointer), (uint256[][]));

        bytes memory tr = new bytes(64);
        bytes32 part1 = trPart1;
        bytes32 part2 = trPart2;
        assembly {
            mstore(add(tr, 32), part1)
            mstore(add(tr, 64), part2)
        }
        return PubKey({aHat: aHat, tr: tr, t1: t1Hat});
    }
}
