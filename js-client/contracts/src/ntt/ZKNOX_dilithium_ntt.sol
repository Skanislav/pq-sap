// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

// Derived from ZKNOX ETHDILITHIUM `ZKNOX_dilithium.sol` (df999ed), Copyright (C) 2025
// Renaud Dubois, Simon Masson, MIT License. The only change is in `verifyInternal`: the
// public key's `t1` arrives already as NTT_FW((1 << d) * t1) (see `PKContractNtt`), so the
// per-verify shift-and-NTT loop is gone — the same shape `ZKNOX_ethdilithium` uses, kept on
// the NIST/SHAKE profile.

import {nttFw} from "ethdilithium/ZKNOX_NTT_dilithium.sol";
import {dilithiumCore1, dilithiumCore2} from "ethdilithium/ZKNOX_dilithium_core.sol";
import {sampleInBallNist} from "ethdilithium/ZKNOX_SampleInBall.sol";
import {CtxShake, shakeUpdate, shakeDigest} from "ethdilithium/ZKNOX_shake.sol";
import {q, expandVec, OMEGA, GAMMA_1_MINUS_BETA, TAU, PubKey, Signature, slice} from "ethdilithium/ZKNOX_dilithium_utils.sol";
import {IERC7913SignatureVerifier} from "@openzeppelin/contracts/interfaces/IERC7913.sol";
import {IPKContract} from "ethdilithium/ZKNOX_PKContract.sol";

contract ZKNOX_dilithium_ntt is IERC7913SignatureVerifier {
    function verify(bytes memory pk, bytes memory m, bytes memory signature, bytes memory ctx)
        external
        view
        returns (bool)
    {
        address pubKeyAddress;
        assembly {
            pubKeyAddress := mload(add(pk, 20))
        }
        PubKey memory publicKey = IPKContract(pubKeyAddress).getPublicKey();

        if (ctx.length > 255) {
            revert("ctx bytes must have length at most 255");
        }
        bytes memory mPrime = abi.encodePacked(bytes1(0), bytes1(uint8(ctx.length)), ctx, m);

        Signature memory sig =
            Signature({cTilde: slice(signature, 0, 32), z: slice(signature, 32, 2304), h: slice(signature, 2336, 84)});

        return verifyInternal(publicKey, mPrime, sig);
    }

    function verify(bytes calldata pk, bytes32 m, bytes calldata signature) external view returns (bytes4) {
        address pubKeyAddress;
        assembly {
            pubKeyAddress := shr(96, calldataload(pk.offset))
        }
        PubKey memory publicKey = IPKContract(pubKeyAddress).getPublicKey();

        bytes memory mPrime = abi.encodePacked(bytes1(0), bytes1(0), m);

        Signature memory sig =
            Signature({cTilde: slice(signature, 0, 32), z: slice(signature, 32, 2304), h: slice(signature, 2336, 84)});

        if (verifyInternal(publicKey, mPrime, sig)) {
            return IERC7913SignatureVerifier.verify.selector;
        }
        return 0xFFFFFFFF;
    }

    function verifyInternal(PubKey memory pk, bytes memory mPrime, Signature memory signature)
        internal
        pure
        returns (bool)
    {
        uint256 i;
        uint256 j;

        // FIRST CORE STEP
        (bool foo, uint256 normH, uint256[][] memory h, uint256[][] memory z) = dilithiumCore1(signature);

        if (foo == false) {
            return false;
        }
        if (normH > OMEGA) {
            return false;
        }
        for (i = 0; i < 4; i++) {
            for (j = 0; j < 256; j++) {
                uint256 zij = z[i][j];
                if (zij > GAMMA_1_MINUS_BETA && (q - zij) > GAMMA_1_MINUS_BETA) {
                    return false;
                }
            }
        }

        // C_NTT
        uint256[] memory cNtt = sampleInBallNist(signature.cTilde, TAU, q);
        cNtt = nttFw(cNtt);

        // t1 is stored as NTT_FW((1 << d) * t1): unpack only, no per-verify NTT.
        uint256[][] memory t1New = expandVec(pk.t1);

        // SECOND CORE STEP
        bytes memory wPrimeBytes = dilithiumCore2(pk, z, cNtt, h, t1New);
        // FINAL HASH
        CtxShake memory sctx;
        sctx = shakeUpdate(sctx, pk.tr);
        sctx = shakeUpdate(sctx, mPrime);
        bytes memory mu = shakeDigest(sctx, 64);

        CtxShake memory sctx2;
        sctx2 = shakeUpdate(sctx2, mu);
        sctx2 = shakeUpdate(sctx2, wPrimeBytes);
        bytes32 finalHash = bytes32(shakeDigest(sctx2, 32));

        if (signature.cTilde.length < 32) {
            return false;
        }
        for (i = 0; i < 32; i++) {
            if (signature.cTilde[i] != finalHash[i]) {
                return false;
            }
        }
        return true;
    }
}
