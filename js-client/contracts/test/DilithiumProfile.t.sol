// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";
import {nttFw} from "ethdilithium/ZKNOX_NTT_dilithium.sol";
import {dilithiumCore1, dilithiumCore2} from "ethdilithium/ZKNOX_dilithium_core.sol";
import {sampleInBallNist} from "ethdilithium/ZKNOX_SampleInBall.sol";
import {CtxShake, shakeUpdate, shakeDigest} from "ethdilithium/ZKNOX_shake.sol";
import {q, expandVec, TAU, d, PubKey, Signature, slice} from "ethdilithium/ZKNOX_dilithium_utils.sol";
import {PKContractNtt} from "../src/ntt/PKContractNtt.sol";

/// Where the ML-DSA (ZKNOX df999ed, NIST/SHAKE profile) verify gas goes, step by step,
/// on the same fixture as NttPrecompute.t.sol. Informational — feeds D-022's "split the
/// computation" analysis. Run: forge test --root contracts --match-contract DilithiumProfile -vv
contract DilithiumProfileTest is Test {
    uint256[][][] aHat;
    bytes tr;
    uint256[][] t1;
    bytes32 challenge;
    bytes sig;

    function setUp() public {
        string memory json = vm.readFile("../../python/scripts/zknox_7913_demo.json");
        bytes memory pkData = vm.parseJsonBytes(json, ".public_key_data");
        (bytes memory aHatEnc, bytes memory trBytes, bytes memory t1Enc) =
            abi.decode(pkData, (bytes, bytes, bytes));
        aHat = abi.decode(aHatEnc, (uint256[][][]));
        tr = trBytes;
        t1 = abi.decode(t1Enc, (uint256[][]));
        challenge = vm.parseJsonBytes32(json, ".challenge");
        sig = vm.parseJsonBytes(json, ".sig");
    }

    function testProfile() public {
        PubKey memory pk = PubKey({aHat: aHat, tr: tr, t1: t1});
        bytes memory mPrime = abi.encodePacked(bytes1(0), bytes1(0), challenge);
        bytes memory signature = sig;

        uint256 g0 = gasleft();
        Signature memory s =
            Signature({cTilde: slice(signature, 0, 32), z: slice(signature, 32, 2304), h: slice(signature, 2336, 84)});
        emit log_named_uint("0 slice signature", g0 - gasleft());

        g0 = gasleft();
        (bool ok, uint256 normH, uint256[][] memory h, uint256[][] memory z) = dilithiumCore1(s);
        emit log_named_uint("1 dilithiumCore1 (unpack z/h, norms)", g0 - gasleft());
        assertTrue(ok);
        assertLe(normH, 80);

        g0 = gasleft();
        uint256[] memory cNtt = sampleInBallNist(s.cTilde, TAU, q);
        emit log_named_uint("2 sampleInBallNist (SHAKE256)", g0 - gasleft());

        g0 = gasleft();
        cNtt = nttFw(cNtt);
        emit log_named_uint("3 nttFw(c)", g0 - gasleft());

        g0 = gasleft();
        uint256[][] memory t1New = expandVec(pk.t1);
        for (uint256 i = 0; i < 4; i++) {
            for (uint256 j = 0; j < 256; j++) {
                t1New[i][j] <<= d;
            }
            t1New[i] = nttFw(t1New[i]);
        }
        emit log_named_uint("4 expand + shift + nttFw(t1) x4 (key-dependent)", g0 - gasleft());

        g0 = gasleft();
        bytes memory wPrimeBytes = dilithiumCore2(pk, z, cNtt, h, t1New);
        emit log_named_uint("5 dilithiumCore2 (expandMat, NTT(z)x4, A*z, invNTT x4, hints, w1 encode)", g0 - gasleft());

        g0 = gasleft();
        CtxShake memory sctx;
        sctx = shakeUpdate(sctx, pk.tr);
        sctx = shakeUpdate(sctx, mPrime);
        bytes memory mu = shakeDigest(sctx, 64);
        CtxShake memory sctx2;
        sctx2 = shakeUpdate(sctx2, mu);
        sctx2 = shakeUpdate(sctx2, wPrimeBytes);
        bytes32 finalHash = bytes32(shakeDigest(sctx2, 32));
        emit log_named_uint("6 final SHAKE256 (mu, then c~ over w1)", g0 - gasleft());

        assertEq(finalHash, bytes32(s.cTilde));
    }
}
