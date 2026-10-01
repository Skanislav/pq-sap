// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {Shake128Ctx, shake128Init, shake128SqueezeBlock} from "../src/Shake128.sol";

/// @dev External wrapper so tests can assert the too-long revert across a
///      call boundary (an inlined free function reverts in the caller's own
///      frame, which cheatcodes cannot observe). Lives here, not in `src/`,
///      so no test harness ships as a deployable artifact.
contract Shake128Call {
    function squeezeTwoBlocks(bytes memory seed)
        external
        pure
        returns (bytes memory b0, bytes memory b1)
    {
        (Shake128Ctx memory ctx, bytes memory x0) = shake128SqueezeBlock(shake128Init(seed));
        (, bytes memory x1) = shake128SqueezeBlock(ctx);
        return (x0, x1);
    }
}

/// Direct SHAKE128 (FIPS 202, rate 168) KATs for #27: the trustless registry
/// exercises the library only transitively through one ExpandA fixture, so a
/// padding or lane-ordering bug on a path that fixture does not reach would
/// go unnoticed. Vectors generated with Python `hashlib.shake_128` (the repo's
/// source of truth): the first two 168-byte squeeze blocks for the empty
/// seed, a 34-byte seed (the largest ExpandA seed shape: rho || j || i) and
/// a 166-byte seed (the shake128Init guard boundary). Block 1 exercises the
/// permutation-before-squeeze path that block 0 (read straight from the
/// post-absorb state) does not.
contract Shake128Test is Test {
    function _twoBlocks(bytes memory seed)
        internal
        pure
        returns (bytes memory b0, bytes memory b1)
    {
        Shake128Ctx memory ctx;
        (ctx, b0) = shake128SqueezeBlock(shake128Init(seed));
        (, b1) = shake128SqueezeBlock(ctx);
    }

    function _seed(uint256 len) internal pure returns (bytes memory s) {
        s = new bytes(len);
        for (uint256 i; i < len; ++i) {
            s[i] = bytes1(uint8(i & 0xff));
        }
    }

    function testEmptySeed() public pure {
        (bytes memory b0, bytes memory b1) = _twoBlocks("");
        // hashlib.shake_128(b"").digest(336) split at 168
        assertEq(
            b0,
            hex"7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef263cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdefaee7eef47cb0fca9",
            "empty seed block 0"
        );
        assertEq(
            b1,
            hex"767be1fda69419dfb927e9df07348b196691abaeb580b32def58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4cee8cc0d4c922a96188d032675c8ac850933c7aff1533b94c834adbb69c6115bad4692d8619f90b0cdf8a7b9c264029ac185b70b83f2801f2f4b3f70c593ea3aeeb613a7f1b1de33fd75081f592305f2e4526edc09631b10958f464d889f31ba010250fda7f1368ec2967fc84ef2ae9aff268e0b170",
            "empty seed block 1"
        );
    }

    function testSeed34() public pure {
        (bytes memory b0, bytes memory b1) = _twoBlocks(_seed(34));
        // hashlib.shake_128(bytes(range(34))).digest(336) split at 168
        assertEq(
            b0,
            hex"42b3c5cbdc45441a59489b99a72a74fb0cb4c1a2b0182aeb5f48f925d8eee07c25f0a91e8dc67d9b662bb680e7752e23dabcf03f6b239ccb0c16479a42bb3fe1885bbae558ca2124a98f8f3d3f6d043e63e331f3a3c90b98a789161262d8b8b9098107fdb355390a186aef7783cb5c99db3f061588b4936439f55083011f1c16a3ee6ff0946da9011aa4c733d076842fb28de18befc062a81bef7da5835fbd6c8d009639833727e4",
            "seed34 block 0"
        );
        assertEq(
            b1,
            hex"3f9c5fd56de35c29efa2faec0c126c063e06ba87d4fd2542959d24fb34265c54b071b96bbae26cd9a07fefac966b1577393870fecb318640671e7df98e284cfcd3aca15afc666d39e37d749fccf3bd287f4e1328db6eaafb78cbf4d1ce23e576feba0426a80fb8af21de958a77fb744d9d75ec3fa4f8fd993086b7fdbae881282b536a846c997e8b1799d231decb1f8b3ebd73b9f4ef736c3891b978c669ee45de724156fc15c255",
            "seed34 block 1"
        );
    }

    function testSeed166GuardBoundary() public pure {
        (bytes memory b0, bytes memory b1) = _twoBlocks(_seed(166));
        // hashlib.shake_128(bytes(i & 0xff for i in range(166))).digest(336)
        // split at 168 — the largest seed shake128Init accepts
        assertEq(
            b0,
            hex"3ba54a1410815583e600db440b79530c7d4d549621dc260ab88555e3f24729a4a92e7946724d741ed816edfb813cd1a649e135586c98ffbbb2ef0d7bf6bb38d7c6ed9cebe500f5241af1ccfb257f0e4fd2f42eeeb910f28c1c5f233b233bcebe47813d4911c1a40e729c8a7153bd9460fb4acb2c1702115fe2ac9a47641b0e535e0bce47c8c386fbc100c470f7bd77ae28fef6f2d65d1801bca5aae21662ca67afeedc931a8b0051",
            "seed166 block 0"
        );
        assertEq(
            b1,
            hex"6d3b803ce826056456b60f75697a04ecbf8eac69d9d2ceb3c7475cbd4f662bf39f31986c27adbf1dc55893e4322ee3c5645cd56b58de1048242f28012f5dd4b065dba5d7bdc872f842c8a71c48ba7c829d4749e9f9be37baac1aabb5fd0393a20b621b716b482327e241781033ecad255f32c425a7025e7ef8ea2e14ff9cd4e797c643d5faab7e20bbada1d590be0fceb28847560a6f579922dfca4b69dced9fe7b2d57ced691cf5",
            "seed166 block 1"
        );
    }

    function testSeedTooLongReverts() public {
        Shake128Call caller = new Shake128Call();
        vm.expectRevert(bytes("shake128: seed too long"));
        caller.squeezeTwoBlocks(_seed(167));
    }
}