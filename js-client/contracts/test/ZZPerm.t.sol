// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {TrustlessMlDsa44KeyRegistry} from "../src/TrustlessMlDsa44KeyRegistry.sol";

/// The attack that is NEW to the hash-commitment design: the finalizer
/// supplies the honest word sets but PERMUTED across entry indices, so the
/// deployed aHat would be a transposed/shuffled matrix built entirely from
/// real ExpandA(rho) output. Every per-entry hash is computed over genuine
/// words — only their PLACEMENT is a lie, and the per-entry hash check must
/// reject it. Every test pins the revert REASON (EntryWordsMismatch), never
/// just "some revert".
///
/// Fixture layout: the generator emits the oracle words as ONE flat
/// `uint256[512]` ABI blob (`.flat_words`, entry e at words 32*e — exactly
/// the shape `finalize` takes), so this test decodes a single static array.
/// The previous shape — decoding the triple-nested `uint256[][][]` from
/// `public_key_data` — overflows the legacy codegen's stack in this frame
/// (its generated ABI decoder needs too many stack slots; a via_ir
/// restriction would instead link a second, differently-optimized registry
/// artifact, so the tests must run against the bytecode that ships).
contract ZZPermTest is Test {
    bytes pk;
    uint256[512] ow; // flat oracle words, entry e at 32*e
    TrustlessMlDsa44KeyRegistry r;

    function setUp() public {
        string memory json = vm.readFile("../../python/scripts/mldsa44_commit_7913_demo.json");
        pk = vm.parseJsonBytes(json, ".ml_dsa_pk");
        ow = abi.decode(vm.parseJsonBytes(json, ".flat_words"), (uint256[512]));
        r = new TrustlessMlDsa44KeyRegistry();
        r.begin(pk);
        for (uint256 e = 0; e < 16; e++) r.stage(pk, e);
    }

    /// entry `e`'s words as a DYNAMIC array — the exact shape `_checkedEntry`
    /// hashes, so the expected-revert payloads are byte-precise
    function _entry(uint256[512] memory flat, uint256 e) internal pure returns (uint256[] memory) {
        uint256[] memory words = new uint256[](32);
        for (uint256 w = 0; w < 32; w++) words[w] = flat[32 * e + w];
        return words;
    }

    /// expect EntryWordsMismatch(e, stored, given) with the args hoisted so the
    /// legacy codegen does not juggle the selector and both hashes in one
    /// nested call expression
    function _expectMismatch(uint256 e, uint256[512] memory candidate) internal {
        bytes32 stored = r.entryHashes(keccak256(pk), e);
        bytes32 given = keccak256(abi.encodePacked(_entry(candidate, e)));
        vm.expectRevert(
            abi.encodeWithSelector(
                TrustlessMlDsa44KeyRegistry.EntryWordsMismatch.selector, e, stored, given
            )
        );
    }

    /// swap entries 1 and 4 (i.e. transpose A[0][1] and A[1][0]) — all words
    /// are genuine ExpandA(rho) output, only their placement is a lie
    function testPermutedEntriesRejected() public {
        uint256[512] memory perm = ow;
        for (uint256 w = 0; w < 32; w++) {
            (perm[32 + w], perm[128 + w]) = (ow[128 + w], ow[32 + w]);
        }
        _expectMismatch(1, perm);
        r.finalize(pk, perm);
    }

    /// full transpose A -> A^T, the strongest permutation. Entry 0 is on the
    /// diagonal (its words are unchanged under transpose), so the FIRST
    /// mismatch the assembly hits is entry 1, the first off-diagonal entry.
    function testTransposeRejected() public {
        uint256[512] memory t;
        for (uint256 i = 0; i < 4; i++) {
            for (uint256 j = 0; j < 4; j++) {
                for (uint256 w = 0; w < 32; w++) t[32 * (i * 4 + j) + w] = ow[32 * (j * 4 + i) + w];
            }
        }
        _expectMismatch(1, t);
        r.finalize(pk, t);
    }

    /// every entry = entry 0's words (a rank-1 matrix of genuine words)
    function testAllSameEntryRejected() public {
        uint256[512] memory s;
        for (uint256 e = 0; e < 16; e++) {
            for (uint256 w = 0; w < 32; w++) s[32 * e + w] = ow[w];
        }
        _expectMismatch(1, s);
        r.finalize(pk, s);
    }
}