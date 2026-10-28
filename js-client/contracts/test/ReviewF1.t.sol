// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {TrustedMlDsa44KeyRegistry} from "../src/MlDsa44KeyRegistry.sol";

/// F1 (review 2026-10-01): `register -> replace(wrong) -> replace(correct)`
/// recovery. Every `_bind` deploy uses CREATE2 salted by (pkHash, aHat), so
/// deploying the SAME (pk, aHat) twice collides with the still-deployed first
/// PKContract and reverts — correct -> incorrect -> correct recovery is
/// impossible today. The fix must reuse the existing deployment for an
/// identical binding rather than deploying again.
contract ReviewF1Test is Test {
    function _registry() internal returns (TrustedMlDsa44KeyRegistry, bytes memory pk, uint256[][][] memory aHat) {
        string memory json = vm.readFile("../../python/scripts/mldsa44_commit_7913_demo.json");
        pk = vm.parseJsonBytes(json, ".ml_dsa_pk");
        (bytes memory aHatEnc,,) = abi.decode(vm.parseJsonBytes(json, ".public_key_data"), (bytes, bytes, bytes));
        aHat = abi.decode(aHatEnc, (uint256[][][]));
        TrustedMlDsa44KeyRegistry registry = new TrustedMlDsa44KeyRegistry(address(this));
        return (registry, pk, aHat);
    }

    /// Acceptance: the correct -> incorrect -> correct sequence succeeds and
    /// restores the original pointer.
    function test_f1_correct_incorrect_correct_recovery() public {
        (TrustedMlDsa44KeyRegistry registry, bytes memory pk, uint256[][][] memory aHat) = _registry();
        address original = registry.register(pk, aHat);

        // replace with a WRONG matrix (one word flipped) — succeeds, new binding
        aHat[0][0][0] ^= 1;
        address replacement = registry.replace(pk, aHat);
        assertTrue(replacement != original, "wrong matrix must rebind to a new deployment");

        // replace back with the CORRECT matrix: pre-fix this re-deploys the
        // original (pk, aHat) via CREATE2 — salt and initcode are deterministic,
        // the original PKContract is still deployed there, so the deploy
        // reverts. The fix must reuse it and restore the pointer.
        aHat[0][0][0] ^= 1;
        address restored = registry.replace(pk, aHat);
        assertEq(restored, original, "re-binding to the previous matrix must restore the original pointer");
        assertEq(registry.expandedKey(keccak256(pk)), original, "registry must answer the original deployment");
    }

    /// Acceptance: original deployment code remains unchanged by the round trip.
    function test_f1_original_deployment_code_unchanged() public {
        (TrustedMlDsa44KeyRegistry registry, bytes memory pk, uint256[][][] memory aHat) = _registry();
        address original = registry.register(pk, aHat);
        bytes32 originalCode = keccak256(original.code);

        aHat[0][0][0] ^= 1;
        registry.replace(pk, aHat);
        aHat[0][0][0] ^= 1;
        registry.replace(pk, aHat);

        assertEq(keccak256(original.code), originalCode, "original PKContract bytecode must be untouched");
    }

    /// Acceptance: unauthorized callers remain unable to register or replace.
    function test_f1_unauthorized_callers_rejected() public {
        (TrustedMlDsa44KeyRegistry registry, bytes memory pk, uint256[][][] memory aHat) = _registry();
        vm.prank(address(0xBEEF));
        vm.expectRevert(abi.encodeWithSelector(TrustedMlDsa44KeyRegistry.NotRegistrar.selector, address(0xBEEF)));
        registry.register(pk, aHat);

        registry.register(pk, aHat);
        vm.prank(address(0xBEEF));
        vm.expectRevert(abi.encodeWithSelector(TrustedMlDsa44KeyRegistry.NotRegistrar.selector, address(0xBEEF)));
        registry.replace(pk, aHat);
    }

    /// Acceptance: rebinding to the CURRENT identical matrix has an explicit,
    /// tested policy — reuse, pointer unchanged, no new deployment.
    function test_f1_replace_with_identical_matrix_reuses_pointer() public {
        (TrustedMlDsa44KeyRegistry registry, bytes memory pk, uint256[][][] memory aHat) = _registry();
        address original = registry.register(pk, aHat);

        address pointer = registry.replace(pk, aHat);
        assertEq(pointer, original, "identical rebind must reuse the current deployment");
        assertEq(registry.expandedKey(keccak256(pk)), original);
    }

    /// Acceptance: the pre-existing recovery path (incorrect first
    /// registration corrected by replace) still works.
    function test_f1_incorrect_first_registration_recovery_still_works() public {
        (TrustedMlDsa44KeyRegistry registry, bytes memory pk, uint256[][][] memory aHat) = _registry();
        aHat[0][0][0] ^= 1;
        address wrong = registry.register(pk, aHat);

        aHat[0][0][0] ^= 1;
        address corrected = registry.replace(pk, aHat);
        assertTrue(corrected != wrong, "correction must point at the corrected deployment");
        assertEq(registry.expandedKey(keccak256(pk)), corrected);
        assertEq(corrected, registry.pointerFor(pk, aHat), "pointer must equal the deterministic address");
    }
}