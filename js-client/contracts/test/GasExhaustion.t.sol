// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {IERC7913SignatureVerifier} from "@openzeppelin/contracts/interfaces/IERC7913.sol";
import {ISphincsC13Verifier} from "../src/SphincsC13Signer7913.sol";

import {Pq7913Signer} from "../src/Pq7913Signer.sol";
import {ZKNOX_dilithium} from "ethdilithium/ZKNOX_dilithium.sol";
import {IMlDsa44Erc7913Verifier, MlDsa44CommitSigner7913} from "../src/MlDsa44CommitSigner7913.sol";
import {IMlDsa44ExpandedKeys, TrustedMlDsa44KeyRegistry} from "../src/MlDsa44KeyRegistry.sol";
import {Stealth7913Account} from "../src/Stealth7913Account.sol";
import {IProofVerifier, Stealth8141ZkAccount} from "../src/frames/Stealth8141ZkAccount.sol";
import {Stealth8141ZkFactory} from "../src/frames/Stealth8141ZkFactory.sol";
import {MlDsa44CommitFrameVerifier} from "../src/frames/MlDsa44CommitFrameVerifier.sol";
import {IFrameTxContext} from "../src/frames/IFrameTxContext.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

/// Stand-in for the Yul FrameTxContext outside a frame transaction: returns a chosen
/// sig_hash and signature bytes so `executeFrame` can be exercised in forge.
/// Local copy of ZkAccount.t.sol's mock: importing that file pulls the UltraHonk
/// verifier into this compilation unit, which the default legacy-codegen profile
/// cannot compile (stack too deep).
contract MockFrameCtx is IFrameTxContext {
    bytes32 public h;
    mapping(uint256 => bytes) sigs;

    function set(bytes32 h_, uint256 idx, bytes memory sig) external {
        h = h_;
        sigs[idx] = sig;
    }

    function sigHash() external view returns (bytes32) { return h; }
    function txParam(uint256) external pure returns (uint256) { revert("n/a"); }
    function frameParam(uint256, uint256) external pure returns (uint256) { revert("n/a"); }
    function sigParam(uint256, uint256) external pure returns (uint256) { revert("n/a"); }
    function signature(uint256 i) external view returns (bytes memory) { return sigs[i]; }
}

/// A backend that accepts everything: stands in for a working prover backend.
/// Local copy of ZkAccount.t.sol's mock (same reason as MockFrameCtx above).
contract AcceptAllVerifier is IProofVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) { return true; }
}

/// An ERC-7913 verifier that always reverts: stands in for a verifier call that
/// does not complete (out of gas, or a broken backend).
contract Reverting7913Verifier is IERC7913SignatureVerifier {
    function verify(bytes calldata, bytes32, bytes calldata) external pure returns (bytes4) {
        revert("verifier unavailable");
    }
}

/// An ERC-7913 verifier that answers the magic without checking anything.
contract Magic7913Verifier is IERC7913SignatureVerifier {
    function verify(bytes calldata, bytes32, bytes calldata) external pure returns (bytes4) {
        return IERC7913SignatureVerifier.verify.selector;
    }
}

/// An ERC-7913 verifier that completes but returns garbage (short return).
contract Garbage7913Verifier is IERC7913SignatureVerifier {
    function verify(bytes calldata, bytes32, bytes calldata) external pure returns (bytes4) {
        assembly ("memory-safe") {
            return(0, 16)
        }
    }
}

/// An IProofVerifier that reverts: a broken ZK backend.
contract RevertingProofVerifier is IProofVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        revert("backend unavailable");
    }
}

/// Gas-exhaustion semantics across the spend wrappers (issue #32):
///   * `Stealth8141ZkAccount.executeFrame` — MIN_PROOF_GAS floor + no revert
///     swallowing: underfunded -> GasFloorExceeded, reverting backend ->
///     ProofCallFailed, completed false -> NotAuthorized.
///   * `Pq7913Signer` accounts (Stealth7913Account / ...4337 / Stealth8141Account)
///     — a verifier call that does not complete reverts VerifierCallFailed
///     through every surface (ERC-1271, 7913, frame) instead of "invalid".
/// Also measures the shipped verifiers' whole-call gas, the numbers behind the
/// documented floors.
/// Run: forge test --root contracts --match-contract GasExhaustion -vv
contract GasExhaustionTest is Test {
    bytes4 constant MAGIC_7913 = 0x024ad318;
    bytes4 constant MAGIC_1271 = 0x1626ba7e;
    bytes4 constant FAIL = 0xffffffff;

    // -- fixtures -----------------------------------------------------------
    // Real committed ML-DSA-44 spend from python/scripts/mldsa44_commit_7913_demo.json
    // (the C13 gas fixture below is separate — gas shape is what is measured).
    bytes16 constant C13_PK_SEED = bytes16(keccak256("c13 seed"));
    bytes16 constant C13_PK_ROOT = bytes16(keccak256("c13 root"));
    bytes32 constant C13_DIGEST = bytes32(keccak256("c13 digest"));

    /// @dev Storage-held fixture state (issue #32 gas semantics tests): decoded
    ///      one field per function so no single frame carries the nested
    ///      `uint256[][][]` decode alongside the other locals (solc 0.8.30
    ///      without via_ir runs out of stack slots otherwise).
    bytes pk;
    bytes32 spendKey;
    bytes32 opener;
    bytes32 commitment;
    bytes32 digest;
    bytes payload;
    uint256[][][] aHat;

    ZKNOX_dilithium dilithium;
    TrustedMlDsa44KeyRegistry registry;
    MlDsa44CommitSigner7913 signer;

    function setUp() public {
        _loadPk();
        _loadSpendKey();
        _loadOpener();
        _loadCommitment();
        _loadDigest();
        _loadPayload();
        _loadAHat();
        dilithium = new ZKNOX_dilithium();
        registry = new TrustedMlDsa44KeyRegistry(address(this));
        signer = new MlDsa44CommitSigner7913(
            IMlDsa44Erc7913Verifier(address(dilithium)), IMlDsa44ExpandedKeys(address(registry)));
        registry.register(pk, aHat);
    }

    function _fixtureJson() internal view returns (string memory) {
        return vm.readFile("../../python/scripts/mldsa44_commit_7913_demo.json");
    }

    function _loadPk() internal {
        pk = vm.parseJsonBytes(_fixtureJson(), ".ml_dsa_pk");
    }

    function _loadSpendKey() internal {
        spendKey = vm.parseJsonBytes32(_fixtureJson(), ".spend_key");
    }

    function _loadOpener() internal {
        opener = vm.parseJsonBytes32(_fixtureJson(), ".opener");
    }

    function _loadCommitment() internal {
        commitment = vm.parseJsonBytes32(_fixtureJson(), ".commitment");
    }

    function _loadDigest() internal {
        digest = vm.parseJsonBytes32(_fixtureJson(), ".digest");
    }

    function _loadPayload() internal {
        payload = vm.parseJsonBytes(_fixtureJson(), ".payload");
    }

    function _loadAHat() internal {
        (bytes memory aHatEnc,,) = abi.decode(vm.parseJsonBytes(_fixtureJson(), ".public_key_data"), (bytes, bytes, bytes));
        aHat = abi.decode(aHatEnc, (uint256[][][]));
    }

    // ------------------------------------------------- documented gas table

    /// @dev Whole-call gas of the vendored C13 verifier on its fixture — the
    ///      floor table in Pq7913Signer says ~110 k exec (~188 k tx-level);
    ///      assert it stays below the cheapest shipped backend's budget line
    ///      and record the number.
    ///      Deployed from the compiled artifact (`vm.deployCode`), never from a
    ///      source import: the vendored verifier is compiled via-IR only
    ///      (foundry.toml compilation_restrictions) and a direct import would
    ///      drag it into the default legacy-codegen profile (stack too deep).
    ///      Fixture: python/scripts/sphincs_c13_7913_demo.json — a REAL C13
    ///      key + signature, so the full verification path is measured.
    function test_c13_verify_gas_documented() public {
        ISphincsC13Verifier verifier = ISphincsC13Verifier(
            vm.deployCode("out/SPHINCs-C13Asm.sol/SphincsC13Asm.json"));
        string memory json = vm.readFile("../../python/scripts/sphincs_c13_7913_demo.json");
        // pk halves are top-aligned n = 16 words, exactly as the demo stores them
        bytes32 pkSeed = vm.parseJsonBytes32(json, ".pk_seed");
        bytes32 pkRoot = vm.parseJsonBytes32(json, ".pk_root");
        bytes32 msg = vm.parseJsonBytes32(json, ".challenge");
        bytes memory sig = vm.parseJsonBytes(json, ".sig");
        uint256 g0 = gasleft();
        bool valid = verifier.verify(pkSeed, pkRoot, msg, sig);
        uint256 used = g0 - gasleft();
        emit log_named_uint("SphincsC13Asm.verify gas (real C13 key/sig)", used);
        assertTrue(valid, "the demo fixture carries a genuine C13 signature");
        assertLt(used, 2_000_000, "C13 verify must stay well under the ZK floor");
    }

    /// @dev The ML-DSA-44 route through the whole account surface, for the
    ///      documented ~15 M line.
    function test_mldsa44_route_gas_documented() public {
        Stealth7913Account account = new Stealth7913Account(abi.encodePacked(address(signer), commitment));
        uint256 g0 = gasleft();
        bytes4 got = account.isValidSignature(digest, payload);
        emit log_named_uint("Stealth7913Account.isValidSignature gas (ML-DSA-44 route)", g0 - gasleft());
        assertEq(got, MAGIC_1271, "genuine authorization must verify");
    }

    // ---------------------------------------------- Pq7913Signer: no swallow

    function test_erc1271_surfaces_verifier_failure() public {
        Reverting7913Verifier bad = new Reverting7913Verifier();
        Stealth7913Account account = new Stealth7913Account(abi.encodePacked(address(bad), bytes32(uint256(1))));
        vm.expectRevert(_stringRevert(Pq7913Signer.VerifierCallFailed.selector, "verifier unavailable"));
        account.isValidSignature(digest, payload);
    }

    function test_erc1271_surfaces_garbage_return() public {
        Garbage7913Verifier bad = new Garbage7913Verifier();
        Stealth7913Account account = new Stealth7913Account(abi.encodePacked(address(bad), bytes32(uint256(1))));
        // a completed call with a short return: not magic, so "invalid"
        assertEq(account.isValidSignature(digest, payload), FAIL);
    }

    function test_erc1271_valid_path_unchanged() public {
        Stealth7913Account account = new Stealth7913Account(abi.encodePacked(address(signer), commitment));
        assertEq(account.isValidSignature(digest, payload), MAGIC_1271, "real route still verifies");
        assertEq(account.isValidSignature(digest, senderPayload()), FAIL, "bad payload still fails");
    }

    /// @dev Gas-starved real verifier: the ML-DSA-44 backend needs ~15 M; cap
    ///      the ERC-1271 call below that and the account must revert
    ///      VerifierCallFailed (out of gas inside the verifier), not answer
    ///      "invalid". The revert's payload is the OOG revert data, which is
    ///      not stable across backends — expect only the selector.
    function test_erc1271_out_of_gas_reverts_not_invalid() public {
        Stealth7913Account account = new Stealth7913Account(abi.encodePacked(address(signer), commitment));
        // warm the account so the 63/64 rule forwards a predictable budget
        account.isValidSignature(digest, payload);
        // cap below the ~15 M the ML-DSA-44 backend needs: the call must revert
        // with VerifierCallFailed (selector prefix on the returndata), not
        // answer MAGIC_1271's "invalid" — underfunding is not forgery.
        (bool ok, bytes memory ret) = address(account).staticcall{gas: 2_000_000}(
            abi.encodeCall(IERC1271.isValidSignature, (digest, payload)));
        assertFalse(ok, "gas-starved verifier call must revert");
        assertEq(ret.length >= 4 ? bytes4(ret) : bytes4(0), Pq7913Signer.VerifierCallFailed.selector);
    }

    // ------------------------------------------- ZK account: floor + errors

    function test_zk_gas_floor_reverts_before_verifier() public {
        RevertingProofVerifier bad = new RevertingProofVerifier();
        Stealth8141ZkAccount acct = new Stealth8141ZkAccount(
            bytes32(uint256(1)), IProofVerifier(address(bad)), new MockFrameCtx());
        // entry-point-framed call with gas below the floor: the reverting
        // backend is never reached; the account fails fast and self-describes.
        // The exact `gasleft()` at the check is not stable — assert floor + error.
        vm.prank(address(0xaa));
        (bool ok, bytes memory ret) = address(acct).call{gas: 1_000_000}(
            abi.encodeCall(Stealth8141ZkAccount.executeFrame, (1, address(0xdEaD), 0, "")));
        assertFalse(ok, "below-floor frame must revert");
        assertEq(bytes4(ret), Stealth8141ZkAccount.GasFloorExceeded.selector);
        assertEq(ret.length, 68, "GasFloorExceeded(uint256,uint256) payload");
        uint256 floor;
        uint256 available;
        assembly ("memory-safe") {
            floor := mload(add(ret, 36)) // skip selector (4) + offset (32)
            available := mload(add(ret, 68))
        }
        assertEq(floor, 4_000_000);
        assertLt(available, 1_000_000, "reported available gas must be under the frame's budget");
    }

    function test_zk_proof_call_failure_surfaces() public {
        RevertingProofVerifier bad = new RevertingProofVerifier();
        MockFrameCtx ctx = new MockFrameCtx();
        Stealth8141ZkAccount acct = new Stealth8141ZkAccount(bytes32(uint256(1)), IProofVerifier(address(bad)), ctx);
        ctx.set(bytes32(uint256(1)), 1, "irrelevant");
        vm.prank(address(0xaa));
        vm.expectRevert(_stringRevert(Stealth8141ZkAccount.ProofCallFailed.selector, "backend unavailable"));
        acct.executeFrame(1, address(0xdEaD), 0, "");
    }

    function test_zk_valid_proof_still_spends() public {
        AcceptAllVerifier good = new AcceptAllVerifier();
        MockFrameCtx ctx = new MockFrameCtx();
        Stealth8141ZkAccount acct = new Stealth8141ZkAccount(bytes32(uint256(1)), IProofVerifier(address(good)), ctx);
        vm.deal(address(acct), 1 ether);
        ctx.set(bytes32(uint256(1)), 1, "any proof");
        vm.prank(address(0xaa));
        acct.executeFrame(1, address(0xdEaD), 0.1 ether, "");
        assertEq(address(0xdEaD).balance, 0.1 ether);
    }

    function test_zk_false_proof_is_not_authorized() public {
        // completes, answers false: forgery, not malfunction
        FalseProofVerifier bad = new FalseProofVerifier();
        MockFrameCtx ctx = new MockFrameCtx();
        Stealth8141ZkAccount acct = new Stealth8141ZkAccount(bytes32(uint256(1)), IProofVerifier(address(bad)), ctx);
        ctx.set(bytes32(uint256(1)), 1, "any proof");
        vm.prank(address(0xaa));
        vm.expectRevert(Stealth8141ZkAccount.NotAuthorized.selector);
        acct.executeFrame(1, address(0xdEaD), 0, "");
    }

    // -------------------------------------------------------- ML-DSA-44 frame

    /// @dev The direct-signature ZK-shape account (adapter over the ERC-7913
    ///      signer) under a gas cap: the signer reverts VerifierCallFailed, the
    ///      adapter propagates, the account surfaces ProofCallFailed — not
    ///      NotAuthorized.
    function test_mldsa44_frame_route_underfunded() public {
        MlDsa44CommitFrameVerifier adapter =
            new MlDsa44CommitFrameVerifier(IERC7913SignatureVerifier(address(signer)));
        MockFrameCtx ctx = new MockFrameCtx();
        Stealth8141ZkAccount acct =
            new Stealth8141ZkAccount(commitment, IProofVerifier(address(adapter)), ctx);
        ctx.set(digest, 1, payload);
        vm.prank(address(0xaa));
        // above the floor (gas forwarded past MIN_PROOF_GAS) but below the
        // ~15 M the ML-DSA-44 verify needs: the inner signer reverts
        // VerifierCallFailed, which the account surfaces as ProofCallFailed
        // (selector prefix — the OOG revert payload is not stable)
        (bool ok, bytes memory ret) = address(acct).call{gas: 5_000_000}(
            abi.encodeCall(Stealth8141ZkAccount.executeFrame, (1, address(0xdEaD), 0, "")));
        assertFalse(ok, "underfunded ML-DSA-44 frame must revert");
        assertEq(bytes4(ret), Stealth8141ZkAccount.ProofCallFailed.selector);
    }

    /// @dev Same route, fully funded: still spends.
    function test_mldsa44_frame_route_funded() public {
        MlDsa44CommitFrameVerifier adapter =
            new MlDsa44CommitFrameVerifier(IERC7913SignatureVerifier(address(signer)));
        MockFrameCtx ctx = new MockFrameCtx();
        Stealth8141ZkFactory factory = new Stealth8141ZkFactory(IProofVerifier(address(adapter)), ctx);
        Stealth8141ZkAccount acct = Stealth8141ZkAccount(payable(factory.createAccount(commitment)));
        vm.deal(address(acct), 1 ether);
        ctx.set(digest, 1, payload);
        vm.prank(address(0xaa));
        acct.executeFrame(1, address(0xdEaD), 0.1 ether, "");
        assertEq(address(0xdEaD).balance, 0.1 ether);
    }

    // ------------------------------------------------------------- helpers

    /// @dev `abi.encodeWithSelector(sel, abi.encodeWithSignature("Error(string)", msg))`
    ///      hoisted to one call level — the nested form overflows the legacy
    ///      codegen's stack frame (solc 0.8.30, via_ir=false).
    function _stringRevert(bytes4 sel, string memory msg_) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(sel, abi.encodeWithSignature("Error(string)", msg_));
    }

    function senderPayload() internal view returns (bytes memory) {
        // a payload that opens the commitment but signs under a key the sender
        // derives: from the fixture, `sender_derived_payload`
        string memory json = vm.readFile("../../python/scripts/mldsa44_commit_7913_demo.json");
        return vm.parseJsonBytes(json, ".sender_derived_payload");
    }
}

/// An IProofVerifier that completes and answers false.
contract FalseProofVerifier is IProofVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return false;
    }
}