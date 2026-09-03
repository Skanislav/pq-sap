// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {IFrameTxContext} from "../src/frames/IFrameTxContext.sol";
import {IProofVerifier, Stealth8141ZkAccount} from "../src/frames/Stealth8141ZkAccount.sol";
import {Stealth8141ZkFactory} from "../src/frames/Stealth8141ZkFactory.sol";
import {HonkVerifier} from "../src/frames/zk/SphincsC13HonkVerifier.sol";

/// Stand-in for the Yul FrameTxContext outside a frame transaction: returns a chosen
/// sig_hash and signature bytes so `executeFrame` can be exercised in forge.
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

/// A second backend that accepts everything: stands in for "the STARK verifier" to show
/// the rotation path; the real swap target must implement the same statement.
contract AcceptAllVerifier is IProofVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) { return true; }
}

/// ZK SPHINCS- spend, end to end in forge: real UltraHonk proof of the C13 verification
/// (noir/sphincs-c13-verify, fixture vector `raw`) accepted by the account, gas measured.
/// Run: forge test --root contracts --match-contract ZkAccount -vv
contract ZkAccountTest is Test {
    address constant ENTRY_POINT = address(0xaa);
    bytes32 constant COMMITMENT = 0x14f2101faec0e1c72e66c0d7e8f122ce7803b32d9d42547fddf65adec63df8ed;
    bytes32 constant DIGEST = 0xb66fa4db389f1895d7f0460362f376c7220ed6088850f3b3523b82b58826aeb9;

    MockFrameCtx ctx;
    HonkVerifier honk;
    Stealth8141ZkFactory factory;
    Stealth8141ZkAccount acct;
    bytes proof;

    function setUp() public {
        ctx = new MockFrameCtx();
        honk = new HonkVerifier();
        factory = new Stealth8141ZkFactory(IProofVerifier(address(honk)), ctx);
        proof = vm.readFileBinary("../../noir/sphincs-c13-verify/out/proof");
        acct = Stealth8141ZkAccount(payable(factory.createAccount(COMMITMENT)));
        vm.deal(address(acct), 1 ether);
        ctx.set(DIGEST, 1, proof);
    }

    function testVerifierSizeAndProofShape() public {
        emit log_named_uint("HonkVerifier runtime code size", address(honk).code.length);
        emit log_named_uint("proof bytes", proof.length);
        emit log_named_uint("ZkAccount runtime code size", address(acct).code.length);
        assertEq(acct.COMMITMENT(), COMMITMENT);
        assertEq(factory.getAccountAddress(COMMITMENT), address(acct));
    }

    function testSpendWithProof() public {
        address dest = address(0xdEaD);
        uint256 before = dest.balance;
        vm.prank(ENTRY_POINT);
        uint256 g0 = gasleft();
        acct.executeFrame(1, dest, 0.1 ether, "");
        uint256 used = g0 - gasleft();
        emit log_named_uint("executeFrame gas (Honk proof verify + call)", used);
        assertEq(dest.balance - before, 0.1 ether);
    }

    function testRejectsWrongDigest() public {
        ctx.set(keccak256("other frames"), 1, proof);
        vm.prank(ENTRY_POINT);
        vm.expectRevert(Stealth8141ZkAccount.NotAuthorized.selector);
        acct.executeFrame(1, address(0xdEaD), 0.1 ether, "");
    }

    function testRejectsTamperedProof() public {
        bytes memory bad = proof;
        bad[200] ^= 0x01;
        ctx.set(DIGEST, 1, bad);
        vm.prank(ENTRY_POINT);
        vm.expectRevert(Stealth8141ZkAccount.NotAuthorized.selector);
        acct.executeFrame(1, address(0xdEaD), 0.1 ether, "");
    }

    function testRejectsOtherCommitment() public {
        Stealth8141ZkAccount other =
            Stealth8141ZkAccount(payable(factory.createAccount(keccak256("someone else"))));
        vm.deal(address(other), 1 ether);
        vm.prank(ENTRY_POINT);
        vm.expectRevert(Stealth8141ZkAccount.NotAuthorized.selector);
        other.executeFrame(1, address(0xdEaD), 0.1 ether, "");
    }

    function testRejectsNonEntryPoint() public {
        vm.expectRevert(abi.encodeWithSelector(Stealth8141ZkAccount.NotEntryPoint.selector, address(this)));
        acct.executeFrame(1, address(0xdEaD), 0.1 ether, "");
    }

    function testVerifierRotationIsAnAuthorizedSpend() public {
        AcceptAllVerifier next = new AcceptAllVerifier();
        // direct call: refused
        vm.expectRevert(abi.encodeWithSelector(Stealth8141ZkAccount.NotSelf.selector, address(this)));
        acct.setVerifier(next);
        // through executeFrame under the current (Honk) verifier: accepted
        vm.prank(ENTRY_POINT);
        acct.executeFrame(1, address(acct), 0, abi.encodeCall(Stealth8141ZkAccount.setVerifier, (next)));
        assertEq(address(acct.verifier()), address(next));
    }
}
