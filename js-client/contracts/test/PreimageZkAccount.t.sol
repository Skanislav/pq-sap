// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {IProofVerifier, Stealth8141ZkAccount} from "../src/frames/Stealth8141ZkAccount.sol";
import {Stealth8141ZkFactory} from "../src/frames/Stealth8141ZkFactory.sol";
import {PreimageHonkVerifier} from "../src/frames/zk/PreimageHonkVerifier.sol";
import {MockFrameCtx} from "./ZkAccount.t.sol";

/// D-025: the same account, a different statement — knowledge of the spending
/// secret behind the commitment (noir/preimage-ownership), proven with UltraHonk.
/// Run: forge test --root contracts --match-contract PreimageZkAccount -vv
contract PreimageZkAccountTest is Test {
    address constant ENTRY_POINT = address(0xaa);
    // generate_prover.py defaults: sk = SHA-256("pq-stealth/preimage/keygen/v0" || 0x81*32),
    // opener from the fixture shared secret, message = the fixture challenge
    bytes32 constant COMMITMENT = 0x314f84573edd8bbff73fc40d65b78b07f92012710d6a6bc4accb53ea2a62ee18;
    bytes32 constant DIGEST = 0xb66fa4db389f1895d7f0460362f376c7220ed6088850f3b3523b82b58826aeb9;

    MockFrameCtx ctx;
    PreimageHonkVerifier honk;
    Stealth8141ZkFactory factory;
    Stealth8141ZkAccount acct;
    bytes proof;

    function setUp() public {
        ctx = new MockFrameCtx();
        honk = new PreimageHonkVerifier();
        factory = new Stealth8141ZkFactory(IProofVerifier(address(honk)), ctx);
        proof = vm.readFileBinary("../../noir/preimage-ownership/out/proof");
        acct = Stealth8141ZkAccount(payable(factory.createAccount(COMMITMENT)));
        vm.deal(address(acct), 1 ether);
        ctx.set(DIGEST, 1, proof);
    }

    function testSpendWithSecretProof() public {
        emit log_named_uint("PreimageHonkVerifier runtime code size", address(honk).code.length);
        emit log_named_uint("proof bytes", proof.length);
        address dest = address(0xdEaD);
        vm.prank(ENTRY_POINT);
        uint256 g0 = gasleft();
        acct.executeFrame(1, dest, 0.1 ether, "");
        emit log_named_uint("executeFrame gas (preimage proof verify + call)", g0 - gasleft());
        assertEq(dest.balance, 0.1 ether);
    }

    function testRejectsWrongDigestAndTamper() public {
        ctx.set(keccak256("other"), 1, proof);
        vm.prank(ENTRY_POINT);
        vm.expectRevert(Stealth8141ZkAccount.NotAuthorized.selector);
        acct.executeFrame(1, address(0xdEaD), 0.1 ether, "");
        bytes memory bad = proof;
        bad[300] ^= 0x01;
        ctx.set(DIGEST, 1, bad);
        vm.prank(ENTRY_POINT);
        vm.expectRevert(Stealth8141ZkAccount.NotAuthorized.selector);
        acct.executeFrame(1, address(0xdEaD), 0.1 ether, "");
    }
}
