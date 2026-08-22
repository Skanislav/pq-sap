// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {ZKNOX_ethdilithium} from "../src/ZKNOX_ethdilithium.sol";
import {PythonSigner} from "../src/ZKNOX_PythonSigner.sol";
import {PointerSigRegistry, PointerSigVault} from "../src/PointerSig.sol";
import {Constants} from "./seed.sol";

/// POC: (v, r, s) kept as the signature ABI; v selects classic / pq / hybrid,
/// r and s become lookup-table indices for the PQ modes.
contract PointerSigTest is Test {
    ZKNOX_ethdilithium dilithium = new ZKNOX_ethdilithium();
    PythonSigner pythonSigner = new PythonSigner();
    PointerSigRegistry registry;
    PointerSigVault vault;
    uint8 V_PQ;
    uint8 V_HYBRID;

    uint256 constant CLASSIC_PK = 0xA11CE;
    address classicOwner = vm.addr(CLASSIC_PK);
    address payable recipient = payable(address(0xBEEF));

    function setUp() public {
        registry = new PointerSigRegistry(dilithium);
        vault = new PointerSigVault(registry);
        V_PQ = registry.V_PQ();
        V_HYBRID = registry.V_HYBRID();
    }

    // ------------------------------------------------------------ helpers

    function _pqSign(bytes32 digest) internal returns (bytes memory sig) {
        (bytes memory cTilde, bytes memory z, bytes memory h) =
            pythonSigner.sign("pythonref", vm.toString(digest), "ETH", Constants.SEED_POSTQUANTUM_STR);
        sig = abi.encodePacked(cTilde, z, h);
        assertEq(sig.length, registry.PQ_SIG_LEN());
    }

    function _registerPqKey(address from) internal returns (uint256 idx, address pqAddr) {
        bytes memory pk = pythonSigner.getPubKey("pythonref", "ETH", Constants.SEED_POSTQUANTUM_STR);
        vm.prank(from);
        idx = registry.registerKey(pk);
        (, pqAddr,) = registry.keys(idx);
        assertEq(pqAddr, address(uint160(uint256(keccak256(pk)))));
    }

    // ------------------------------------------------------- classic path

    function testClassicUnchanged() public {
        vault.depositFor{value: 1 ether}(classicOwner);
        bytes32 digest = vault.withdrawDigest(classicOwner, recipient, 0.4 ether, 0);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(CLASSIC_PK, digest);

        vault.withdrawWithSig(classicOwner, recipient, 0.4 ether, v, r, s);
        assertEq(recipient.balance, 0.4 ether);
        assertEq(vault.balanceOf(classicOwner), 0.6 ether);
    }

    // ------------------------------------------------------------ pq path

    function testPqPointers() public {
        (uint256 keyIdx, address pqOwner) = _registerPqKey(address(this));
        vault.depositFor{value: 1 ether}(pqOwner);

        bytes32 digest = vault.withdrawDigest(pqOwner, recipient, 0.25 ether, 0);
        bytes memory pqSig = _pqSign(digest);

        uint256 g0 = gasleft();
        uint256 sigIdx = registry.publishSignature(pqSig);
        console.log("publishSignature gas:", g0 - gasleft());

        // Same ABI as classic: v = version, r = key index, s = signature index.
        g0 = gasleft();
        vault.withdrawWithSig(pqOwner, recipient, 0.25 ether, V_PQ, bytes32(keyIdx), bytes32(sigIdx));
        console.log("withdrawWithSig (pq) gas:", g0 - gasleft());

        assertEq(recipient.balance, 0.25 ether);
        assertEq(vault.balanceOf(pqOwner), 0.75 ether);
    }

    function testPqSignatureIsBoundToDigest() public {
        (uint256 keyIdx, address pqOwner) = _registerPqKey(address(this));
        vault.depositFor{value: 1 ether}(pqOwner);

        // sign a withdraw of 0.1, then try to replay the pointer for 0.9
        bytes32 digest = vault.withdrawDigest(pqOwner, recipient, 0.1 ether, 0);
        uint256 sigIdx = registry.publishSignature(_pqSign(digest));

        vm.expectRevert(PointerSigRegistry.InvalidPqSignature.selector);
        vault.withdrawWithSig(pqOwner, recipient, 0.9 ether, V_PQ, bytes32(keyIdx), bytes32(sigIdx));
    }

    function testPqBadIndices() public {
        (uint256 keyIdx,) = _registerPqKey(address(this));
        bytes32 digest = keccak256("x");
        vm.expectRevert(PointerSigRegistry.BadIndex.selector);
        registry.recover(digest, V_PQ, bytes32(keyIdx + 1), bytes32(0));
        vm.expectRevert(PointerSigRegistry.BadIndex.selector);
        registry.recover(digest, V_PQ, bytes32(keyIdx), bytes32(uint256(7)));
    }

    function testUnknownVersion() public {
        vm.expectRevert(abi.encodeWithSelector(PointerSigRegistry.UnknownVersion.selector, uint8(5)));
        registry.recover(keccak256("x"), 5, bytes32(0), bytes32(0));
    }

    // -------------------------------------------------------- hybrid path

    function testHybridBothRequired() public {
        // EOA registers the PQ key, binding classic + pq under one index.
        (uint256 keyIdx,) = _registerPqKey(classicOwner);
        vault.depositFor{value: 1 ether}(classicOwner);

        bytes32 digest = vault.withdrawDigest(classicOwner, recipient, 0.5 ether, 0);
        (uint8 cv, bytes32 cr, bytes32 cs) = vm.sign(CLASSIC_PK, digest);
        bytes memory ecdsaSig = abi.encodePacked(cr, cs, cv);
        bytes memory pqSig = _pqSign(digest);

        uint256 sigIdx = registry.publishSignature(abi.encode(ecdsaSig, pqSig));
        vault.withdrawWithSig(classicOwner, recipient, 0.5 ether, V_HYBRID, bytes32(keyIdx), bytes32(sigIdx));
        assertEq(recipient.balance, 0.5 ether);

        // Wrong EOA half: pq still valid, classic signed by someone else -> reject.
        bytes32 digest2 = vault.withdrawDigest(classicOwner, recipient, 0.5 ether, 1);
        (cv, cr, cs) = vm.sign(0xB0B, digest2);
        uint256 badIdx = registry.publishSignature(abi.encode(abi.encodePacked(cr, cs, cv), _pqSign(digest2)));
        vm.expectRevert(PointerSigRegistry.InvalidClassicSignature.selector);
        vault.withdrawWithSig(classicOwner, recipient, 0.5 ether, V_HYBRID, bytes32(keyIdx), bytes32(badIdx));
    }
}
