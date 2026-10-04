// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {IERC7913SignatureVerifier} from "@openzeppelin/contracts/interfaces/IERC7913.sol";
import {IProofVerifier, Stealth8141ZkAccount} from "../src/frames/Stealth8141ZkAccount.sol";
import {IFrameTxContext} from "../src/frames/IFrameTxContext.sol";
import {Pq7913Signer} from "../src/Pq7913Signer.sol";
import {Stealth7913Account} from "../src/Stealth7913Account.sol";
import {IMlDsa44Erc7913Verifier, MlDsa44CommitSigner7913} from "../src/MlDsa44CommitSigner7913.sol";
import {IMlDsa44ExpandedKeys} from "../src/MlDsa44KeyRegistry.sol";

/// F5 (review 2026-10-01): malformed verifier responses lose their intended
/// error classification. Policy under test:
///   - completed call, response not exactly 32 bytes   -> call failure
///     (VerifierCallFailed / ProofCallFailed), NOT "invalid" / silent decode revert
///   - completed call, 32 bytes, canonical encoding:
///       answers the valid selector / true            -> accepted
///       answers false / a non-magic word              -> authorization rejection
///   - call does not complete (reverts)                -> call failure, keep diagnostics
contract F5MockFrameCtx is IFrameTxContext {
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

contract ShortReturn7913Verifier is IERC7913SignatureVerifier {
    function verify(bytes calldata, bytes32, bytes calldata) external pure returns (bytes4) {
        assembly ("memory-safe") { return(0, 16) }
    }
}

contract NonMagicWord7913Verifier is IERC7913SignatureVerifier {
    function verify(bytes calldata, bytes32, bytes calldata) external pure returns (bytes4) {
        assembly ("memory-safe") { return(0, 32) }  // 32 zero bytes: canonical, not magic
    }
}

contract MagicWord7913Verifier is IERC7913SignatureVerifier {
    function verify(bytes calldata, bytes32, bytes calldata) external pure returns (bytes4) {
        // ABI-encoded bytes4: selector left-aligned in the word, like abi.encode(bytes4)
        assembly ("memory-safe") { mstore(0, shl(224, 0x024ad318)) return(0, 32) }
    }
}

contract MagicExtraBytes7913Verifier is IERC7913SignatureVerifier {
    function verify(bytes calldata, bytes32, bytes calldata) external pure returns (bytes4) {
        // magic + trailing bytes: the ABI encoder never appends dirt to a
        // bytes4, so this is a malformed response, not a pass
        assembly ("memory-safe") { mstore(0, shl(224, 0x024ad318)) mstore(32, 0) return(0, 64) }
    }
}

contract MagicDirtyPadding7913Verifier is IERC7913SignatureVerifier {
    function verify(bytes calldata, bytes32, bytes calldata) external pure returns (bytes4) {
        // A bytes4 response occupies the high four bytes of its ABI word; this
        // has the right selector but nonzero padding and is therefore malformed.
        assembly ("memory-safe") { mstore(0, or(shl(224, 0x024ad318), 1)) return(0, 32) }
    }
}

contract MagicDirtyPaddingMlDsaVerifier is IMlDsa44Erc7913Verifier {
    function verify(bytes calldata, bytes32, bytes calldata) external pure returns (bytes4) {
        assembly ("memory-safe") { mstore(0, or(shl(224, 0x024ad318), 1)) return(0, 32) }
    }
}

contract NonzeroExpandedKeys is IMlDsa44ExpandedKeys {
    function expandedKey(bytes32) external pure returns (address) {
        return address(1);
    }
}

contract ExtraBytesTrueProofVerifier is IProofVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        assembly ("memory-safe") { mstore(0, 1) return(0, 64) }  // true + trailing dirt
    }
}

contract WordTwoProofVerifier is IProofVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        assembly ("memory-safe") { mstore(0, 2) return(0, 32) }
    }
}

contract ShortReturnProofVerifier is IProofVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        assembly ("memory-safe") { return(0, 16) }
    }
}

contract TrueProofVerifier is IProofVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        assembly ("memory-safe") { mstore(0, 1) return(0, 32) }
    }
}

contract FalseProofVerifier is IProofVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        assembly ("memory-safe") { mstore(0, 0) return(0, 32) }
    }
}

contract RevertingProofVerifier is IProofVerifier {
    error BackendSays(bytes reason);
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        revert BackendSays("invalid proof");
    }
}

contract ReviewF5Test is Test {
    bytes4 constant MAGIC = 0x024ad318;
    bytes32 constant DIGEST = bytes32(keccak256("f5 digest"));

    function _zk(IProofVerifier v) internal returns (Stealth8141ZkAccount, F5MockFrameCtx) {
        F5MockFrameCtx ctx = new F5MockFrameCtx();
        Stealth8141ZkAccount acct = new Stealth8141ZkAccount(bytes32(uint256(1)), v, ctx);
        ctx.set(bytes32(uint256(1)), 1, "any proof");
        return (acct, ctx);
    }

    // ---------------- 7913 route (Pq7913Signer / Stealth7913Account) ----------------

    function test_f5a_short_return_is_verifier_call_failed() public {
        Stealth7913Account account = new Stealth7913Account(abi.encodePacked(address(new ShortReturn7913Verifier()), bytes32(uint256(1))));
        vm.expectRevert(
            abi.encodeWithSelector(Pq7913Signer.VerifierCallFailed.selector, hex"00000000000000000000000000000000")
        );
        account.isValidSignature(DIGEST, abi.encode(bytes32(uint256(1))));
    }

    function test_f5a_extra_bytes_magic_is_verifier_call_failed() public {
        Stealth7913Account account = new Stealth7913Account(abi.encodePacked(address(new MagicExtraBytes7913Verifier()), bytes32(uint256(1))));
        vm.expectRevert(
            abi.encodeWithSelector(Pq7913Signer.VerifierCallFailed.selector, abi.encodePacked(bytes32(MAGIC), bytes32(0)))
        );
        account.isValidSignature(DIGEST, abi.encode(bytes32(uint256(1))));
    }

    function test_f5a_magic_with_dirty_padding_is_verifier_call_failed() public {
        Stealth7913Account account = new Stealth7913Account(
            abi.encodePacked(address(new MagicDirtyPadding7913Verifier()), bytes32(uint256(1))));
        vm.expectRevert(
            abi.encodeWithSelector(
                Pq7913Signer.VerifierCallFailed.selector,
                abi.encodePacked(bytes32((uint256(uint32(MAGIC)) << 224) | 1))
            )
        );
        account.isValidSignature(DIGEST, abi.encode(bytes32(uint256(1))));
    }

    function test_f5a_canonical_non_magic_word_is_invalid_not_crash() public {
        Stealth7913Account account = new Stealth7913Account(abi.encodePacked(address(new NonMagicWord7913Verifier()), bytes32(uint256(1))));
        assertEq(uint32(account.isValidSignature(DIGEST, abi.encode(bytes32(uint256(1))))), uint32(0xffffffff));
    }

    function test_f5a_canonical_magic_still_accepted() public {
        Stealth7913Account account = new Stealth7913Account(abi.encodePacked(address(new MagicWord7913Verifier()), bytes32(uint256(1))));
        // SignerERC7913 answers the ERC-1271 magic word when the 7913 check passes
        assertEq(uint32(account.isValidSignature(DIGEST, abi.encode(bytes32(uint256(1))))), uint32(0x1626ba7e));
    }

    function test_f5a_commit_signer_dirty_padding_is_verifier_call_failed() public {
        MlDsa44CommitSigner7913 signer = new MlDsa44CommitSigner7913(
            new MagicDirtyPaddingMlDsaVerifier(), new NonzeroExpandedKeys());
        bytes memory pk = new bytes(signer.PUBLIC_KEY_LENGTH());
        bytes32 opener = bytes32(uint256(2));
        bytes memory key = abi.encodePacked(signer.commitment(signer.spendKey(pk), opener));
        bytes memory signature = bytes.concat(pk, abi.encodePacked(opener), new bytes(signer.ML_DSA_44_SIGNATURE_LENGTH()));
        vm.expectRevert(
            abi.encodeWithSelector(
                MlDsa44CommitSigner7913.VerifierCallFailed.selector,
                abi.encodePacked(bytes32((uint256(uint32(MAGIC)) << 224) | 1))
            )
        );
        signer.verify(key, DIGEST, signature);
    }

    // ---------------- ZK route (Stealth8141ZkAccount) ----------------

    function test_f5b_zk_short_return_is_proof_call_failed() public {
        (Stealth8141ZkAccount acct,) = _zk(new ShortReturnProofVerifier());
        vm.prank(address(0xaa));
        vm.expectRevert(
            abi.encodeWithSelector(Stealth8141ZkAccount.ProofCallFailed.selector, hex"00000000000000000000000000000000")
        );
        acct.executeFrame(1, address(0xdEaD), 0, "");
    }

    function test_f5b_zk_word_two_is_proof_call_failed() public {
        (Stealth8141ZkAccount acct,) = _zk(new WordTwoProofVerifier());
        vm.prank(address(0xaa));
        // pre-fix: length passes, abi.decode(ret,(bool)) reverts EMPTY
        vm.expectRevert(
            abi.encodeWithSelector(Stealth8141ZkAccount.ProofCallFailed.selector, hex"0000000000000000000000000000000000000000000000000000000000000002")
        );
        acct.executeFrame(1, address(0xdEaD), 0, "");
    }

    function test_f5b_zk_extra_bytes_true_is_proof_call_failed() public {
        (Stealth8141ZkAccount acct,) = _zk(new ExtraBytesTrueProofVerifier());
        vm.prank(address(0xaa));
        vm.expectRevert(
            abi.encodeWithSelector(Stealth8141ZkAccount.ProofCallFailed.selector, abi.encodePacked(uint256(1), uint256(0)))
        );
        acct.executeFrame(1, address(0xdEaD), 0, "");
    }

    function test_f5b_zk_canonical_true_still_accepted() public {
        (Stealth8141ZkAccount acct,) = _zk(new TrueProofVerifier());
        vm.prank(address(0xaa));
        acct.executeFrame(1, address(0xdEaD), 0, "");
    }

    function test_f5b_zk_canonical_false_still_not_authorized() public {
        (Stealth8141ZkAccount acct,) = _zk(new FalseProofVerifier());
        vm.prank(address(0xaa));
        vm.expectRevert(Stealth8141ZkAccount.NotAuthorized.selector);
        acct.executeFrame(1, address(0xdEaD), 0, "");
    }

    function test_f5b_zk_revert_keeps_diagnostics() public {
        (Stealth8141ZkAccount acct,) = _zk(new RevertingProofVerifier());
        vm.prank(address(0xaa));
        vm.expectRevert(
            abi.encodeWithSelector(
                Stealth8141ZkAccount.ProofCallFailed.selector,
                abi.encodeWithSelector(RevertingProofVerifier.BackendSays.selector, "invalid proof")
            )
        );
        acct.executeFrame(1, address(0xdEaD), 0, "");
    }
}
