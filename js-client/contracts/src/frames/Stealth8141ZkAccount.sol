// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IFrameTxContext} from "./IFrameTxContext.sol";

/// @notice The bb-generated UltraHonk verifier surface (`HonkVerifier.verify`), and what
///         any replacement backend (a STARK verifier, a wrapped proof) must expose.
interface IProofVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
}

/// @title Stealth8141ZkAccount
/// @notice Stealth account spent through an EIP-8141 frame transaction and authorized by a
///         zero-knowledge proof instead of a signature: the proof shows knowledge of a valid
///         SPHINCS- C13 signature over `sig_hash` under a public key that opens the
///         account's `COMMITMENT` (noir/sphincs-c13-verify). The key is never revealed, so
///         two spends by the same recipient are unlinkable — the D-018 open item.
///
///         Same authorization shape as `Stealth8141Account`: `msg.sender == ENTRY_POINT`
///         (this call IS a DEFAULT frame), the proof travels as the ARBITRARY-scheme
///         signature at `sigIndex`, and the statement binds `sig_hash` (TXPARAM 0x08), so a
///         proof authorizes exactly one (sponsor, nonce, frames) tuple.
///
///         Gas-exhaustion semantics (issue #32): `executeFrame` checks a gas
///         floor (`MIN_PROOF_GAS`) before the verifier call and no longer
///         swallows a verifier revert — underfunding surfaces as
///         `GasFloorExceeded`, a reverting backend as `ProofCallFailed`, and
///         only a completed `verify == false` is `NotAuthorized`. The tooling
///         surface `isValidProof` keeps the bool contract.
///
///         The verifier is a rotatable pointer, not an immutable, because the proof system
///         is the part expected to change: UltraHonk (BN254/KZG) is classically sound only,
///         so before a CRQC the owner swaps in a hash-based (STARK) verifier for the same
///         statement. The swap is an ordinary spend: `executeFrame` targeting this account
///         with `setVerifier(new)`, i.e. authorized by a proof under the current verifier and
///         covered by `sig_hash`. Public-input layout is part of the statement and fixed:
///         [message_hi, message_lo, commitment_hi, commitment_lo], each a 128-bit half.
contract Stealth8141ZkAccount {
    address public constant ENTRY_POINT = address(0xaa);

    IFrameTxContext public immutable FRAME_CTX;
    bytes32 public immutable COMMITMENT;
    IProofVerifier public verifier;

    event VerifierRotated(address indexed previous, address indexed current);

    error NotEntryPoint(address caller);
    error NotSelf(address caller);
    error NotAuthorized();
    error CallFailed(bytes returnData);
    /// @notice The frame's remaining gas is below `MIN_PROOF_GAS`, so the proof
    ///         verify cannot be trusted to have completed; distinct from
    ///         `NotAuthorized` so an integrator tells underfunding from a bad
    ///         proof (issue #32).
    error GasFloorExceeded(uint256 floor, uint256 available);
    /// @notice The proof verifier call did not complete (it reverted with
    ///         `returnData`); distinct from `NotAuthorized`.
    error ProofCallFailed(bytes returnData);

    /// @notice Minimum gas the frame must still hold for the proof verify. The
    ///         shipped backends measure (whole call, forge/solc 0.8.30/prague,
    ///         GasExhaustion.t.sol): preimage-ownership ~3.0 M, UltraHonk C13
    ///         ~3.6 M; 4 M leaves headroom for larger proofs of the same
    ///         statements. Below this, `executeFrame` fails fast and cheap with
    ///         `GasFloorExceeded` instead of letting the verifier run out of
    ///         gas mid-call, which `_verify` would collapse into "not
    ///         authorized". A cheaper replacement backend still works — the
    ///         floor is a caller budget, not a verifier cost — but a sponsor
    ///         must supply at least this much.
    uint256 public constant MIN_PROOF_GAS = 4_000_000;

    constructor(bytes32 commitment_, IProofVerifier verifier_, IFrameTxContext frameCtx_) {
        COMMITMENT = commitment_;
        verifier = verifier_;
        FRAME_CTX = frameCtx_;
    }

    receive() external payable {}

    /// @notice Execute `to.call{value}(data)` from this account inside a frame transaction,
    ///         authorized by the proof carried as signature `sigIndex`.
    function executeFrame(uint256 sigIndex, address to, uint256 value, bytes calldata data) external {
        if (msg.sender != ENTRY_POINT) revert NotEntryPoint(msg.sender);
        bytes32 digest = FRAME_CTX.sigHash();
        bytes memory proof = FRAME_CTX.signature(sigIndex);
        if (gasleft() < MIN_PROOF_GAS) revert GasFloorExceeded(MIN_PROOF_GAS, gasleft());
        (bool ok, bytes memory ret) = address(verifier).staticcall(
            abi.encodeWithSelector(IProofVerifier.verify.selector, proof, publicInputs(digest)));
        if (!ok) revert ProofCallFailed(ret);
        // a completed call must answer exactly one canonical bool word. A
        // shorter, longer, or non-canonical return (e.g. the integer 2) is a
        // verifier malfunction, not a bad-proof verdict — and decoding it as a
        // bool would revert empty, losing the classification (review F5).
        if (ret.length != 32 || abi.decode(ret, (uint256)) > 1) revert ProofCallFailed(ret);
        if (abi.decode(ret, (bool))) {} else { revert NotAuthorized(); }
        (bool callOk, bytes memory callRet) = to.call{value: value}(data);
        if (!callOk) revert CallFailed(callRet);
    }

    /// @notice Swap the proof backend. Only callable by the account itself, i.e. through an
    ///         authorized `executeFrame` — the current backend approves its successor.
    function setVerifier(IProofVerifier next) external {
        if (msg.sender != address(this)) revert NotSelf(msg.sender);
        emit VerifierRotated(address(verifier), address(next));
        verifier = next;
    }

    /// @notice Statement check, exposed for tooling: is `proof` valid for `digest` against
    ///         this account's commitment under the current verifier?
    function isValidProof(bytes32 digest, bytes calldata proof) external view returns (bool) {
        return _verify(digest, proof);
    }

    function publicInputs(bytes32 digest) public view returns (bytes32[] memory pubs) {
        pubs = new bytes32[](4);
        pubs[0] = bytes32(uint256(uint128(bytes16(digest))));
        pubs[1] = bytes32(uint256(uint128(uint256(digest))));
        pubs[2] = bytes32(uint256(uint128(bytes16(COMMITMENT))));
        pubs[3] = bytes32(uint256(uint128(uint256(COMMITMENT))));
    }

    function _verify(bytes32 digest, bytes memory proof) internal view returns (bool) {
        (bool ok, bytes memory ret) = address(verifier).staticcall(
            abi.encodeWithSelector(IProofVerifier.verify.selector, proof, publicInputs(digest)));
        // same malformed-return policy as executeFrame (review F5): a
        // non-canonical response is a malfunction, reported as false here
        // because the tooling surface answers a bool
        return ok && ret.length == 32 && abi.decode(ret, (uint256)) <= 1 && abi.decode(ret, (bool));
    }
}
