// SPDX-License-Identifier: MIT
// FILE: PointerSig.sol
// Description: POC of the "65-byte signature as pointers" hotfix.
//
// The classic ECDSA signature tuple (v, r, s) keeps its ABI shape, but `v`
// becomes a *version* selector:
//
//   v = 27 / 28        classic ECDSA; (r, s) are the curve scalars, recovered with ecrecover.
//   v = V_PQ    (0x50) post-quantum;  r = index of an ML-DSA public key in the key table,
//                                     s = index of an ML-DSA signature in the signature table.
//   v = V_HYBRID(0x51) hybrid;        r = key index (entry binds an EOA *and* an ML-DSA key),
//                                     s = index of a blob holding (ECDSA sig || ML-DSA sig);
//                                     both must verify over the same digest.
//
// Every consumer that already takes (digest, v, r, s) and expects an `address`
// back keeps its interface; only the recovery primitive changes.
pragma solidity ^0.8.25;

import {SSTORE2} from "sstore2/SSTORE2.sol";
import {ISigVerifier} from "InterfaceVerifier/IVerifier.sol";

/// @notice Lookup tables + version-dispatching recover(). Pure-view recovery, so it is a drop-in for ecrecover.
contract PointerSigRegistry {
    uint8 public constant V_PQ = 0x50;
    uint8 public constant V_HYBRID = 0x51;

    /// @dev ML-DSA-44 (Dilithium2) signature size as expected by the ZKNOX verifier.
    uint256 public constant PQ_SIG_LEN = 2420;

    struct KeyEntry {
        address pkPointer; // SSTORE2 pointer to the expanded ML-DSA public key
        address pqAddress; // keccak256(pk)[12:] — the "address" a pure-PQ key controls
        address classicAddress; // EOA bound to this key for hybrid mode (msg.sender at registration)
    }

    ISigVerifier public immutable verifier;

    KeyEntry[] public keys;
    address[] public sigPointers; // SSTORE2 pointers to published signatures

    event KeyRegistered(uint256 indexed index, address pqAddress, address classicAddress);
    event SignaturePublished(uint256 indexed index, address pointer, uint256 length);

    error UnknownVersion(uint8 v);
    error BadIndex();
    error InvalidPqSignature();
    error InvalidClassicSignature();

    constructor(ISigVerifier _verifier) {
        verifier = _verifier;
    }

    // ----------------------------------------------------------------- tables

    /// @notice Register an ML-DSA public key. Returns its index (what goes into `r`).
    function registerKey(bytes calldata expandedPk) external returns (uint256 index) {
        address pointer = SSTORE2.write(expandedPk);
        address pqAddr = address(uint160(uint256(keccak256(expandedPk))));
        index = keys.length;
        keys.push(KeyEntry({pkPointer: pointer, pqAddress: pqAddr, classicAddress: msg.sender}));
        emit KeyRegistered(index, pqAddr, msg.sender);
    }

    /// @notice Publish a signature blob (ML-DSA sig, or abi.encode(ecdsaSig, pqSig) for hybrid).
    ///         Anyone may publish; the blob is useless unless it verifies against a digest at use time.
    ///         Returns its index (what goes into `s`).
    function publishSignature(bytes calldata sig) external returns (uint256 index) {
        address pointer = SSTORE2.write(sig);
        index = sigPointers.length;
        sigPointers.push(pointer);
        emit SignaturePublished(index, pointer, sig.length);
    }

    function keyCount() external view returns (uint256) {
        return keys.length;
    }

    function signatureCount() external view returns (uint256) {
        return sigPointers.length;
    }

    // ---------------------------------------------------------------- recover

    /// @notice ecrecover-compatible entry point. Returns the signer address or reverts.
    function recover(bytes32 digest, uint8 v, bytes32 r, bytes32 s) external view returns (address) {
        if (v == 27 || v == 28) {
            address a = ecrecover(digest, v, r, s);
            if (a == address(0)) revert InvalidClassicSignature();
            return a;
        }
        if (v == V_PQ) {
            KeyEntry memory k = _key(r);
            bytes memory pqSig = _sig(s);
            _verifyPq(k.pkPointer, digest, pqSig);
            return k.pqAddress;
        }
        if (v == V_HYBRID) {
            KeyEntry memory k = _key(r);
            (bytes memory ecdsaSig, bytes memory pqSig) = abi.decode(_sig(s), (bytes, bytes));
            if (ecdsaSig.length != 65) revert InvalidClassicSignature();
            (bytes32 cr, bytes32 cs, uint8 cv) = _split(ecdsaSig);
            if (ecrecover(digest, cv, cr, cs) != k.classicAddress) revert InvalidClassicSignature();
            _verifyPq(k.pkPointer, digest, pqSig);
            return k.classicAddress;
        }
        revert UnknownVersion(v);
    }

    // --------------------------------------------------------------- internal

    function _key(bytes32 r) internal view returns (KeyEntry memory) {
        uint256 i = uint256(r);
        if (i >= keys.length) revert BadIndex();
        return keys[i];
    }

    function _sig(bytes32 s) internal view returns (bytes memory) {
        uint256 i = uint256(s);
        if (i >= sigPointers.length) revert BadIndex();
        return SSTORE2.read(sigPointers[i]);
    }

    function _verifyPq(address pkPointer, bytes32 digest, bytes memory pqSig) internal view {
        if (pqSig.length != PQ_SIG_LEN) revert InvalidPqSignature();
        bytes4 res = verifier.verify(abi.encodePacked(pkPointer), digest, pqSig);
        if (res != ISigVerifier.verify.selector) revert InvalidPqSignature();
    }

    function _split(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}

/// @notice Example consumer: a vault whose withdraw-by-signature ABI is the classic (v, r, s)
///         and is untouched by the PQ migration. Only the recovery call changed.
contract PointerSigVault {
    PointerSigRegistry public immutable registry;
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public nonces;

    constructor(PointerSigRegistry _registry) {
        registry = _registry;
    }

    function depositFor(address owner) external payable {
        balanceOf[owner] += msg.value;
    }

    function withdrawDigest(address owner, address to, uint256 amount, uint256 nonce) public view returns (bytes32) {
        return keccak256(abi.encode(block.chainid, address(this), owner, to, amount, nonce));
    }

    /// @dev Same ABI as a pre-quantum permit/withdraw: (owner, to, amount, v, r, s).
    function withdrawWithSig(address owner, address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = withdrawDigest(owner, to, amount, nonces[owner]++);
        address signer = registry.recover(digest, v, r, s);
        require(signer == owner, "bad signer");
        balanceOf[owner] -= amount;
        (bool ok,) = to.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
