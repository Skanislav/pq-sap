// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// "65-byte signature as pointers": the classic ECDSA tuple (v, r, s) keeps its
// ABI shape, but `v` becomes a version selector. Consumers that take
// (digest, v, r, s) and expect an `address` back keep their interface; only
// the recovery primitive changes (`ecrecover` -> `registry.recover`).
//
//   v = 27 / 28          classic ECDSA; (r, s) are the curve scalars.
//   v = V_PQ       0x50  ML-DSA;  r = key-table index (entry = PKContract),
//                                 s = signature-table index (2,420-B ML-DSA sig).
//   v = V_HYBRID   0x51  EOA + ML-DSA; r = key-table index (entry binds the
//                                 registering EOA), s = index of
//                                 abi.encode(ecdsaSig, pqSig); both must verify.
//   v = V_SPHINCS  0x52  SPHINCS- C13; r = THE KEY ITSELF (pkSeed[0:16] ||
//                                 pkRoot[0:16] — a C13 public key is one word,
//                                 so there is no key table and no registration),
//                                 s = signature-table index (3,688-B C13 sig).
//                                 Address = keccak256(r)[12:].
//   v = V_SPHINCS_COMMIT 0x53  SPHINCS- C13 behind a hiding commitment;
//                                 r = keccak256(COMMIT_DOMAIN || pk || opener),
//                                 s = index of blob pk(32) || opener(32) || c13sig.
//                                 Address = keccak256(r)[12:] — the sender of a
//                                 stealth payment can compute it (pk from the
//                                 meta-address, opener from the KEM shared
//                                 secret), so it is a stealth address in plain
//                                 address shape. Opening reveals pk (D-018).
//
// WHERE THE VALUE MUST LIVE. `recover` only authorizes actions inside contracts
// that call it. keccak256(r)[12:] is not an account: native ETH or tokens sent
// to it directly are unspendable, because no EVM rule lets a hash-based key
// move them. The addresses these branches return are meaningful only as owner
// keys inside pointer-aware contracts (a vault like the one below, a token
// whose permit/transfer-by-sig path adopted `recover`). A stealth RECEIVE of
// arbitrary value still needs the stealth address to be a contract account
// (the CREATE2 ERC-7913 route); this registry is the spend-authorization shim
// for value already held by adopting contracts.
//
// Adapted from docs/pointer-sig-poc/PointerSig.sol (run against ETHDILITHIUM
// main, where the verifier reads SSTORE2 key blobs) to the vendored df999ed,
// whose ERC-7913 `verify` takes a PKContract address as the key.

import {SSTORE2} from "solady/utils/SSTORE2.sol";
import {IERC7913SignatureVerifier} from "@openzeppelin/contracts/interfaces/IERC7913.sol";
import {IPKContract} from "ethdilithium/ZKNOX_PKContract.sol";
import {PubKey} from "ethdilithium/ZKNOX_dilithium_utils.sol";
import {ISphincsC13Verifier} from "./SphincsC13Signer7913.sol";

/// @notice Lookup tables + version-dispatching recover(). View-only recovery, so it is a drop-in for ecrecover.
contract PointerSigRegistry {
    uint8 public constant V_PQ = 0x50;
    uint8 public constant V_HYBRID = 0x51;
    uint8 public constant V_SPHINCS = 0x52;
    uint8 public constant V_SPHINCS_COMMIT = 0x53;

    /// @dev ML-DSA-44 (Dilithium2) signature size as expected by the ZKNOX verifier.
    uint256 public constant PQ_SIG_LEN = 2420;
    /// @dev SPHINCS- C13 signature size.
    uint256 public constant C13_SIG_LEN = 3688;
    /// @dev Same domain as SphincsC13CommitSigner7913 / js-client/src/sphincs.ts.
    bytes32 public constant COMMIT_DOMAIN = "pq-stealth/sphincs-c13/commit/v0";

    struct KeyEntry {
        address pkContract;     // deployed PKContract holding the expanded ML-DSA public key
        address pqAddress;      // keccak256(abi.encode(aHat, tr, t1))[12:] — the "address" a pure-PQ key controls
        address classicAddress; // EOA bound to this key for hybrid mode (msg.sender at registration)
    }

    IERC7913SignatureVerifier public immutable mldsa;
    ISphincsC13Verifier public immutable sphincs;

    KeyEntry[] public keys;
    address[] public sigPointers; // SSTORE2 pointers to published signatures

    event KeyRegistered(uint256 indexed index, address pqAddress, address classicAddress);
    event SignaturePublished(uint256 indexed index, address pointer, uint256 length);

    error UnknownVersion(uint8 v);
    error BadIndex();
    error InvalidPqSignature();
    error InvalidClassicSignature();
    error InvalidCommitment();

    constructor(IERC7913SignatureVerifier _mldsa, ISphincsC13Verifier _sphincs) {
        mldsa = _mldsa;
        sphincs = _sphincs;
    }

    // ----------------------------------------------------------------- tables

    /// @notice Register an ML-DSA public key (as its deployed PKContract). Returns its index (what goes into `r`).
    function registerKey(address pkContract) external returns (uint256 index) {
        PubKey memory pk = IPKContract(pkContract).getPublicKey();
        address pqAddr = address(uint160(uint256(keccak256(abi.encode(pk.aHat, pk.tr, pk.t1)))));
        index = keys.length;
        keys.push(KeyEntry({pkContract: pkContract, pqAddress: pqAddr, classicAddress: msg.sender}));
        emit KeyRegistered(index, pqAddr, msg.sender);
    }

    /// @notice Publish a signature blob. Anyone may publish; a blob is useless unless it
    ///         verifies against a digest at use time. Returns its index (what goes into `s`).
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

    /// @notice The address a SPHINCS- word (raw key or commitment) controls.
    function pqAddressOf(bytes32 word) public pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(word)))));
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
            _verifyPq(k.pkContract, digest, _sig(s));
            return k.pqAddress;
        }
        if (v == V_HYBRID) {
            KeyEntry memory k = _key(r);
            (bytes memory ecdsaSig, bytes memory pqSig) = abi.decode(_sig(s), (bytes, bytes));
            if (ecdsaSig.length != 65) revert InvalidClassicSignature();
            (bytes32 cr, bytes32 cs, uint8 cv) = _split(ecdsaSig);
            if (ecrecover(digest, cv, cr, cs) != k.classicAddress) revert InvalidClassicSignature();
            _verifyPq(k.pkContract, digest, pqSig);
            return k.classicAddress;
        }
        if (v == V_SPHINCS) {
            _verifyC13(r, digest, _sig(s));
            return pqAddressOf(r);
        }
        if (v == V_SPHINCS_COMMIT) {
            bytes memory blob = _sig(s);
            if (blob.length != 64 + C13_SIG_LEN) revert InvalidPqSignature();
            bytes32 pk;
            bytes32 opener;
            assembly {
                pk := mload(add(blob, 32))
                opener := mload(add(blob, 64))
            }
            if (keccak256(abi.encodePacked(COMMIT_DOMAIN, pk, opener)) != r) revert InvalidCommitment();
            bytes memory sig;
            assembly {
                // View the tail of the blob as a bytes array: reuse the opener's
                // word (already read) as the length slot of the C13 signature.
                sig := add(blob, 64)
                mstore(sig, 3688)
            }
            _verifyC13(pk, digest, sig);
            return pqAddressOf(r);
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

    function _verifyPq(address pkContract, bytes32 digest, bytes memory pqSig) internal view {
        if (pqSig.length != PQ_SIG_LEN) revert InvalidPqSignature();
        bytes4 res = mldsa.verify(abi.encodePacked(pkContract), digest, pqSig);
        if (res != IERC7913SignatureVerifier.verify.selector) revert InvalidPqSignature();
    }

    function _verifyC13(bytes32 pk, bytes32 digest, bytes memory sig) internal view {
        if (sig.length != C13_SIG_LEN) revert InvalidPqSignature();
        // n = 16: the verifier takes each half as a top-aligned bytes32.
        bytes32 pkSeed = bytes32(uint256(pk) & (type(uint256).max << 128));
        bytes32 pkRoot = bytes32(uint256(pk) << 128);
        if (!sphincs.verify(pkSeed, pkRoot, digest, sig)) revert InvalidPqSignature();
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
///         and is untouched by the PQ migration. Only the recovery call changed. It is also
///         the answer to "where does the value live": inside a contract that adopted `recover`.
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
