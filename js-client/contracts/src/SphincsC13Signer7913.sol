// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC7913SignatureVerifier} from "@openzeppelin/contracts/interfaces/IERC7913.sol";
/// @dev Interface of the vendored `SphincsC13Asm` (vendor/sphincs-minus/). Kept as an
///      interface rather than an import so the wrappers compile under the default
///      profile while the verifier keeps upstream's via-IR / 200-runs settings (see
///      foundry.toml `compilation_restrictions`), and so a wrapper can point at an
///      already-deployed verifier instance.
interface ISphincsC13Verifier {
    function verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata sig)
        external pure returns (bool valid);
}

/// @title SphincsC13SignerBase
/// @notice Shared core for the two ERC-7913 signers over SPHINCS- C13, the
///         hash-based (WOTS+C / FORS+C, keccak256, FIPS 205 uncompressed ADRS)
///         verifier whose Solidity is machine-checked by Verity Labs and vendored
///         verbatim under `vendor/sphincs-minus/` (see VENDORED_REV.txt there).
///
///         C13 has n = 16, so a public key is two 16-byte halves. The verifier
///         takes each half as a bytes32 with the low 128 bits zero ("top-aligned")
///         and reverts otherwise; this base builds those words itself, so the
///         canonicality revert is unreachable, and it checks lengths up front so
///         the length revert is too. Every remaining failure (forced-zero FORS
///         index, WOTS+C digit sum, root mismatch) is a `false` from the verifier
///         and surfaces here as 0xffffffff. The wrappers therefore never revert
///         on well-typed input, which keeps SignatureChecker's staticcall path
///         uniform for callers.
abstract contract SphincsC13SignerBase is IERC7913SignatureVerifier {
    /// @notice The shared stateless C13 verifier (deployed once per chain).
    ISphincsC13Verifier public immutable VERIFIER;

    /// @notice `pkSeed[0:16] || pkRoot[0:16]`.
    uint256 public constant PUBLIC_KEY_LENGTH = 32;
    /// @notice C13 signature: R(16) || FORS+C (7 secrets + 6 auth paths) || 2 × (WOTS+C + counter + auth).
    uint256 public constant C13_SIGNATURE_LENGTH = 3688;

    bytes4 internal constant FAIL = 0xffffffff;

    constructor(ISphincsC13Verifier verifier) {
        VERIFIER = verifier;
    }

    /// @dev `pk` must be exactly 32 bytes; `sig` exactly 3,688 bytes.
    function _verifyC13(bytes calldata pk, bytes32 hash, bytes calldata sig) internal view returns (bool) {
        // bytes16 -> bytes32 pads on the right: exactly the top-aligned word layout
        // the vendored verifier wants for its n = 16 seed and root.
        bytes32 pkSeed = bytes32(bytes16(pk[0:16]));
        bytes32 pkRoot = bytes32(bytes16(pk[16:32]));
        return VERIFIER.verify(pkSeed, pkRoot, hash, sig);
    }
}

/// @title SphincsC13Signer7913
/// @notice ERC-7913 signer with the raw C13 public key as `key`.
///
///           key       = pkSeed[0:16] || pkRoot[0:16]              (32 bytes)
///           signature = C13 signature                              (3,688 bytes)
///           hash      = the bytes32 the account is asked to validate
///
///         A full signer string is `verifier || key` = 52 bytes, fully stateless
///         (no key contract, nothing written at key setup). This is the form for a
///         key that is public anyway: an ERC-6538 registry-authentication key
///         (D-014's update ratchet), an account co-signer or recovery key, or the
///         key behind a ZK-bound stealth address. A stealth address whose signer
///         bytes carry this key directly is NOT sender-derivable (the sender cannot
///         compute a hash-based public key from the meta-address; D-016) — use
///         `SphincsC13CommitSigner7913` for that.
contract SphincsC13Signer7913 is SphincsC13SignerBase {
    constructor(ISphincsC13Verifier verifier) SphincsC13SignerBase(verifier) {}

    /// @inheritdoc IERC7913SignatureVerifier
    function verify(bytes calldata key, bytes32 hash, bytes calldata signature)
        external view returns (bytes4)
    {
        if (key.length != PUBLIC_KEY_LENGTH || signature.length != C13_SIGNATURE_LENGTH) return FAIL;
        return _verifyC13(key, hash, signature) ? IERC7913SignatureVerifier.verify.selector : FAIL;
    }
}

/// @title SphincsC13CommitSigner7913
/// @notice ERC-7913 signer whose `key` is a hiding commitment to a C13 public key,
///         opened inside the signature. This is the form that gives a hash-based
///         spend key a sender-derivable stealth address:
///
///           key       = keccak256(COMMIT_DOMAIN || pk || opener)   (32 bytes)
///           signature = pk(32) || opener(32) || C13 signature      (3,752 bytes)
///
///         The sender knows `pk` (the recipient's C13 key, carried in the
///         meta-address of a hash-based-spend variant) and derives `opener` from the
///         ML-KEM shared secret (`SHA-256("pq-stealth/sphincs-c13/open/v0" || ss)`),
///         so it can form the commitment, hence the account initcode, hence the
///         CREATE2 stealth address — without the signing key. The recipient
///         recovers the same `ss` on detection and re-derives `opener`.
///
///         What it does and does not hide: `ss` is 256 bits of KEM output, so the
///         commitment reveals nothing about `pk` before the first spend — unspent
///         stealth addresses stay unlinkable exactly as in the ML-DSA scheme. A
///         spend opens the commitment on-chain: it reveals `pk`, which is the
///         recipient's registered key, so every SPENT address of one recipient is
///         linkable to that recipient from that point. This is the row-B trade-off
///         of docs/research/hash-based-key-exchange.md made concrete: hash-based
///         keys have no blinding, so a spend from a hash-based stealth address is
///         an identifying event. Only the D-012 ZK ownership proof (a hash-preimage
///         STARK) removes that; this contract is the honest non-ZK point on the curve.
///
///         `opener` is a domain-separated derivative of `ss`, never `ss` itself, so
///         opening the commitment does not expose the view tag or any other
///         material derived from the shared secret.
contract SphincsC13CommitSigner7913 is SphincsC13SignerBase {
    /// @notice Domain tag for the commitment (32 ASCII bytes).
    bytes32 public constant COMMIT_DOMAIN = "pq-stealth/sphincs-c13/commit/v0";
    uint256 public constant OPENER_LENGTH = 32;

    constructor(ISphincsC13Verifier verifier) SphincsC13SignerBase(verifier) {}

    /// @notice The `key` an account holds for public key `pk` under `opener`.
    function commitment(bytes calldata pk, bytes32 opener) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(COMMIT_DOMAIN, pk, opener));
    }

    /// @inheritdoc IERC7913SignatureVerifier
    function verify(bytes calldata key, bytes32 hash, bytes calldata signature)
        external view returns (bytes4)
    {
        if (key.length != 32) return FAIL;
        if (signature.length != PUBLIC_KEY_LENGTH + OPENER_LENGTH + C13_SIGNATURE_LENGTH) return FAIL;
        bytes calldata pk = signature[0:PUBLIC_KEY_LENGTH];
        bytes32 opener = bytes32(signature[PUBLIC_KEY_LENGTH:PUBLIC_KEY_LENGTH + OPENER_LENGTH]);
        if (commitment(pk, opener) != bytes32(key)) return FAIL;
        bytes calldata sig = signature[PUBLIC_KEY_LENGTH + OPENER_LENGTH:];
        return _verifyC13(pk, hash, sig) ? IERC7913SignatureVerifier.verify.selector : FAIL;
    }
}
