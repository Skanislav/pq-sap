// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SSTORE2} from "solady/utils/SSTORE2.sol";

/// @dev The ERC-5564 announcer singleton (mainnet/Sepolia
///      0x55649E01B5Df198D18D95b5cc5051630cfD45564; `ERC5564Announcer.sol` on anvil).
interface IERC5564Announcer {
    function announce(
        uint256 schemeId,
        address stealthAddress,
        bytes memory ephemeralPubKey,
        bytes memory metadata
    ) external;
}

/// @title StealthKeyExchange
/// @notice The on-chain half of the scheme's key exchange, separated from the spend
///         side (accounts, verifiers, factories). Everything the chain sees of the
///         ML-KEM handshake is (a) the recipient's encapsulation key and (b) the
///         sender's ciphertext riding as the ERC-5564 `ephemeralPubKey`; this contract
///         owns both:
///
///           * a write-once registry of encapsulation keys (SSTORE2, typed by KEM
///             parameter set, referenced by index — a 5.6 kB meta-address can then be
///             shared as `rho || pack23(t) || index`), and
///           * `announce`, which checks the announcement's SHAPE — a ciphertext of a
///             supported parameter set's length and a metadata field that carries the
///             view tag at `metadata[0]` — and forwards it unchanged, under scheme ID
///             `2`, to the ERC-5564 announcer. Scanners that read the singleton's log
///             with `caller == this` therefore only ever see well-formed announcements.
///
///         What it deliberately does NOT do is run ML-KEM.Encaps: the EVM computes in
///         public, so an on-chain encapsulation would publish the shared secret, and
///         with it the view tag and the stealth key derivation — the one thing the
///         scheme exists to hide. Encapsulation (and decapsulation) stay off-chain;
///         the chain carries and validates the ciphertext, nothing more. `announce`
///         takes no recipient-identifying input on purpose: an announcement that
///         referenced a registry index would link the payment to the recipient.
///
///         Every pure function here is mirrored one-to-one by the Lean model in
///         `lean/StealthKeyExchange/` (the parameter table, `isValidAnnouncement`,
///         the registry's append-only state machine); the Foundry tests replay the
///         same conformance vectors the model asserts on.
contract StealthKeyExchange {
    // ------------------------------------------------------------------ errors
    error UnsupportedCiphertextLength(uint256 length);
    error UnsupportedEncapsulationKeyLength(uint256 length);
    error UnsupportedMetaAddress(uint256 length, uint8 version);
    error MissingViewTag();
    error NoSuchViewingKey(uint256 index);

    // ------------------------------------------------------------------ events
    /// @notice A viewing (encapsulation) key was stored at `index`.
    event ViewingKeyRegistered(uint256 indexed index, address indexed registrant, Kem kem);

    // --------------------------------------------------------------- constants
    /// @notice ERC-5564 scheme ID of the post-quantum scheme (docs/erc-draft.md).
    uint256 public constant SCHEME_ID = 2;
    /// @notice `metadata[0]` is the view tag (ERC-5564 convention, VIEW_TAG_BYTES = 1).
    uint256 public constant VIEW_TAG_BYTES = 1;

    /// @notice Discovery-KEM parameter sets: the three FIPS 203 sets (each paired with
    ///         the ML-DSA set of the same NIST level: 512↔44, 768↔65, 1024↔87) and the
    ///         optional PQ/T hybrid MLKEM768-X25519 (X-Wing, D-017; spending stays
    ///         ML-DSA-65). ML-KEM-768 is the default and the only MUST.
    enum Kem {
        MLKEM512,
        MLKEM768,
        MLKEM1024,
        XWING
    }

    // FIPS 203 Table 3 / X-Wing draft §5: sizes in bytes.
    uint256 public constant MLKEM512_EK_BYTES = 800;
    uint256 public constant MLKEM512_CT_BYTES = 768;
    uint256 public constant MLKEM768_EK_BYTES = 1184;
    uint256 public constant MLKEM768_CT_BYTES = 1088;
    uint256 public constant MLKEM1024_EK_BYTES = 1568;
    uint256 public constant MLKEM1024_CT_BYTES = 1568;
    uint256 public constant XWING_EK_BYTES = 1216;
    uint256 public constant XWING_CT_BYTES = 1120;

    /// @notice Meta-address version byte: `0x01` for the FIPS 203 sets, `0x02` for X-Wing.
    uint8 public constant META_VERSION_MLKEM = 0x01;
    uint8 public constant META_VERSION_XWING = 0x02;

    // Full-precision `t` of the paired ML-DSA set: k * 256 * 23 / 8 bytes.
    uint256 public constant PACKED_T_BYTES_MLDSA44 = 2944;
    uint256 public constant PACKED_T_BYTES_MLDSA65 = 4416;
    uint256 public constant PACKED_T_BYTES_MLDSA87 = 5888;

    /// @notice The ERC-5564 announcer every announcement is forwarded to.
    IERC5564Announcer public immutable ANNOUNCER;

    // ----------------------------------------------------------------- storage
    struct ViewingKey {
        address pointer; // SSTORE2 pointer to the encapsulation key bytes
        Kem kem;
    }

    ViewingKey[] private _keys;

    constructor(IERC5564Announcer announcer) {
        ANNOUNCER = announcer;
    }

    // ------------------------------------------------------- parameter table
    /// @notice Ciphertext (`ephemeralPubKey`) length of a parameter set.
    function ciphertextBytes(Kem kem) public pure returns (uint256) {
        if (kem == Kem.MLKEM512) return MLKEM512_CT_BYTES;
        if (kem == Kem.MLKEM768) return MLKEM768_CT_BYTES;
        if (kem == Kem.MLKEM1024) return MLKEM1024_CT_BYTES;
        return XWING_CT_BYTES;
    }

    /// @notice Encapsulation (viewing) key length of a parameter set.
    function encapsulationKeyBytes(Kem kem) public pure returns (uint256) {
        if (kem == Kem.MLKEM512) return MLKEM512_EK_BYTES;
        if (kem == Kem.MLKEM768) return MLKEM768_EK_BYTES;
        if (kem == Kem.MLKEM1024) return MLKEM1024_EK_BYTES;
        return XWING_EK_BYTES;
    }

    /// @notice Packed full-precision `t` of the ML-DSA set paired with `kem`.
    function packedTBytes(Kem kem) public pure returns (uint256) {
        if (kem == Kem.MLKEM512) return PACKED_T_BYTES_MLDSA44;
        if (kem == Kem.MLKEM1024) return PACKED_T_BYTES_MLDSA87;
        return PACKED_T_BYTES_MLDSA65; // MLKEM768 and XWING both pair with ML-DSA-65
    }

    /// @notice Meta-address version byte of a parameter set.
    function metaAddressVersion(Kem kem) public pure returns (uint8) {
        return kem == Kem.XWING ? META_VERSION_XWING : META_VERSION_MLKEM;
    }

    /// @notice `version(1) || rho(32) || pack23(t) || ek` — 5,633 B for the default set.
    function metaAddressBytes(Kem kem) public pure returns (uint256) {
        return 1 + 32 + packedTBytes(kem) + encapsulationKeyBytes(kem);
    }

    /// @notice The parameter set whose ciphertext has `length` bytes. The four
    ///         lengths are pairwise distinct, so the ciphertext identifies its set.
    function kemOfCiphertextLength(uint256 length) public pure returns (Kem) {
        if (length == MLKEM768_CT_BYTES) return Kem.MLKEM768;
        if (length == XWING_CT_BYTES) return Kem.XWING;
        if (length == MLKEM512_CT_BYTES) return Kem.MLKEM512;
        if (length == MLKEM1024_CT_BYTES) return Kem.MLKEM1024;
        revert UnsupportedCiphertextLength(length);
    }

    /// @notice The parameter set whose encapsulation key has `length` bytes.
    function kemOfEncapsulationKeyLength(uint256 length) public pure returns (Kem) {
        if (length == MLKEM768_EK_BYTES) return Kem.MLKEM768;
        if (length == XWING_EK_BYTES) return Kem.XWING;
        if (length == MLKEM512_EK_BYTES) return Kem.MLKEM512;
        if (length == MLKEM1024_EK_BYTES) return Kem.MLKEM1024;
        revert UnsupportedEncapsulationKeyLength(length);
    }

    /// @notice Shape check of a full meta-address: version byte and total length
    ///         determine the parameter set (the ML-DSA half by the version's
    ///         pairing, the KEM half by what is left for `ek`).
    function kemOfMetaAddress(bytes calldata metaAddress) public pure returns (Kem) {
        uint256 length = metaAddress.length;
        if (length == 0) revert UnsupportedMetaAddress(0, 0);
        uint8 version = uint8(metaAddress[0]);
        if (version == META_VERSION_MLKEM) {
            if (length == metaAddressBytes(Kem.MLKEM768)) return Kem.MLKEM768;
            if (length == metaAddressBytes(Kem.MLKEM512)) return Kem.MLKEM512;
            if (length == metaAddressBytes(Kem.MLKEM1024)) return Kem.MLKEM1024;
        } else if (version == META_VERSION_XWING) {
            if (length == metaAddressBytes(Kem.XWING)) return Kem.XWING;
        }
        revert UnsupportedMetaAddress(length, version);
    }

    /// @notice Exactly the predicate under which `announce` succeeds: a ciphertext
    ///         of a supported length and a metadata field long enough to hold the
    ///         view tag. Wallets can pre-check with this; the Lean model proves the
    ///         equivalence (`announce_ok_iff`).
    function isValidAnnouncement(bytes calldata ciphertext, bytes calldata metadata)
        public
        pure
        returns (bool)
    {
        uint256 length = ciphertext.length;
        bool supported = length == MLKEM768_CT_BYTES || length == XWING_CT_BYTES
            || length == MLKEM512_CT_BYTES || length == MLKEM1024_CT_BYTES;
        return supported && metadata.length >= VIEW_TAG_BYTES;
    }

    /// @notice The view tag an announcement carries (`metadata[0]`).
    function viewTagOf(bytes calldata metadata) public pure returns (bytes1) {
        if (metadata.length < VIEW_TAG_BYTES) revert MissingViewTag();
        return metadata[0];
    }

    // ----------------------------------------------------------- announcing
    /// @notice Validate the shape of a scheme-2 announcement and forward it to the
    ///         ERC-5564 announcer. `ciphertext` is the KEM ciphertext (the
    ///         `ephemeralPubKey`), `metadata[0]` the view tag; both are forwarded
    ///         byte for byte. Reverts with `UnsupportedCiphertextLength` /
    ///         `MissingViewTag` otherwise — the truncated-ciphertext conformance
    ///         vector, which a scanner must skip silently, never reaches the log.
    function announce(address stealthAddress, bytes calldata ciphertext, bytes calldata metadata)
        external
        returns (Kem kem)
    {
        kem = kemOfCiphertextLength(ciphertext.length);
        if (metadata.length < VIEW_TAG_BYTES) revert MissingViewTag();
        ANNOUNCER.announce(SCHEME_ID, stealthAddress, ciphertext, metadata);
    }

    // ------------------------------------------------------------- registry
    /// @notice Store an encapsulation key; returns its permanent index. The key's
    ///         parameter set is inferred from its length and recorded alongside.
    ///         Append-only: an index, once assigned, never changes what it resolves to.
    function registerViewingKey(bytes calldata encapsulationKey) external returns (uint256 index) {
        Kem kem = kemOfEncapsulationKeyLength(encapsulationKey.length);
        address pointer = SSTORE2.write(encapsulationKey);
        _keys.push(ViewingKey({pointer: pointer, kem: kem}));
        index = _keys.length - 1;
        emit ViewingKeyRegistered(index, msg.sender, kem);
    }

    /// @notice Resolve an index to `(parameter set, encapsulation key)`.
    function viewingKeyOf(uint256 index) external view returns (Kem kem, bytes memory encapsulationKey) {
        if (index >= _keys.length) revert NoSuchViewingKey(index);
        ViewingKey storage k = _keys[index];
        return (k.kem, SSTORE2.read(k.pointer));
    }

    /// @notice Number of registered keys (= the next index).
    function viewingKeyCount() external view returns (uint256) {
        return _keys.length;
    }
}
