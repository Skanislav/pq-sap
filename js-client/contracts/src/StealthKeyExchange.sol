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
///             parameter set, referenced by index). An implementation experiment, not
///             part of the proposal: meta-address distribution and the ERC-6538
///             registry are out of the ERC's scope (D-014 scope update, 2026-09-28;
///             issue #36), and
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

    /// @notice Meta-address layouts. The version byte names the LAYOUT, not the KEM:
    ///         `0x01` is Construction A, `version || rho(32) || pack23(t) || ek`
    ///         (D-003/D-021), `0x02` the commitment form, `version || spend_key(32) || ek`
    ///         (D-024, 1,217 B at ML-KEM-768). Within a layout the KEM is typed by the
    ///         total length; all eight lengths are pairwise distinct (D-028). D-017's
    ///         earlier assignment of `0x02` to the X-Wing hybrid is superseded: X-Wing is
    ///         a KEM row, reachable under either layout by its length.
    enum Form {
        CONSTRUCTION_A,
        COMMIT
    }
    uint8 public constant META_VERSION_CONSTRUCTION_A = 0x01;
    uint8 public constant META_VERSION_COMMIT = 0x02;
    /// @notice The commitment form's 32-byte `spend_key` (D-024).
    uint256 public constant SPEND_KEY_BYTES = 32;

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

    /// @notice Meta-address version byte of a layout.
    function metaAddressVersion(Form form) public pure returns (uint8) {
        return form == Form.COMMIT ? META_VERSION_COMMIT : META_VERSION_CONSTRUCTION_A;
    }

    /// @notice Total meta-address length of a (KEM, layout) pair: Construction A is
    ///         `1 + 32 + pack23(t) + ek` (5,633 B for the default set), the commitment
    ///         form `1 + 32 + ek` (1,217 B).
    function metaAddressBytes(Kem kem, Form form) public pure returns (uint256) {
        if (form == Form.COMMIT) return 1 + SPEND_KEY_BYTES + encapsulationKeyBytes(kem);
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

    /// @notice Shape check of a full meta-address: the version byte selects the
    ///         layout and the total length the parameter set. Reverts with
    ///         `UnsupportedMetaAddress(length, version)` otherwise.
    function kemOfMetaAddress(bytes calldata metaAddress) public pure returns (Kem kem, Form form) {
        uint256 length = metaAddress.length;
        if (length == 0) revert UnsupportedMetaAddress(0, 0);
        uint8 version = uint8(metaAddress[0]);
        if (version == META_VERSION_CONSTRUCTION_A) {
            form = Form.CONSTRUCTION_A;
        } else if (version == META_VERSION_COMMIT) {
            form = Form.COMMIT;
        } else {
            revert UnsupportedMetaAddress(length, version);
        }
        if (length == metaAddressBytes(Kem.MLKEM768, form)) return (Kem.MLKEM768, form);
        if (length == metaAddressBytes(Kem.XWING, form)) return (Kem.XWING, form);
        if (length == metaAddressBytes(Kem.MLKEM512, form)) return (Kem.MLKEM512, form);
        if (length == metaAddressBytes(Kem.MLKEM1024, form)) return (Kem.MLKEM1024, form);
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
