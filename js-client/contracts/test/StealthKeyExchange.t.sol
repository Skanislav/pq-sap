// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {ERC5564Announcer} from "../src/ERC5564Announcer.sol";
import {IERC5564Announcer, StealthKeyExchange} from "../src/StealthKeyExchange.sol";

/// @dev Replays python/vectors/v0/vectors.json — the same cases the Python, TS and
///      Lean sides assert on — against the on-chain key-exchange layer, plus the
///      fuzzed shape predicate. The Lean model (contracts/lean/) proves the same
///      statements about its functional mirror of this contract; the constants
///      script there keeps the two in step.
contract StealthKeyExchangeTest is Test {
    ERC5564Announcer internal announcer;
    StealthKeyExchange internal kx;
    string internal vectors;

    event Announcement(
        uint256 indexed schemeId,
        address indexed stealthAddress,
        address indexed caller,
        bytes ephemeralPubKey,
        bytes metadata
    );
    event ViewingKeyRegistered(uint256 indexed index, address indexed registrant, StealthKeyExchange.Kem kem);

    function setUp() public {
        announcer = new ERC5564Announcer();
        kx = new StealthKeyExchange(IERC5564Announcer(address(announcer)));
        vectors = vm.readFile("../../python/vectors/v0/vectors.json");
    }

    // ------------------------------------------------------------ helpers
    function _case(uint256 i) internal view returns (address stealth, bytes memory ct, bytes memory tag) {
        string memory k = string.concat(".cases[", vm.toString(i), "].announcement.");
        stealth = vm.parseJsonAddress(vectors, string.concat(k, "stealth_address"));
        ct = vm.parseJsonBytes(vectors, string.concat(k, "ephemeral_pub_key"));
        tag = vm.parseJsonBytes(vectors, string.concat(k, "view_tag"));
    }

    function _caseName(uint256 i) internal view returns (string memory) {
        return vm.parseJsonString(vectors, string.concat(".cases[", vm.toString(i), "].name"));
    }

    function _caseIndex(string memory name) internal view returns (uint256) {
        for (uint256 i = 0; i < 16; i++) {
            if (keccak256(bytes(_caseName(i))) == keccak256(bytes(name))) return i;
        }
        revert("case not found");
    }

    function _metaA() internal view returns (bytes memory) {
        return vm.parseJsonBytes(vectors, ".recipients.A.meta_address");
    }

    /// @dev `ek` is the tail of the meta-address: after version(1) || rho(32) || pack23(t).
    function _ekOf(bytes memory meta, StealthKeyExchange.Kem kem) internal view returns (bytes memory ek) {
        uint256 start = 1 + 32 + kx.packedTBytes(kem);
        ek = new bytes(meta.length - start);
        for (uint256 i = 0; i < ek.length; i++) ek[i] = meta[start + i];
    }

    // ------------------------------------------------------- parameter table
    function test_vector_sizes_match_table() public view {
        assertEq(vm.parseJsonUint(vectors, ".scheme_id"), kx.SCHEME_ID());
        assertEq(vm.parseJsonUint(vectors, ".view_tag_bytes"), kx.VIEW_TAG_BYTES());
        assertEq(vm.parseJsonUint(vectors, ".sizes.meta_address"), kx.metaAddressBytes(StealthKeyExchange.Kem.MLKEM768));
        assertEq(vm.parseJsonUint(vectors, ".sizes.ephemeral_pub_key"), kx.ciphertextBytes(StealthKeyExchange.Kem.MLKEM768));
        assertEq(_metaA().length, 5633);
        assertEq(uint8(_metaA()[0]), kx.metaAddressVersion(StealthKeyExchange.Kem.MLKEM768));
    }

    function test_table_is_the_erc_draft() public view {
        assertEq(kx.metaAddressBytes(StealthKeyExchange.Kem.MLKEM512), 3777);
        assertEq(kx.metaAddressBytes(StealthKeyExchange.Kem.MLKEM768), 5633);
        assertEq(kx.metaAddressBytes(StealthKeyExchange.Kem.MLKEM1024), 7489);
        assertEq(kx.metaAddressBytes(StealthKeyExchange.Kem.XWING), 5665);
        assertEq(kx.ciphertextBytes(StealthKeyExchange.Kem.XWING), 1120);
        assertEq(kx.encapsulationKeyBytes(StealthKeyExchange.Kem.XWING), 1216);
        assertEq(kx.metaAddressVersion(StealthKeyExchange.Kem.XWING), 0x02);
    }

    function test_kemOfCiphertextLength_roundtrips() public view {
        for (uint8 k = 0; k <= uint8(StealthKeyExchange.Kem.XWING); k++) {
            StealthKeyExchange.Kem kem = StealthKeyExchange.Kem(k);
            assertEq(uint8(kx.kemOfCiphertextLength(kx.ciphertextBytes(kem))), k);
            assertEq(uint8(kx.kemOfEncapsulationKeyLength(kx.encapsulationKeyBytes(kem))), k);
        }
    }

    function testFuzz_kemOfCiphertextLength_iff_supported(uint256 length) public {
        bool supported = length == 768 || length == 1088 || length == 1568 || length == 1120;
        if (!supported) {
            vm.expectRevert(abi.encodeWithSelector(StealthKeyExchange.UnsupportedCiphertextLength.selector, length));
        }
        StealthKeyExchange.Kem kem = kx.kemOfCiphertextLength(length);
        if (supported) assertEq(kx.ciphertextBytes(kem), length);
    }

    // ------------------------------------------------------------ announce
    function test_announce_vector_forwards_unchanged() public {
        (address stealth, bytes memory ct, bytes memory tag) = _case(_caseIndex("positive/basic-match"));
        vm.expectEmit(true, true, true, true, address(announcer));
        emit Announcement(2, stealth, address(kx), ct, tag);
        StealthKeyExchange.Kem kem = kx.announce(stealth, ct, tag);
        assertEq(uint8(kem), uint8(StealthKeyExchange.Kem.MLKEM768));
    }

    /// @dev The wrong-view-tag and bit-flipped vectors are well-formed on the wire:
    ///      only a scanner can reject them. They must pass the shape check.
    function test_announce_accepts_wire_valid_negatives() public {
        string[2] memory names = ["negative/wrong-view-tag", "negative/bitflipped-ciphertext"];
        for (uint256 i = 0; i < names.length; i++) {
            (address stealth, bytes memory ct, bytes memory tag) = _case(_caseIndex(names[i]));
            kx.announce(stealth, ct, tag);
        }
    }

    /// @dev The truncated-ciphertext vector (1,087 B) is malformed on the wire: the
    ///      contract rejects it before it reaches the log.
    function test_announce_rejects_truncated_vector() public {
        (address stealth, bytes memory ct, bytes memory tag) = _case(_caseIndex("negative/truncated-ciphertext"));
        assertEq(ct.length, 1087);
        vm.expectRevert(abi.encodeWithSelector(StealthKeyExchange.UnsupportedCiphertextLength.selector, 1087));
        kx.announce(stealth, ct, tag);
    }

    function test_announce_rejects_missing_view_tag() public {
        (address stealth, bytes memory ct,) = _case(0);
        vm.expectRevert(StealthKeyExchange.MissingViewTag.selector);
        kx.announce(stealth, ct, "");
    }

    /// @dev `announce` succeeds exactly when `isValidAnnouncement` holds — the
    ///      statement the Lean model proves as `announce_ok_iff`.
    function testFuzz_announce_iff_isValidAnnouncement(uint16 ctLen, uint8 mdLen, address stealth) public {
        bytes memory ct = new bytes(ctLen);
        bytes memory md = new bytes(mdLen);
        bool valid = kx.isValidAnnouncement(ct, md);
        bool expected = (ctLen == 768 || ctLen == 1088 || ctLen == 1568 || ctLen == 1120) && mdLen >= 1;
        assertEq(valid, expected);
        if (!valid) vm.expectRevert();
        kx.announce(stealth, ct, md);
    }

    function test_viewTagOf() public {
        (,, bytes memory tag) = _case(0);
        assertEq(kx.viewTagOf(tag), tag[0]);
        vm.expectRevert(StealthKeyExchange.MissingViewTag.selector);
        kx.viewTagOf("");
    }

    // ------------------------------------------------------------ registry
    function test_register_vector_ek_and_read_back() public {
        bytes memory ek = _ekOf(_metaA(), StealthKeyExchange.Kem.MLKEM768);
        assertEq(ek.length, 1184);

        vm.expectEmit(true, true, true, true, address(kx));
        emit ViewingKeyRegistered(0, address(this), StealthKeyExchange.Kem.MLKEM768);
        uint256 index = kx.registerViewingKey(ek);
        assertEq(index, 0);
        assertEq(kx.viewingKeyCount(), 1);

        (StealthKeyExchange.Kem kem, bytes memory stored) = kx.viewingKeyOf(0);
        assertEq(uint8(kem), uint8(StealthKeyExchange.Kem.MLKEM768));
        assertEq(stored, ek);
    }

    function test_register_is_append_only() public {
        bytes memory a = new bytes(1184);
        bytes memory b = new bytes(1216);
        a[0] = 0xaa;
        b[0] = 0xbb;
        assertEq(kx.registerViewingKey(a), 0);
        assertEq(kx.registerViewingKey(b), 1);
        (StealthKeyExchange.Kem k0, bytes memory s0) = kx.viewingKeyOf(0);
        (StealthKeyExchange.Kem k1, bytes memory s1) = kx.viewingKeyOf(1);
        assertEq(uint8(k0), uint8(StealthKeyExchange.Kem.MLKEM768));
        assertEq(uint8(k1), uint8(StealthKeyExchange.Kem.XWING));
        assertEq(s0, a);
        assertEq(s1, b);
        vm.expectRevert(abi.encodeWithSelector(StealthKeyExchange.NoSuchViewingKey.selector, 2));
        kx.viewingKeyOf(2);
    }

    function test_register_rejects_unsupported_length() public {
        vm.expectRevert(abi.encodeWithSelector(StealthKeyExchange.UnsupportedEncapsulationKeyLength.selector, 1183));
        kx.registerViewingKey(new bytes(1183));
    }

    // -------------------------------------------------------- meta-address
    function test_kemOfMetaAddress_vector() public view {
        assertEq(uint8(kx.kemOfMetaAddress(_metaA())), uint8(StealthKeyExchange.Kem.MLKEM768));
    }

    function test_kemOfMetaAddress_rejects_bad_version_and_length() public {
        bytes memory meta = _metaA();
        meta[0] = 0x02; // X-Wing version with an ML-KEM-768 length
        vm.expectRevert(abi.encodeWithSelector(StealthKeyExchange.UnsupportedMetaAddress.selector, 5633, 2));
        kx.kemOfMetaAddress(meta);

        bytes memory xw = new bytes(5665);
        xw[0] = 0x02;
        assertEq(uint8(kx.kemOfMetaAddress(xw)), uint8(StealthKeyExchange.Kem.XWING));

        vm.expectRevert(abi.encodeWithSelector(StealthKeyExchange.UnsupportedMetaAddress.selector, 0, 0));
        kx.kemOfMetaAddress("");
    }

    // ------------------------------------------------------------- cost
    /// @dev The wrapper's overhead over a direct singleton call, for the cost report.
    function test_announce_overhead_gas() public {
        (address stealth, bytes memory ct, bytes memory tag) = _case(0);
        uint256 g0 = gasleft();
        announcer.announce(2, stealth, ct, tag);
        uint256 direct = g0 - gasleft();
        uint256 g1 = gasleft();
        kx.announce(stealth, ct, tag);
        uint256 wrapped = g1 - gasleft();
        emit log_named_uint("announce direct (execution gas)", direct);
        emit log_named_uint("announce via StealthKeyExchange", wrapped);
        assertLt(wrapped - direct, 10_000);
    }
}
