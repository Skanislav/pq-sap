// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ZKNOX_dilithium} from "ethdilithium/ZKNOX_dilithium.sol";
import {PKContract} from "ethdilithium/ZKNOX_PKContract.sol";
import {PubKey} from "ethdilithium/ZKNOX_dilithium_utils.sol";

import {IMlDsa44ExpandedKeys, TrustedMlDsa44KeyRegistry} from "../src/MlDsa44KeyRegistry.sol";
import {TrustlessMlDsa44KeyRegistry} from "../src/TrustlessMlDsa44KeyRegistry.sol";
import {IMlDsa44Erc7913Verifier, MlDsa44CommitSigner7913} from "../src/MlDsa44CommitSigner7913.sol";
import {IProofVerifier, Stealth8141ZkAccount} from "../src/frames/Stealth8141ZkAccount.sol";
import {Stealth8141ZkFactory} from "../src/frames/Stealth8141ZkFactory.sol";
import {MlDsa44CommitFrameVerifier} from "../src/frames/MlDsa44CommitFrameVerifier.sol";
import {AcceptAllVerifier, MockFrameCtx} from "./ZkAccount.t.sol";

/// #27 acceptance, trustless route: the staged registry derives the whole
/// expanded key (aHat via on-chain ExpandA, tr and t1 from the canonical key
/// bytes) with NO registrar, and the resulting binding accepts a genuine
/// signature through the real ZKNOX ML-DSA-44 verifier. The Python fixture is
/// the byte-level oracle (its aHat == ExpandA(pk[0:32]) verified in python
/// before this run). Since the gas redesign, `stage` stores only the
/// keccak256 of each entry's words and `finalize` takes the 16x32 words as
/// calldata — so the tests feed finalize the PYTHON-oracle words: the
/// per-entry hash check is then itself a cross-language assertion (any
/// on-chain ExpandA disagreement reverts EntryWordsMismatch instead of
/// deploying). Run: forge test --root contracts --match-contract
/// TrustlessKeySetup -vv
contract TrustlessKeySetupTest is Test {
    address constant ENTRY_POINT = address(0xaa);

    bytes pk;
    bytes32 spendKey;
    bytes32 opener;
    bytes32 commitment;
    bytes32 digest;
    bytes payload;
    uint256[][][] aHat; // python oracle: ExpandA(pk[0:32]) in compact_256(32)
    bytes fixtureTr;
    uint256[][] fixtureT1;

    TrustlessMlDsa44KeyRegistry trustless;
    TrustedMlDsa44KeyRegistry trusted; // the one-transaction path being paralleled
    MlDsa44CommitSigner7913 signer;
    ZKNOX_dilithium dilithium;
    MlDsa44CommitFrameVerifier adapter;
    MockFrameCtx ctx;
    Stealth8141ZkFactory factory;

    /// the python-oracle words in the shape finalize/pointerFor take:
    /// flat 512 words, entry e = i*4 + j at flatWords[32*e .. 32*e+31]
    uint256[512] oracleWords;

    function setUp() public {
        string memory json = vm.readFile("../../python/scripts/mldsa44_commit_7913_demo.json");
        pk = vm.parseJsonBytes(json, ".ml_dsa_pk");
        spendKey = vm.parseJsonBytes32(json, ".spend_key");
        opener = vm.parseJsonBytes32(json, ".opener");
        commitment = vm.parseJsonBytes32(json, ".commitment");
        digest = vm.parseJsonBytes32(json, ".digest");
        payload = vm.parseJsonBytes(json, ".payload");
        (bytes memory aHatEnc, bytes memory trBytes, bytes memory t1Enc) =
            abi.decode(vm.parseJsonBytes(json, ".public_key_data"), (bytes, bytes, bytes));
        aHat = abi.decode(aHatEnc, (uint256[][][]));
        fixtureTr = trBytes;
        fixtureT1 = abi.decode(t1Enc, (uint256[][]));
        for (uint256 i = 0; i < 4; i++) {
            for (uint256 j = 0; j < 4; j++) {
                for (uint256 w = 0; w < 32; w++) {
                    oracleWords[32 * (i * 4 + j) + w] = aHat[i][j][w];
                }
            }
        }

        dilithium = new ZKNOX_dilithium();
        trustless = new TrustlessMlDsa44KeyRegistry();
        trusted = new TrustedMlDsa44KeyRegistry(address(this));
        signer = new MlDsa44CommitSigner7913(
            IMlDsa44Erc7913Verifier(address(dilithium)), IMlDsa44ExpandedKeys(address(trustless)));
        adapter = new MlDsa44CommitFrameVerifier(signer);
        ctx = new MockFrameCtx();
        factory = new Stealth8141ZkFactory(IProofVerifier(address(adapter)), ctx);
    }

    /// drive the full staged expansion the way random unprivileged addresses
    /// would: begin by one, each entry staged by a DIFFERENT caller (anyone
    /// may stage), finalize by yet another — feeding finalize the
    /// python-oracle words, so the hash check doubles as the cross-language
    /// assertion that on-chain ExpandA == Python ExpandA
    function _stageAll() internal returns (address pointer) {
        vm.startPrank(address(0xbeef));
        trustless.begin(pk);
        vm.stopPrank();
        for (uint256 e = 0; e < 16; e++) {
            vm.prank(address(uint160(0x1000 + e)));
            uint256 gs = gasleft();
            trustless.stage(pk, e);
            if (e == 0) emit log_named_uint("stage(entry 0) gas", gs - gasleft());
        }
        // memory-copy first (BEFORE the gas window opens): passing a *storage*
        // array would charge the 512 cold SLOADs of ABI marshalling to
        // finalize's measured gas — a real tx sends the words as calldata the
        // caller already has in memory
        uint256[512] memory words = oracleWords;
        uint256 g0 = gasleft();
        vm.prank(address(0xbeef));
        pointer = trustless.finalize(pk, words);
        emit log_named_uint("finalize (hash-check + tr + t1 + PKContract)", g0 - gasleft());
    }

    function testStagedExpansionMatchesPythonOracle() public {
        // before begin: staging is refused
        vm.expectRevert(
            abi.encodeWithSelector(TrustlessMlDsa44KeyRegistry.NotStarted.selector, keccak256(pk)));
        trustless.stage(pk, 0);

        address pointer = _stageAll();
        assertEq(trustless.entriesDone(keccak256(pk)), (1 << 16) - 1, "all 16 entries done");
        assertEq(trustless.expandedKey(keccak256(pk)), pointer);

        // byte-exact vs the python fixture: aHat, tr, t1 — all 16x32 words
        PubKey memory stored = PKContract(pointer).getPublicKey();
        assertEq(stored.tr, fixtureTr, "tr == SHAKE256(pk, 64) from python");
        for (uint256 i = 0; i < 4; i++) {
            for (uint256 w = 0; w < 32; w++) {
                assertEq(stored.t1[i][w], fixtureT1[i][w], "t1 word");
                for (uint256 j = 0; j < 4; j++) {
                    assertEq(stored.aHat[i][j][w], aHat[i][j][w], "aHat word != ExpandA oracle");
                }
            }
        }

        // CREATE2 determinism, asserted on chain: the pointer equals the
        // pre-finalize prediction (view over the staged words)
        vm.prank(address(0xbeef));
        trustless.begin(pk); // idempotent repeat begin: no-op
        address predicted = trustless.pointerFor(pk, oracleWords);
        assertEq(predicted, pointer, "pointerFor predicts the CREATE2 address");

        // staging is idempotent: a repeat stage of a done entry is a no-op
        // (a front-runner or racing helper cannot invalidate a 16-stage bundle)
        uint256 doneBefore = trustless.entriesDone(keccak256(pk));
        trustless.stage(pk, 0);
        trustless.stage(pk, 7);
        assertEq(trustless.entriesDone(keccak256(pk)), doneBefore, "repeat stages are no-ops");

        // finalize is once-only
        vm.expectRevert(
            abi.encodeWithSelector(TrustlessMlDsa44KeyRegistry.AlreadyFinalized.selector, keccak256(pk)));
        trustless.finalize(pk, oracleWords);

        // a different pk (any rho flip) has no setup at all — it cannot
        // piggyback on this one
        bytes memory badPk = pk;
        badPk[0] ^= 0x01;
        vm.expectRevert(
            abi.encodeWithSelector(TrustlessMlDsa44KeyRegistry.NotStarted.selector, keccak256(badPk)));
        trustless.stage(badPk, 0);
        vm.expectRevert(
            abi.encodeWithSelector(TrustlessMlDsa44KeyRegistry.NotStarted.selector, keccak256(badPk)));
        trustless.finalize(badPk, oracleWords);
    }

    /// the gas redesign's own negative: tampered calldata words cannot pass
    /// the per-entry hash check — finalize reverts, deploys nothing, and the
    /// key remains finalizable with the honest words (the failed attempt is
    /// not state-changing griefing, it is a clean revert)
    function testTamperedEntryWordsRevert() public {
        vm.prank(address(0xbeef));
        trustless.begin(pk);
        for (uint256 e = 0; e < 16; e++) {
            vm.prank(address(uint160(0x3000 + e)));
            trustless.stage(pk, e);
        }

        // one flipped coefficient word in entry 5
        uint256[512] memory tampered = oracleWords;
        tampered[32 * 5 + 7] ^= 0x01;
        vm.expectRevert(
            abi.encodeWithSelector(
                TrustlessMlDsa44KeyRegistry.EntryWordsMismatch.selector,
                5,
                trustless.entryHashes(keccak256(pk), 5),
                keccak256(abi.encodePacked(_entryWords(tampered, 5)))
            )
        );
        trustless.finalize(pk, tampered);

        // pointerFor with the same tampered words reverts too
        vm.expectRevert(
            abi.encodeWithSelector(
                TrustlessMlDsa44KeyRegistry.EntryWordsMismatch.selector,
                5,
                trustless.entryHashes(keccak256(pk), 5),
                keccak256(abi.encodePacked(_entryWords(tampered, 5)))
            )
        );
        trustless.pointerFor(pk, tampered);

        // nothing was deployed and the setup is still open: the honest words
        // finalize cleanly after the failed attempt
        assertEq(trustless.expandedKey(keccak256(pk)), address(0), "tampered attempt deployed nothing");
        address pointer = trustless.finalize(pk, oracleWords);
        assertTrue(pointer != address(0), "honest words still finalize");
        assertEq(trustless.expandedKey(keccak256(pk)), pointer);
    }

    /// the 32 words of entry e out of the flat 512-word calldata shape
    function _entryWords(uint256[512] memory flat, uint256 e)
        internal
        pure
        returns (uint256[32] memory)
    {
        uint256[32] memory out;
        for (uint256 w = 0; w < 32; w++) {
            out[w] = flat[32 * e + w];
        }
        return out;
    }

    function testGuards() public {
        // begin with a wrong-length key is refused
        bytes memory shortPk = new bytes(33);
        for (uint256 i; i < 33; ++i) {
            shortPk[i] = pk[i];
        }
        vm.expectRevert(
            abi.encodeWithSelector(TrustlessMlDsa44KeyRegistry.BadKeyLength.selector, 33));
        trustless.begin(shortPk);

        // pre-begin finalize is refused
        vm.expectRevert(
            abi.encodeWithSelector(TrustlessMlDsa44KeyRegistry.NotStarted.selector, keccak256(pk)));
        trustless.finalize(pk, oracleWords);

        // staging out-of-range entries is refused
        vm.prank(address(0xbeef));
        trustless.begin(pk);
        vm.expectRevert(
            abi.encodeWithSelector(TrustlessMlDsa44KeyRegistry.BadEntryIndex.selector, 16));
        trustless.stage(pk, 16);

        // finalize before all 16 entries is refused with the progress bitmap
        for (uint256 e = 0; e < 15; e++) {
            vm.prank(address(uint160(0x2000 + e)));
            trustless.stage(pk, e);
        }
        vm.expectRevert(
            abi.encodeWithSelector(TrustlessMlDsa44KeyRegistry.NotFinished.selector, keccak256(pk), (1 << 15) - 1));
        trustless.finalize(pk, oracleWords);

        // staging the last entry unblocks finalize
        vm.prank(address(0x2fff));
        trustless.stage(pk, 15);
        address pointer = trustless.finalize(pk, oracleWords);
        assertEq(trustless.expandedKey(keccak256(pk)), pointer);

        // pointerFor with a wrong-length key is refused: the underlying
        // unpacker zero-fills out-of-range reads instead of reverting, so
        // without this guard a truncated key would return a confident-looking
        // address computed from a partly zero t1
        vm.expectRevert(
            abi.encodeWithSelector(TrustlessMlDsa44KeyRegistry.BadKeyLength.selector, 33));
        trustless.pointerFor(shortPk, oracleWords);
        // 1311 bytes: same guard at the other boundary
        bytes memory truncPk = new bytes(1311);
        for (uint256 i; i < 1311; ++i) {
            truncPk[i] = pk[i];
        }
        vm.expectRevert(
            abi.encodeWithSelector(TrustlessMlDsa44KeyRegistry.BadKeyLength.selector, 1311));
        trustless.pointerFor(truncPk, oracleWords);
    }

    /// the two setup routes derive byte-identical expanded keys from the same
    /// canonical pk: the trusted one-tx path (registrar-attested aHat) and
    /// the staged trustless path (on-chain ExpandA) agree on every word —
    /// so a deployment can move between them without re-deriving anything.
    function testTrustedAndTrustlessAgree() public {
        _stageAll();
        address trustlessPointer = trustless.expandedKey(keccak256(pk));

        // registrar route: the same python-oracle aHat, attested
        vm.prank(address(this));
        address trustedPointer = trusted.register(pk, aHat);

        PubKey memory a = PKContract(trustlessPointer).getPublicKey();
        PubKey memory b = PKContract(trustedPointer).getPublicKey();
        assertEq(a.tr, b.tr, "tr agrees across routes");
        for (uint256 i = 0; i < 4; i++) {
            for (uint256 w = 0; w < 32; w++) {
                assertEq(a.t1[i][w], b.t1[i][w], "t1 agrees across routes");
                for (uint256 j = 0; j < 4; j++) {
                    assertEq(a.aHat[i][j][w], b.aHat[i][j][w], "aHat agrees across routes");
                }
            }
        }
        // the PKContracts are distinct (different salt policy), the bindings equal
        assertFalse(trustlessPointer == trustedPointer, "distinct CREATE2 salts");
    }

    /// the acceptance criterion of #27: the trustless binding accepts the
    /// recipient's genuine signature through the real ZKNOX verifier, and the
    /// frame account spends — no registrar anywhere
    function testTrustlessBindingSpends() public {
        _stageAll();
        Stealth8141ZkAccount acct = Stealth8141ZkAccount(payable(factory.createAccount(commitment)));
        vm.deal(address(acct), 1 ether);
        ctx.set(digest, 1, payload);
        address dest = address(0xdEaD);
        vm.prank(ENTRY_POINT);
        acct.executeFrame(1, dest, 0.1 ether, "");
        assertEq(dest.balance, 0.1 ether, "trustless setup: recipient can spend");
    }
}