// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {IERC7913SignatureVerifier} from "@openzeppelin/contracts/interfaces/IERC7913.sol";
import {ZKNOX_dilithium} from "ethdilithium/ZKNOX_dilithium.sol";
import {PKContract} from "ethdilithium/ZKNOX_PKContract.sol";
import {PubKey} from "ethdilithium/ZKNOX_dilithium_utils.sol";

import {IMlDsa44Erc7913Verifier, MlDsa44CommitSigner7913} from "../src/MlDsa44CommitSigner7913.sol";
import {IMlDsa44ExpandedKeys, TrustedMlDsa44KeyRegistry} from "../src/MlDsa44KeyRegistry.sol";
import {Stealth7913Account} from "../src/Stealth7913Account.sol";
import {IProofVerifier, Stealth8141ZkAccount} from "../src/frames/Stealth8141ZkAccount.sol";
import {Stealth8141ZkFactory} from "../src/frames/Stealth8141ZkFactory.sol";
import {MlDsa44CommitFrameVerifier} from "../src/frames/MlDsa44CommitFrameVerifier.sol";
import {AcceptAllVerifier, MockFrameCtx} from "./ZkAccount.t.sol";

/// `ml-dsa-44-commit/v0` end to end in forge on the fixture from
/// python/scripts/mldsa44_commit_7913_demo.py: trusted key setup, committed-key
/// ERC-7913 verify through the real ZKNOX ML-DSA-44 verifier, the frame account
/// spend through the adapter, the ERC-1271 account surface, and the negatives.
/// Run: forge test --root contracts --match-contract MlDsa44CommitAccount -vv
contract MlDsa44CommitAccountTest is Test {
    address constant ENTRY_POINT = address(0xaa);
    bytes4 constant MAGIC_7913 = 0x024ad318;
    bytes4 constant MAGIC_1271 = 0x1626ba7e;
    bytes4 constant FAIL = 0xffffffff;

    bytes pk;
    bytes32 spendKey;
    bytes32 opener;
    bytes32 commitment;
    bytes32 digest;
    bytes payload;
    bytes32 otherDigest;
    bytes payloadOtherDigest;
    bytes senderPayload;
    uint256[][][] aHat;
    bytes fixtureTr;
    uint256[][] fixtureT1;

    ZKNOX_dilithium dilithium;
    TrustedMlDsa44KeyRegistry registry;
    MlDsa44CommitSigner7913 signer;
    MlDsa44CommitFrameVerifier adapter;
    MockFrameCtx ctx;
    Stealth8141ZkFactory factory;
    Stealth8141ZkAccount acct;

    function setUp() public {
        string memory json = vm.readFile("../../python/scripts/mldsa44_commit_7913_demo.json");
        pk = vm.parseJsonBytes(json, ".ml_dsa_pk");
        spendKey = vm.parseJsonBytes32(json, ".spend_key");
        opener = vm.parseJsonBytes32(json, ".opener");
        commitment = vm.parseJsonBytes32(json, ".commitment");
        digest = vm.parseJsonBytes32(json, ".digest");
        payload = vm.parseJsonBytes(json, ".payload");
        otherDigest = vm.parseJsonBytes32(json, ".other_digest");
        payloadOtherDigest = vm.parseJsonBytes(json, ".payload_other_digest");
        senderPayload = vm.parseJsonBytes(json, ".sender_derived_payload");
        (bytes memory aHatEnc, bytes memory trBytes, bytes memory t1Enc) =
            abi.decode(vm.parseJsonBytes(json, ".public_key_data"), (bytes, bytes, bytes));
        aHat = abi.decode(aHatEnc, (uint256[][][]));
        fixtureTr = trBytes;
        fixtureT1 = abi.decode(t1Enc, (uint256[][]));

        dilithium = new ZKNOX_dilithium();
        registry = new TrustedMlDsa44KeyRegistry(address(this));
        signer = new MlDsa44CommitSigner7913(
            IMlDsa44Erc7913Verifier(address(dilithium)), IMlDsa44ExpandedKeys(address(registry)));
        adapter = new MlDsa44CommitFrameVerifier(IERC7913SignatureVerifier(address(signer)));
        ctx = new MockFrameCtx();
        factory = new Stealth8141ZkFactory(IProofVerifier(address(adapter)), ctx);
    }

    function _register() internal returns (address pointer) {
        uint256 g0 = gasleft();
        pointer = registry.register(pk, aHat);
        emit log_named_uint("key setup: registry.register (SHAKE256 tr + t1 unpack + PKContract)", g0 - gasleft());
    }

    // ------------------------------------------------------------ key setup
    function testKeySetupDerivesTrAndT1OnChain() public {
        address pointer = _register();
        assertEq(registry.expandedKey(keccak256(pk)), pointer);
        PubKey memory stored = PKContract(pointer).getPublicKey();
        assertEq(stored.tr, fixtureTr, "tr must equal SHAKE256(pk, 64) from the Python fixture");
        assertEq(stored.t1.length, 4);
        for (uint256 i = 0; i < 4; i++) {
            for (uint256 w = 0; w < 32; w++) {
                assertEq(stored.t1[i][w], fixtureT1[i][w], "t1 word");
            }
        }
        assertEq(pointer, registry.pointerFor(pk, aHat), "pointer is CREATE2 of (pk, aHat)");
        // a second registration of the same key is refused; a wrong caller too
        vm.expectRevert(abi.encodeWithSelector(TrustedMlDsa44KeyRegistry.AlreadyRegistered.selector, keccak256(pk)));
        registry.register(pk, aHat);
        vm.prank(address(0xbeef));
        vm.expectRevert(abi.encodeWithSelector(TrustedMlDsa44KeyRegistry.NotRegistrar.selector, address(0xbeef)));
        registry.register(pk, aHat);
        bytes memory shortPk = new bytes(1311);
        vm.expectRevert(abi.encodeWithSelector(TrustedMlDsa44KeyRegistry.BadKeyLength.selector, 1311));
        registry.register(shortPk, aHat);
    }

    function testRegistrarCanCorrectABinding() public {
        // a wrong matrix (here: the honest one with one word flipped) leaves the
        // recipient unable to spend; `replace` is the correction path, registrar only
        uint256[][][] memory wrong = aHat;
        wrong[0][0][0] ^= 1;
        address bad = registry.register(pk, wrong);
        bytes memory key = abi.encodePacked(commitment);
        assertEq(signer.verify(key, digest, payload), FAIL, "wrong aHat: recipient cannot spend");
        vm.expectRevert(abi.encodeWithSelector(TrustedMlDsa44KeyRegistry.NotRegistered.selector, keccak256("never")));
        registry.replace("never", aHat);
        vm.prank(address(0xbeef));
        vm.expectRevert(abi.encodeWithSelector(TrustedMlDsa44KeyRegistry.NotRegistrar.selector, address(0xbeef)));
        registry.replace(pk, aHat);
        address good = registry.replace(pk, aHat);
        assertTrue(good != bad, "corrected binding has its own PKContract");
        assertEq(registry.expandedKey(keccak256(pk)), good);
        assertGt(bad.code.length, 0, "the old PKContract stays deployed, just unmapped");
        assertEq(signer.verify(key, digest, payload), MAGIC_7913, "recipient can spend after the correction");
    }

    // ---------------------------------------------------- ERC-7913 signer
    function testCommitmentDerivationMatchesPython() public view {
        assertEq(signer.spendKey(pk), spendKey);
        assertEq(signer.commitment(spendKey, opener), commitment);
        assertEq(signer.PAYLOAD_LENGTH(), payload.length);
        assertEq(signer.KEY_DOMAIN(), bytes("pq-stealth/ml-dsa-44/key/v0"));
        assertEq(signer.COMMIT_DOMAIN(), bytes("pq-stealth/ml-dsa-44/commit/v0"));
    }

    function testSignerAcceptsRecipientAndRejectsEverythingElse() public {
        bytes memory key = abi.encodePacked(commitment);
        // before key setup: commitment matches, but there is no expanded key -> fail closed
        assertEq(signer.verify(key, digest, payload), FAIL, "unregistered key must fail");
        _register();

        uint256 g0 = gasleft();
        bytes4 got = signer.verify(key, digest, payload);
        emit log_named_uint("MlDsa44CommitSigner7913.verify (commitment + ZKNOX ML-DSA-44 verify)", g0 - gasleft());
        assertEq(got, MAGIC_7913, "genuine authorization must verify");
        // the same key signs another digest fine -- and that payload does not transfer
        assertEq(signer.verify(key, otherDigest, payloadOtherDigest), MAGIC_7913);
        assertEq(signer.verify(key, digest, payloadOtherDigest), FAIL, "wrong digest");
        assertEq(signer.verify(key, otherDigest, payload), FAIL, "wrong digest (other way)");
        // wrong account commitment
        assertEq(signer.verify(abi.encodePacked(keccak256("other account")), digest, payload), FAIL, "wrong commitment");
        assertEq(signer.verify(abi.encodePacked(commitment, uint8(0)), digest, payload), FAIL, "bad key length");
        // sender-known values only: valid ML-DSA-44 signature under a key derived from ss
        assertEq(signer.verify(key, digest, senderPayload), FAIL, "sender-derived key");
        // wrong opener, tampered pk, tampered signature, wrong lengths
        bytes memory bad = payload;
        bad[1312 + 3] ^= 0x01;
        assertEq(signer.verify(key, digest, bad), FAIL, "wrong opener");
        bad = payload;
        bad[40] ^= 0x01;
        assertEq(signer.verify(key, digest, bad), FAIL, "tampered pk");
        bad = payload;
        bad[1312 + 32 + 100] ^= 0x01;
        assertEq(signer.verify(key, digest, bad), FAIL, "tampered signature");
        bytes memory truncated = new bytes(payload.length - 1);
        for (uint256 i = 0; i < truncated.length; i++) truncated[i] = payload[i];
        assertEq(signer.verify(key, digest, truncated), FAIL, "truncated");
        assertEq(signer.verify(key, digest, abi.encodePacked(payload, uint8(0))), FAIL, "extended");
        assertEq(signer.verify(key, digest, ""), FAIL, "empty");
        // an ML-DSA-65-sized payload (1952 + 32 + 3309) is a different parameter set: rejected by length
        assertEq(signer.verify(key, digest, new bytes(1952 + 32 + 3309)), FAIL, "ML-DSA-65 sizes");
    }

    function testVerifierOutOfGasRevertsInsteadOfInvalid() public {
        _register();
        bytes memory key = abi.encodePacked(commitment);
        // a gas cap far below the ~15 M the ML-DSA-44 verify needs: the inner call
        // runs out of gas, and the signer must surface that, not report "invalid"
        vm.expectRevert(abi.encodeWithSelector(MlDsa44CommitSigner7913.VerifierCallFailed.selector, bytes("")));
        signer.verify{gas: 2_000_000}(key, digest, payload);
        // steps 1-3 still answer 0xffffffff cheaply, without reaching the verifier
        assertEq(signer.verify{gas: 200_000}(key, otherDigest, senderPayload), FAIL);
    }

    // ------------------------------------------------- frame adapter guards
    function testAdapterPublicInputPacking() public {
        _register();
        bytes32[] memory pubs = new bytes32[](4);
        pubs[0] = bytes32(uint256(uint128(bytes16(digest))));
        pubs[1] = bytes32(uint256(uint128(uint256(digest))));
        pubs[2] = bytes32(uint256(uint128(bytes16(commitment))));
        pubs[3] = bytes32(uint256(uint128(uint256(commitment))));
        assertTrue(adapter.verify(payload, pubs), "hi/lo halves reassemble digest and commitment");
        // swapped halves are a different digest
        (pubs[0], pubs[1]) = (pubs[1], pubs[0]);
        assertFalse(adapter.verify(payload, pubs), "swapped digest halves");
        (pubs[0], pubs[1]) = (pubs[1], pubs[0]);
        // a half with its upper 128 bits set is malformed, even if the low bits are right
        pubs[2] = bytes32(uint256(pubs[2]) | (uint256(1) << 200));
        assertFalse(adapter.verify(payload, pubs), "dirty upper bits");
        pubs[2] = bytes32(uint256(uint128(bytes16(commitment))));
        // wrong count
        bytes32[] memory three = new bytes32[](3);
        (three[0], three[1], three[2]) = (pubs[0], pubs[1], pubs[2]);
        assertFalse(adapter.verify(payload, three), "three public inputs");
        bytes32[] memory five = new bytes32[](5);
        (five[0], five[1], five[2], five[3]) = (pubs[0], pubs[1], pubs[2], pubs[3]);
        assertFalse(adapter.verify(payload, five), "five public inputs");
        // and the account builds exactly these inputs
        acct = Stealth8141ZkAccount(payable(factory.createAccount(commitment)));
        bytes32[] memory fromAccount = acct.publicInputs(digest);
        for (uint256 i = 0; i < 4; i++) assertEq(fromAccount[i], pubs[i]);
    }

    // ------------------------------------------------ frame account spend
    function testFrameAccountSpendAndBinding() public {
        _register();
        uint256 gDeploy = gasleft();
        acct = Stealth8141ZkAccount(payable(factory.createAccount(commitment)));
        emit log_named_uint("account deploy: factory.createAccount (no key material in initcode)", gDeploy - gasleft());
        assertEq(address(acct), factory.getAccountAddress(commitment));
        assertEq(acct.COMMITMENT(), commitment);
        assertEq(address(acct.verifier()), address(adapter));
        assertEq(factory.createAccount(commitment), address(acct), "idempotent");
        vm.deal(address(acct), 1 ether);
        ctx.set(digest, 1, payload);

        address dest = address(0xdEaD);
        vm.prank(ENTRY_POINT);
        uint256 g0 = gasleft();
        acct.executeFrame(1, dest, 0.1 ether, "");
        emit log_named_uint("executeFrame (adapter + signer + ZKNOX verify + call)", g0 - gasleft());
        assertEq(dest.balance, 0.1 ether);

        // a different digest (another chain/nonce/frames tuple) is not authorized
        ctx.set(otherDigest, 1, payload);
        vm.prank(ENTRY_POINT);
        vm.expectRevert(Stealth8141ZkAccount.NotAuthorized.selector);
        acct.executeFrame(1, dest, 0.1 ether, "");
        // sender-derived credentials are not authorized
        ctx.set(digest, 1, senderPayload);
        vm.prank(ENTRY_POINT);
        vm.expectRevert(Stealth8141ZkAccount.NotAuthorized.selector);
        acct.executeFrame(1, dest, 0.1 ether, "");
        // only the entry point may drive the account
        ctx.set(digest, 1, payload);
        vm.expectRevert(abi.encodeWithSelector(Stealth8141ZkAccount.NotEntryPoint.selector, address(this)));
        acct.executeFrame(1, dest, 0.1 ether, "");
    }

    function testInitializationCannotSubstitutePolicy() public {
        // the counterfactual address binds (commitment, adapter, frameCtx): a factory with
        // another verifier -- e.g. one that accepts everything -- lands elsewhere
        Stealth8141ZkFactory rogue = new Stealth8141ZkFactory(IProofVerifier(address(new AcceptAllVerifier())), ctx);
        assertTrue(rogue.getAccountAddress(commitment) != factory.getAccountAddress(commitment));
        // and so does a different commitment under the honest factory
        assertTrue(factory.getAccountAddress(keccak256("x")) != factory.getAccountAddress(commitment));
        // the address is exactly the documented CREATE2 formula (Python/TS `account_address`)
        bytes32 initHash = keccak256(abi.encodePacked(
            type(Stealth8141ZkAccount).creationCode, abi.encode(commitment, address(adapter), address(ctx))));
        address expected = address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff), address(factory), bytes32(0), initHash)))));
        assertEq(factory.getAccountAddress(commitment), expected);
    }

    // --------------------------------------------- ERC-1271 / SignerERC7913
    function testErc1271AccountSurface() public {
        _register();
        Stealth7913Account account = new Stealth7913Account(abi.encodePacked(address(signer), commitment));
        assertEq(account.isValidSignature(digest, payload), MAGIC_1271);
        assertEq(account.isValidSignature(otherDigest, payload), FAIL);
        assertEq(account.isValidSignature(digest, senderPayload), FAIL);
    }
}
