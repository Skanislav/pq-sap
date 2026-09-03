// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";
import {ZKNOX_dilithium} from "ethdilithium/ZKNOX_dilithium.sol";
import {PKContract} from "ethdilithium/ZKNOX_PKContract.sol";
import {IERC7913SignatureVerifier} from "@openzeppelin/contracts/interfaces/IERC7913.sol";
import {expandVec, d} from "ethdilithium/ZKNOX_dilithium_utils.sol";
import {nttInv} from "ethdilithium/ZKNOX_NTT_dilithium.sol";

import {PKContractNtt} from "../src/ntt/PKContractNtt.sol";
import {ZKNOX_dilithium_ntt} from "../src/ntt/ZKNOX_dilithium_ntt.sol";

/// Spike for D-022: same blinded ML-DSA fixture (`python/scripts/zknox_7913_demo.json`)
/// verified through the stock df999ed verifier and through the NTT-precomputed pair.
/// Run: forge test --root contracts --match-contract NttPrecompute -vv
contract NttPrecomputeTest is Test {
    uint256[][][] aHat;
    bytes tr;
    uint256[][] t1;
    bytes32 challenge;
    bytes sig;

    ZKNOX_dilithium stock;
    ZKNOX_dilithium_ntt ntt;
    address pkStock;
    address pkNtt;

    function setUp() public {
        string memory json = vm.readFile("../../python/scripts/zknox_7913_demo.json");
        bytes memory pkData = vm.parseJsonBytes(json, ".public_key_data");
        (bytes memory aHatEnc, bytes memory trBytes, bytes memory t1Enc) =
            abi.decode(pkData, (bytes, bytes, bytes));
        aHat = abi.decode(aHatEnc, (uint256[][][]));
        tr = trBytes;
        t1 = abi.decode(t1Enc, (uint256[][]));
        challenge = vm.parseJsonBytes32(json, ".challenge");
        sig = vm.parseJsonBytes(json, ".sig");

        stock = new ZKNOX_dilithium();
        ntt = new ZKNOX_dilithium_ntt();

        uint256 g0 = gasleft();
        pkStock = address(new PKContract(aHat, tr, t1));
        uint256 gStock = g0 - gasleft();
        g0 = gasleft();
        pkNtt = address(new PKContractNtt(aHat, tr, t1));
        uint256 gNtt = g0 - gasleft();
        emit log_named_uint("PKContract deploy gas (stock, plain t1)", gStock);
        emit log_named_uint("PKContractNtt deploy gas (NTT(t1*2^d) at setup)", gNtt);
    }

    function _verify(IERC7913SignatureVerifier v, address pk, bytes32 m, bytes memory s)
        internal
        view
        returns (bytes4 out, uint256 gas)
    {
        bytes memory key = abi.encodePacked(pk);
        uint256 g0 = gasleft();
        out = v.verify(key, m, s);
        gas = g0 - gasleft();
    }

    function testStockVerifierAccepts() public {
        (bytes4 out, uint256 gas) = _verify(stock, pkStock, challenge, sig);
        emit log_named_uint("verify gas: stock df999ed (per-verify NTT)", gas);
        assertEq(out, IERC7913SignatureVerifier.verify.selector);
    }

    function testNttVerifierAccepts() public {
        (bytes4 out, uint256 gas) = _verify(ntt, pkNtt, challenge, sig);
        emit log_named_uint("verify gas: NTT-precomputed pair", gas);
        assertEq(out, IERC7913SignatureVerifier.verify.selector);
    }

    function testNttVerifierRejectsTamperedSignature() public {
        bytes memory bad = sig;
        bad[100] ^= 0x01;
        (bytes4 out,) = _verify(ntt, pkNtt, challenge, bad);
        assertEq(out, bytes4(0xFFFFFFFF));
        (out,) = _verify(ntt, pkNtt, keccak256("other"), sig);
        assertEq(out, bytes4(0xFFFFFFFF));
    }

    function testMixedPairsFail() public {
        // stock verifier with the NTT key, and vice versa, must not accept
        (bytes4 a,) = _verify(stock, pkNtt, challenge, sig);
        (bytes4 b,) = _verify(ntt, pkStock, challenge, sig);
        assertEq(a, bytes4(0xFFFFFFFF));
        assertEq(b, bytes4(0xFFFFFFFF));
    }

    function testKeyReadCost() public {
        uint256 g0 = gasleft();
        PKContract(pkStock).getPublicKey();
        uint256 gRead = g0 - gasleft();
        emit log_named_uint("getPublicKey() gas: SSTORE2 read + abi.decode of 22.4 kB", gRead);
        g0 = gasleft();
        bytes memory raw = abi.encodePacked(pkStock);
        bytes memory dummy = abi.encode(raw, challenge, sig);
        uint256 gEnc = g0 - gasleft();
        emit log_named_uint("abi.encode calldata build (baseline noise)", gEnc);
        assertGt(dummy.length, 0);
    }

    function testT1HatRoundTrips() public view {
        uint256[][] memory stored = PKContractNtt(pkNtt).getPublicKey().t1;
        uint256[][] memory hat = expandVec(stored);
        uint256[][] memory plain = expandVec(t1);
        for (uint256 i = 0; i < 4; i++) {
            uint256[] memory back = nttInv(hat[i]);
            for (uint256 j = 0; j < 256; j++) {
                assertEq(back[j] >> d, plain[i][j]);
            }
        }
    }
}
