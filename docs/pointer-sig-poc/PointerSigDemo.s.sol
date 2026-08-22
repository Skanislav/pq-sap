// SPDX-License-Identifier: MIT
// End-to-end demo of the (v, r, s)-as-pointers scheme against a live node (anvil).
//
//   anvil &
//   forge script script/PointerSigDemo.s.sol --rpc-url http://127.0.0.1:8545 \
//       --private-key $ANVIL_KEY --broadcast --ffi
//
// Every step is a real transaction: deploy, registerKey, publishSignature, withdrawWithSig.
pragma solidity ^0.8.25;

import {Script, console} from "forge-std/Script.sol";
import {ZKNOX_ethdilithium} from "../src/ZKNOX_ethdilithium.sol";
import {PointerSigRegistry, PointerSigVault} from "../src/PointerSig.sol";

contract PointerSigDemo is Script {
    string constant PY = "pythonref/myenv/bin/python";
    string constant SEED = "cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe";

    function _pubKey() internal returns (bytes memory) {
        string[] memory c = new string[](4);
        c[0] = PY;
        c[1] = "pythonref/prepare_pk_for_deployment.py";
        c[2] = "ETH";
        c[3] = SEED;
        return vm.ffi(c);
    }

    function _pqSign(bytes32 digest) internal returns (bytes memory) {
        string[] memory c = new string[](5);
        c[0] = PY;
        c[1] = "pythonref/sig_sol.py";
        c[2] = vm.toString(digest);
        c[3] = "ETH";
        c[4] = SEED;
        (bytes memory cTilde, bytes memory z, bytes memory h) = abi.decode(vm.ffi(c), (bytes, bytes, bytes));
        return abi.encodePacked(cTilde, z, h);
    }

    PointerSigRegistry registry;
    PointerSigVault vault;

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address recipient = vm.envOr("RECIPIENT", address(0xBEEF));

        bytes memory pubKey = _pubKey(); // off-chain: PQ material via ffi
        vm.startBroadcast(pk);
        _deploy();
        (uint256 keyIdx, uint256 sigIdx, address pqOwner) = _pqSpend(pubKey, recipient);
        _classicSpend(pk, recipient);
        vm.stopBroadcast();

        console.log("registry  :", address(registry));
        console.log("vault     :", address(vault));
        console.log("pqOwner   :", pqOwner);
        console.log("keyIdx (r):", keyIdx);
        console.log("sigIdx (s):", sigIdx);
        console.log("recipient :", recipient, "balance:", recipient.balance);
    }

    // 1. deploy verifier + registry + vault
    function _deploy() internal {
        ZKNOX_ethdilithium verifier = new ZKNOX_ethdilithium();
        registry = new PointerSigRegistry(verifier);
        vault = new PointerSigVault(registry);
        console.log("verifier  :", address(verifier));
    }

    // 2-5. register key (r), fund, sign off-chain, publish sig (s), spend via (v, r, s)
    function _pqSpend(bytes memory pubKey, address recipient)
        internal
        returns (uint256 keyIdx, uint256 sigIdx, address pqOwner)
    {
        pqOwner = address(uint160(uint256(keccak256(pubKey))));
        keyIdx = registry.registerKey(pubKey);
        vault.depositFor{value: 1 ether}(pqOwner);
        bytes32 digest = vault.withdrawDigest(pqOwner, recipient, 0.25 ether, vault.nonces(pqOwner));
        sigIdx = registry.publishSignature(_pqSign(digest));
        vault.withdrawWithSig(pqOwner, recipient, 0.25 ether, registry.V_PQ(), bytes32(keyIdx), bytes32(sigIdx));
    }

    // 6. classic path: same vault, same function, same ABI
    function _classicSpend(uint256 pk, address recipient) internal {
        address eoa = vm.addr(pk);
        vault.depositFor{value: 0.5 ether}(eoa);
        bytes32 d = vault.withdrawDigest(eoa, recipient, 0.1 ether, vault.nonces(eoa));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        vault.withdrawWithSig(eoa, recipient, 0.1 ether, v, r, s);
    }
}
