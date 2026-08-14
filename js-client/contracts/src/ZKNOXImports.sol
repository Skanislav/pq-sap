// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

// Compile anchor: forces forge to build the vendored ETHDILITHIUM contracts
// (lib/ETHDILITHIUM @ df999ed) so their artifacts are available to the
// viem-driven e2e tests (test/e2e-7913.test.ts).

import {ZKNOX_dilithium} from "ethdilithium/ZKNOX_dilithium.sol";
import {ZKNOX_ethdilithium} from "ethdilithium/ZKNOX_ethdilithium.sol";
import {PKContract} from "ethdilithium/ZKNOX_PKContract.sol";
