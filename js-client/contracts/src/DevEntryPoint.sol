// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

// Compile anchor: forces forge to build the vendored ERC-4337 v0.8
// EntryPoint so the UI dev chain (ui/scripts/dev-chain.mjs) can deploy it
// on local anvil, where the canonical singleton does not exist.

import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
