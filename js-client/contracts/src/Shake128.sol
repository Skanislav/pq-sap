// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

// SHAKE128 (FIPS 202, rate 168) for the `ml-dsa-44-commit/v0` trustless key
// setup (#27): FIPS 204 `ExpandA(rho)` derives the public matrix from `rho`
// with SHAKE128, while the vendored ZKNOX sponge (`ethdilithium/ZKNOX_shake.sol`)
// is SHAKE256-only (`_RATE = 136`). The Keccak-f[1600] permutation `f1600` is
// identical for both instances; only the rate (hence capacity) differs. This
// library reuses the vendored permutation so the two implementations cannot
// drift.
//
// Only what ExpandA needs is implemented: absorb a short seed (the largest
// ExpandA seed is 34 bytes; the guard allows up to 166 = RATE-2 so shorter
// FIPS 202 inputs also work), pad, and squeeze 168-byte blocks lazily, one
// per call. No incremental absorb, no interleaved absorb/squeeze — a
// one-shot XOF.

import {f1600} from "ethdilithium/ZKNOX_shake.sol";

uint256 constant SHAKE128_RATE = 168;

struct Shake128Ctx {
    uint64[25] state; // Keccak-f lanes; block byte b lives in lane b/8, bits 8*(b%8)
    uint256 block; // number of blocks squeezed so far
}

/// @dev Absorb `seed` (<= 166 bytes) and apply the SHAKE128 padding (FIPS 202
///      §4): XOR 0x1F at byte `seed.length` and 0x80 at byte 167, then permute
///      once. The state then holds squeeze block 0.
function shake128Init(bytes memory seed) pure returns (Shake128Ctx memory ctx) {
    require(seed.length <= SHAKE128_RATE - 2, "shake128: seed too long");
    for (uint256 b = 0; b < seed.length; b++) {
        ctx.state[b >> 3] = ctx.state[b >> 3] ^ (uint64(uint8(seed[b])) << uint64(8 * (b & 7)));
    }
    ctx.state[seed.length >> 3] =
        ctx.state[seed.length >> 3] ^ (uint64(0x1f) << uint64(8 * (seed.length & 7)));
    ctx.state[(SHAKE128_RATE - 1) >> 3] =
        ctx.state[(SHAKE128_RATE - 1) >> 3] ^ (uint64(0x80) << uint64(8 * ((SHAKE128_RATE - 1) & 7)));
    ctx.state = f1600(ctx.state);
    return ctx;
}

/// @dev Return the next 168 squeeze bytes. Block 0 is read straight from the
///      post-absorb state; every later block is read after one permutation.
///      168 bytes = 21 little-endian 64-bit lanes.
function shake128SqueezeBlock(Shake128Ctx memory ctx)
    pure
    returns (Shake128Ctx memory ctxOut, bytes memory out)
{
    if (ctx.block > 0) {
        ctx.state = f1600(ctx.state);
    }
    out = new bytes(SHAKE128_RATE);
    for (uint256 w = 0; w < 21; w++) {
        uint64 lane = ctx.state[w];
        for (uint256 t = 0; t < 8; t++) {
            out[w * 8 + t] = bytes1(uint8(lane >> (8 * t)));
        }
    }
    ctx.block += 1;
    return (ctx, out);
}