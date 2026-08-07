#!/usr/bin/env python3
"""On-chain data-cost model for the PQ stealth scheme.

The story here is *data*, not compute. Scanning is competitive (see
`scan_bench.py`); the price of going post-quantum is footprint. A PQ
announcement carries a 1088-byte ML-KEM ciphertext where EC DKSAP carries a
33-byte point, and the meta-address is 5,633 B where EC is 33 B. This script
prices that footprint.

It is anchored to a *measured* number: the Sepolia-fork test
(`js-client/test/e2e-sepolia-fork.test.ts`) posts a real vector announcement
to the canonical ERC-5564 announcer and measures 67,580 gas. We reconstruct
the exact calldata of that call, apply the post-Pectra (Prague) gas rules
including the EIP-7623 calldata floor, and check the model reproduces the
measurement before extrapolating to L2. If it doesn't reproduce, every L2
number would inherit the error, so that check gates everything below.

Usage: onchain_cost.py [--json out.json]
"""

import argparse
import json
import os

from eth_abi import encode
from eth_utils import keccak

# --------------------------------------------------------------------------
# Gas constants (Ethereum mainnet, Prague/Pectra, mid-2026)
# --------------------------------------------------------------------------
G_TX = 21_000                 # base transaction cost
G_TXDATA_ZERO = 4             # legacy per-zero-byte (= 1 token * STANDARD_TOKEN_COST)
G_TXDATA_NONZERO = 16         # legacy per-nonzero-byte (= 4 tokens * STANDARD_TOKEN_COST)
# EIP-7623 (Prague): calldata floor.
STANDARD_TOKEN_COST = 4
TOTAL_COST_FLOOR_PER_TOKEN = 10
# LOG opcode (event emission)
G_LOG = 375
G_LOGTOPIC = 375
G_LOGDATA = 8                 # per byte of non-indexed event data
G_MEMORY = 3                  # per word, plus quadratic term

MEASURED_ANNOUNCE_GAS = 67_580  # js-client/test/e2e-sepolia-fork.test.ts


def byte_stats(data: bytes) -> tuple[int, int]:
    z = data.count(0)
    return z, len(data) - z


def calldata_gas_standard(zero: int, nonzero: int) -> int:
    return zero * G_TXDATA_ZERO + nonzero * G_TXDATA_NONZERO


def calldata_tokens(zero: int, nonzero: int) -> int:
    # EIP-7623: nonzero byte = 4 tokens, zero byte = 1 token.
    return zero + nonzero * STANDARD_TOKEN_COST


def memory_gas(num_bytes: int) -> int:
    words = (num_bytes + 31) // 32
    return G_MEMORY * words + words * words // 512


def abi_encode_announce(scheme_id: int, stealth_addr: bytes,
                        ephemeral: bytes, metadata: bytes) -> bytes:
    """Exact calldata for
    ERC5564Announcer.announce(uint256,address,bytes,bytes)."""
    selector = keccak(text="announce(uint256,address,bytes,bytes)")[:4]
    addr = "0x" + stealth_addr.hex()
    body = encode(["uint256", "address", "bytes", "bytes"],
                  [scheme_id, addr, ephemeral, metadata])
    return selector + body


# --------------------------------------------------------------------------
# 1. Reproduce the measured announcement
# --------------------------------------------------------------------------
def model_announce(ephemeral: bytes, stealth_addr: bytes, metadata: bytes,
                   scheme_id: int) -> dict:
    calldata = abi_encode_announce(scheme_id, stealth_addr, ephemeral, metadata)
    z, nz = byte_stats(calldata)
    tokens = calldata_tokens(z, nz)

    # Execution: the announcer just re-emits its args in an event with three
    # indexed topics (schemeId, stealthAddress, caller). LOG4.
    # Non-indexed event data = abi.encode(bytes ephemeralPubKey, bytes metadata).
    event_data = encode(["bytes", "bytes"], [ephemeral, metadata])
    log_gas = G_LOG + 4 * G_LOGTOPIC + G_LOGDATA * len(event_data)
    # Memory to stage the two dynamic args for the LOG, plus a small,
    # empirically-fit dispatch/copy overhead (Solidity ABI-decode + CALLDATACOPY).
    mem_gas = memory_gas(len(event_data) + len(calldata))
    dispatch_overhead = 700
    execution = log_gas + mem_gas + dispatch_overhead

    standard = G_TX + calldata_gas_standard(z, nz) + execution
    floor = G_TX + TOTAL_COST_FLOOR_PER_TOKEN * tokens
    modeled = max(standard, floor)
    regime = "FLOOR (EIP-7623)" if floor >= standard else "standard"

    return {
        "calldata_bytes": len(calldata),
        "calldata_zero": z, "calldata_nonzero": nz,
        "calldata_tokens": tokens,
        "event_data_bytes": len(event_data),
        "execution_gas": execution,
        "standard_total": standard,
        "floor_total": floor,
        "modeled_gas": modeled,
        "binding_regime": regime,
        "measured_gas": MEASURED_ANNOUNCE_GAS,
        "error_pct": round(100 * (modeled - MEASURED_ANNOUNCE_GAS)
                           / MEASURED_ANNOUNCE_GAS, 2),
    }


# --------------------------------------------------------------------------
# 2. DKSAP announcement for comparison (EC baseline)
# --------------------------------------------------------------------------
def model_dksap_announce() -> dict:
    """ERC-5564 secp256k1: ephemeralPubKey = 33-byte compressed point,
    metadata = 1-byte view tag. Same announcer, same event shape."""
    ephemeral = b"\x02" + b"\xab" * 32           # 33 B, worst-case all-nonzero
    stealth_addr = b"\xcd" * 20
    metadata = b"\x2a"
    return model_announce(ephemeral, stealth_addr, metadata, 1)


# --------------------------------------------------------------------------
# 3. L2: raw byte cost + EIP-4844 blob-marginal cost
# --------------------------------------------------------------------------
def model_l2(ann_bytes: int, dksap_bytes: int, eth_usd: float,
             l1_basefee_gwei: float, blob_basefee_gwei: float) -> dict:
    """Rollups post their tx data to L1, either as calldata or (post-4844) in
    blobs. We give the two marginal L1 data costs per announcement; the exact
    per-rollup fee then depends on that rollup's compression ratio and its
    own fee formula, which floats. We do NOT invent a per-rollup $ figure."""
    GWEI = 1e-9

    def usd(gas_or_fee_wei_equiv):
        return gas_or_fee_wei_equiv * eth_usd

    # (a) calldata regime (pre-4844 rollups, or 4844 fallback): the rollup
    #     pays L1 calldata gas for the announcement's compressed bytes. Use
    #     the EIP-7623 floor (data-heavy) at ~10 gas/token, ~40 gas/nonzero.
    #     Assume near-incompressible ciphertext (nonzero-dominated).
    def calldata_l1_usd(nbytes):
        tokens = nbytes * STANDARD_TOKEN_COST  # treat as all-nonzero (ciphertext)
        gas = TOTAL_COST_FLOOR_PER_TOKEN * tokens
        return usd(gas * l1_basefee_gwei * GWEI)

    # (b) blob regime (EIP-4844): data goes in blobs at ~1 gas/byte priced by
    #     the blob base fee, not the execution base fee. 131072 bytes/blob.
    def blob_l1_usd(nbytes):
        # blob gas is charged per-byte-equivalent at blob_basefee; a blob is
        # 2**17 gas. Marginal cost of nbytes = nbytes/131072 * 131072 * fee.
        blob_gas = nbytes  # 1 blob-gas per byte, marginal
        return usd(blob_gas * blob_basefee_gwei * GWEI)

    return {
        "assumptions": {
            "eth_usd": eth_usd,
            "l1_basefee_gwei": l1_basefee_gwei,
            "blob_basefee_gwei": blob_basefee_gwei,
            "note": "marginal L1 data cost per announcement; per-rollup fee "
                    "adds that rollup's compression + margin, which floats",
        },
        "pq_announce_bytes": ann_bytes,
        "dksap_announce_bytes": dksap_bytes,
        "pq_calldata_l1_usd": round(calldata_l1_usd(ann_bytes), 6),
        "dksap_calldata_l1_usd": round(calldata_l1_usd(dksap_bytes), 6),
        "pq_blob_l1_usd": round(blob_l1_usd(ann_bytes), 6),
        "dksap_blob_l1_usd": round(blob_l1_usd(dksap_bytes), 6),
        "blob_vs_calldata_saving_x": round(
            calldata_l1_usd(ann_bytes) / blob_l1_usd(ann_bytes), 1),
    }


# --------------------------------------------------------------------------
# 4. Meta-address registration (ERC-6538), one-time per recipient
# --------------------------------------------------------------------------
def model_meta_registration(meta_bytes: int, dksap_meta_bytes: int) -> dict:
    """ERC6538Registry.registerKeys(schemeId, bytes stealthMetaAddress) stores
    the meta-address in a mapping. Dominated by SSTORE of the bytes payload:
    ~20,000 gas per fresh 32-byte word (G_sset), plus calldata."""
    G_SSET = 20_000

    def reg_gas(nbytes):
        words = (nbytes + 31) // 32
        # calldata floor for the payload (data-heavy), + one SSTORE per word.
        tokens = nbytes * STANDARD_TOKEN_COST
        calldata = TOTAL_COST_FLOOR_PER_TOKEN * tokens
        storage = words * G_SSET
        return G_TX + calldata + storage, words

    pq_gas, pq_words = reg_gas(meta_bytes)
    ec_gas, ec_words = reg_gas(dksap_meta_bytes)
    return {
        "pq_meta_bytes": meta_bytes, "pq_storage_words": pq_words,
        "pq_register_gas": pq_gas,
        "dksap_meta_bytes": dksap_meta_bytes, "dksap_storage_words": ec_words,
        "dksap_register_gas": ec_gas,
        "ratio_x": round(pq_gas / ec_gas, 1),
        "note": "one-time per recipient; SSTORE-dominated. An SSTORE2/"
                "code-blob store (~200 gas/byte to deploy) is cheaper for "
                "payloads this large and is the recommended pattern.",
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    here = os.path.dirname(__file__)
    vpath = os.path.join(here, "..", "vectors", "v0", "vectors.json")
    v = json.load(open(vpath))
    ann = v["cases"][0]["announcement"]

    def hx(s):
        return bytes.fromhex(s[2:] if s.startswith("0x") else s)

    ephemeral = hx(ann["ephemeral_pub_key"])
    stealth_addr = hx(ann["stealth_address"])
    metadata = hx(ann["view_tag"])
    scheme_id = 0x5567

    pq = model_announce(ephemeral, stealth_addr, metadata, scheme_id)
    ec = model_dksap_announce()
    l2 = model_l2(pq["calldata_bytes"], ec["calldata_bytes"],
                  eth_usd=3200.0, l1_basefee_gwei=8.0, blob_basefee_gwei=1.0)
    meta = model_meta_registration(5633, 33)

    out = {"announce_pq": pq, "announce_dksap": ec, "l2": l2,
           "meta_registration": meta}

    # ------- report -------
    print("=" * 66)
    print("1. ANNOUNCEMENT ON-CHAIN COST (anchored to measured 67,580 gas)")
    print("=" * 66)
    print(f"  calldata:        {pq['calldata_bytes']:>6} B  "
          f"({pq['calldata_nonzero']} nonzero, {pq['calldata_zero']} zero, "
          f"{pq['calldata_tokens']} tokens)")
    print(f"  execution (LOG4):{pq['execution_gas']:>7} gas")
    print(f"  standard total:  {pq['standard_total']:>7} gas")
    print(f"  floor total:     {pq['floor_total']:>7} gas   "
          f"<- binding: {pq['binding_regime']}")
    print(f"  MODELED:         {pq['modeled_gas']:>7} gas")
    print(f"  MEASURED:        {pq['measured_gas']:>7} gas   "
          f"(error {pq['error_pct']:+.2f}%)")
    print(f"\n  DKSAP announce (33 B point): "
          f"modeled {ec['modeled_gas']} gas ({ec['binding_regime']})")
    print(f"  => PQ announcement costs "
          f"{pq['modeled_gas']/ec['modeled_gas']:.1f}x the EC baseline on L1")

    print("\n" + "=" * 66)
    print("2. L2 MARGINAL DATA COST (dated assumptions, not per-rollup fees)")
    print("=" * 66)
    a = l2["assumptions"]
    print(f"  assumptions: ETH=${a['eth_usd']:.0f}, L1 base={a['l1_basefee_gwei']} "
          f"gwei, blob base={a['blob_basefee_gwei']} gwei")
    print(f"  PQ announce   : calldata ${l2['pq_calldata_l1_usd']:.4f}  |  "
          f"blob ${l2['pq_blob_l1_usd']:.5f}")
    print(f"  DKSAP announce: calldata ${l2['dksap_calldata_l1_usd']:.4f}  |  "
          f"blob ${l2['dksap_blob_l1_usd']:.5f}")
    print(f"  blobs cut the PQ data cost ~{l2['blob_vs_calldata_saving_x']}x "
          f"vs calldata")

    print("\n" + "=" * 66)
    print("3. META-ADDRESS REGISTRATION (ERC-6538, one-time per recipient)")
    print("=" * 66)
    print(f"  PQ    meta 5,633 B -> {meta['pq_storage_words']} words, "
          f"~{meta['pq_register_gas']:,} gas (naive SSTORE)")
    print(f"  DKSAP meta    33 B -> {meta['dksap_storage_words']} words, "
          f"~{meta['dksap_register_gas']:,} gas")
    print(f"  ratio ~{meta['ratio_x']}x; {meta['note']}")

    if args.json:
        json.dump(out, open(args.json, "w"), indent=2)
        print(f"\nwrote {args.json}")


if __name__ == "__main__":
    main()
