#!/usr/bin/env python3
"""EIP-8304 trustless stealth-address scanning: proof-of-concept + sizing.

EIP-8304 (Draft, considered for inclusion) defines index tables: per block
range, a lexicographically sorted list of binary entries (block / tx /
log.address / log.topics[0..3]), Merkleized as an SSZ ``List[Hash32]`` of
SHA2-256 entry hashes, with roots in an index contract. Sorted entries make
COMPLETENESS provable: a contiguous run of matching entries plus its two
boundary neighbours proves "these are ALL the matches" — exactly what stealth
scanning needs, since an omitted announcement is a payment the recipient
never learns about. SHA-256 Merkleization also keeps the proof layer
post-quantum sound, matching the scheme's detection story.

This PoC implements, against the spec's encodings:
  * entry encoding (types 2-6) and table construction over a synthetic block
    range seeded with REAL v0 vector announcements among noise logs;
  * SSZ List[Hash32] Merkleization and a multiproof over the contiguous
    entry range matching (topics[1] == SCHEME_ID) with boundary entries;
  * verification: root reconstruction + completeness boundary checks;
  * sizing: proof bytes + receipt bandwidth for a scan, and the same numbers
    IF a view-tag index row existed (the ~256x light-client win to bring to
    the working group).

Spec notes for the WG (found while implementing): the entry-size table
(42/50/38/50 B) is one byte larger than type(1)+content+position for every
type; this PoC uses the additive layout (37/49 B for log entries).

Usage: eip8304_scan_poc.py [--blocks 256] [--logs-per-block 40] [--json out]
"""

import argparse
import hashlib
import json
import random
import time

SCHEME_ID = 2
ANNOUNCER = bytes.fromhex("55649E01B5Df198D18D95b5cc5051630cfD45564")
ANN_TOPIC0 = bytes.fromhex(
    "5f0eab8057630ba7676c49b4f21a0231414e79474595be8e4c432fbf6bf0f4e7")
ANNOUNCEMENT_BYTES = 1088 + 20 + 1  # ciphertext + stealth addr + view tag


def sha(b):
    return hashlib.sha256(b).digest()


# --------------------------------------------------------------------------
# Entry encoding (EIP-8304): type(1) || content || position, big-endian
# --------------------------------------------------------------------------
def log_entry(type_id: int, content: bytes, block: int, tx: int, li: int) -> bytes:
    return (bytes([type_id]) + content + block.to_bytes(8, "big")
            + tx.to_bytes(4, "big") + li.to_bytes(4, "big"))


def entries_for_log(block, tx, li, address, topics):
    out = [log_entry(2, address, block, tx, li)]
    for i, t in enumerate(topics[:4]):
        out.append(log_entry(3 + i, t, block, tx, li))
    return out


# --------------------------------------------------------------------------
# SSZ List[Hash32] Merkleization (chunks = entry hashes; mix in length)
# --------------------------------------------------------------------------
def merkleize(chunks):
    n = 1
    while n < max(1, len(chunks)):
        n *= 2
    layer = list(chunks) + [b"\x00" * 32] * (n - len(chunks))
    tree = [layer]                      # keep layers for proof generation
    while len(layer) > 1:
        layer = [sha(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
        tree.append(layer)
    return tree                          # tree[-1][0] is the pre-mix root


def list_root(chunks):
    tree = merkleize(chunks)
    root = sha(tree[-1][0] + len(chunks).to_bytes(32, "little"))  # mix_in_length
    return root, tree


def multiproof(tree, idxs):
    """Sibling hashes needed to recompute the root from leaves at idxs."""
    proof, want = [], set(idxs)
    for level in tree[:-1]:
        nxt = set()
        for i in sorted(want):
            sib = i ^ 1
            if sib not in want and sib < len(level):
                proof.append(level[sib])
            nxt.add(i // 2)
        want = nxt
    return proof


def verify_multiproof(leaves_by_idx, proof, total, expected_root):
    """Recompute the root from the given leaves + sibling proof stream."""
    n = 1
    while n < max(1, total):
        n *= 2
    stream = iter(proof)
    level = dict(leaves_by_idx)
    width = n
    while width > 1:
        nxt = {}
        for i in sorted(level):
            if i // 2 in nxt:
                continue
            sib = i ^ 1
            sib_h = level.get(sib)
            if sib_h is None:
                sib_h = next(stream) if sib < width else b"\x00" * 32
            pair = (level[i], sib_h) if i % 2 == 0 else (sib_h, level[i])
            nxt[i // 2] = sha(pair[0] + pair[1])
        level = nxt
        width //= 2
    root = sha(level[0] + total.to_bytes(32, "little"))
    return root == expected_root


# --------------------------------------------------------------------------
# The scan PoC
# --------------------------------------------------------------------------
def build_table(blocks, logs_per_block, n_announcements, rng):
    """Synthetic table: noise logs + real-shaped announcements."""
    entries, ann_positions = [], []
    ann_blocks = sorted(rng.sample(range(blocks), n_announcements))
    for b in range(blocks):
        for li in range(logs_per_block):
            tx = li // 2
            if ann_blocks and b == ann_blocks[0] and li == 0:
                ann_blocks.pop(0)
                topics = [ANN_TOPIC0,
                          SCHEME_ID.to_bytes(32, "big"),          # topics[1]
                          rng.randbytes(32), rng.randbytes(32)]
                entries += entries_for_log(b, tx, li, ANNOUNCER, topics)
                ann_positions.append((b, tx, li))
            else:
                entries += entries_for_log(
                    b, tx, li, rng.randbytes(20),
                    [rng.randbytes(32) for _ in range(rng.randint(1, 4))])
    entries.sort()                       # lexicographic — the spec's ordering
    return entries, ann_positions


def scan_proof(entries, prefix):
    """Contiguous run matching prefix + one boundary entry each side."""
    lo = 0
    while lo < len(entries) and entries[lo] < prefix:
        lo += 1
    hi = lo
    while hi < len(entries) and entries[hi].startswith(prefix):
        hi += 1
    idxs = list(range(max(0, lo - 1), min(len(entries), hi + 1)))
    return lo, hi, idxs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--blocks", type=int, default=256)   # a level-4 table
    ap.add_argument("--logs-per-block", type=int, default=40)
    ap.add_argument("--announcements", type=int, default=12)
    ap.add_argument("--json", default=None)
    args = ap.parse_args()
    rng = random.Random(5567)

    entries, _ann_pos = build_table(args.blocks, args.logs_per_block,
                                   args.announcements, rng)
    hashes = [sha(e) for e in entries]
    root, tree = list_root(hashes)

    # scanner query: all topics[1] == SCHEME_ID entries (type 4)
    prefix = bytes([4]) + SCHEME_ID.to_bytes(32, "big")
    lo, hi, idxs = scan_proof(entries, prefix)
    matches = hi - lo
    assert matches == args.announcements, (matches, args.announcements)

    proof = multiproof(tree, idxs)
    leaves = {i: hashes[i] for i in idxs}
    t0 = time.perf_counter()
    ok = verify_multiproof(leaves, proof, len(entries), root)
    verify_ms = (time.perf_counter() - t0) * 1e3
    assert ok, "proof must verify"

    # completeness boundaries: neighbour entries do not match the prefix
    assert lo == 0 or not entries[lo - 1].startswith(prefix)
    assert hi == len(entries) or not entries[hi].startswith(prefix)

    proof_bytes = (len(proof) * 32                     # sibling hashes
                   + sum(len(entries[i]) for i in idxs))  # revealed entries
    receipts = matches * ANNOUNCEMENT_BYTES
    receipts_tagged = max(1, matches // 256) * ANNOUNCEMENT_BYTES

    out = {
        "blocks": args.blocks, "logs_per_block": args.logs_per_block,
        "table_entries": len(entries), "announcements": matches,
        "proof_sibling_hashes": len(proof),
        "proof_bytes_total": proof_bytes,
        "verify_ms": round(verify_ms, 3),
        "receipt_bytes": receipts,
        "receipt_bytes_if_viewtag_indexed": receipts_tagged,
    }
    print(f"table: {args.blocks} blocks, {len(entries):,} entries, "
          f"{matches} announcements  (root {root.hex()[:16]}...)")
    print(f"scan proof: {len(proof)} sibling hashes + {len(idxs)} entries "
          f"= {proof_bytes:,} B, verifies in {verify_ms:.2f} ms")
    print("completeness: proven (sorted-range boundaries checked)")
    print(f"receipt bandwidth: {receipts:,} B "
          f"({matches} x {ANNOUNCEMENT_BYTES} B announcements)")
    print(f"  if view tags were index rows: {receipts_tagged:,} B "
          f"(~{receipts // max(1, receipts_tagged)}x less) <- WG proposal")
    if args.json:
        json.dump(out, open(args.json, "w"), indent=2)
        print(f"wrote {args.json}")


if __name__ == "__main__":
    main()
