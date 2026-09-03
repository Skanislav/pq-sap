#!/usr/bin/env python3
"""Witness generator for the C13-in-circuit statement.

Re-implements the SPHINCS- C13 verifier (SPHINCs-C13Asm.sol) in Python to
(a) check the fixture signature, (b) derive the per-layer `chain_hint`
(which WOTS chain each of the 93 hash steps belongs to), and (c) write
Prover.toml. Vector source: python/scripts/sphincs_c13_7913_demo.json —
`--vector raw|commit|pointer-raw|pointer-commit` selects which validated
(digest, sig) pair to prove (all share one key).

Usage: generate_prover.py [--vector raw] [-o Prover.toml]
"""

import argparse
import json
import pathlib

from Crypto.Hash import keccak

HERE = pathlib.Path(__file__).resolve().parent
FIXTURE = HERE.parents[1] / "python" / "scripts" / "sphincs_c13_7913_demo.json"
DOMAIN = b"pq-stealth/sphincs-c13/commit/v0"
N_MASK = (1 << 128) - 1 << 128


def kec(b: bytes) -> bytes:
    return keccak.new(digest_bits=256, data=b).digest()


def w(x: int) -> bytes:
    return x.to_bytes(32, "big")


def top(b16: bytes) -> bytes:
    return b16 + b"\x00" * 16


def adrs(layer, tree, typ, w1, w2, w3) -> bytes:
    return (layer.to_bytes(4, "big") + tree.to_bytes(12, "big") + typ.to_bytes(4, "big")
            + w1.to_bytes(4, "big") + w2.to_bytes(4, "big") + w3.to_bytes(4, "big"))


def th(seed, a, *payload) -> bytes:
    return kec(seed + a + b"".join(payload))[:16] + b"\x00" * 16


def verify_c13(pk_seed: bytes, pk_root: bytes, message: bytes, sig: bytes):
    """Returns (valid, hints) — hints = two lists of 93 chain indices."""
    assert len(sig) == 3688
    seed, root = pk_seed, pk_root
    r = top(sig[0:16])
    digest = kec(seed + root + r + message + b"\xff" * 32)
    dval = int.from_bytes(digest, "big")
    ht_idx = (dval >> 133) & 0x3FFFFF
    if (dval >> 114) & 0x7FFFF:
        return False, None
    idx_leaf0 = ht_idx & 0x7FF
    idx_tree0 = ht_idx >> 11

    roots = []
    for i in range(6):
        tree_idx = (dval >> (19 * i)) & 0x7FFFF
        secret = top(sig[16 + 16 * i:32 + 16 * i])
        node = th(seed, adrs(0, idx_tree0, 3, idx_leaf0, 0, (i << 19) | tree_idx), secret)
        path_idx = tree_idx
        auth = 128 + 304 * i
        for h in range(19):
            sib = top(sig[auth + 16 * h:auth + 16 * h + 16])
            parent = path_idx >> 1
            a = adrs(0, idx_tree0, 3, idx_leaf0, h + 1, (i << (18 - h)) | parent)
            l, rr = (sib, node) if path_idx & 1 else (node, sib)
            node = th(seed, a, l, rr)
            path_idx = parent
        roots.append(node)
    last = top(sig[16 + 96:16 + 112])
    roots.append(th(seed, adrs(0, idx_tree0, 3, idx_leaf0, 0, 6 << 19), last))
    current = th(seed, adrs(0, idx_tree0, 4, idx_leaf0, 0, 0), *roots)

    hints = []
    idx_tree = ht_idx
    sig_off = 1952
    for layer in range(2):
        idx_leaf = idx_tree & 0x7FF
        idx_tree >>= 11
        count_off = sig_off + 688
        count = int.from_bytes(sig[count_off:count_off + 4], "big")
        d = kec(seed + adrs(layer, idx_tree, 0, idx_leaf, 0, 0) + current + w(count))
        dv = int.from_bytes(d, "big")
        digits = [(dv >> (3 * i)) & 7 for i in range(43)]
        if sum(digits) != 208:
            return False, None
        vals = []
        hint = []
        for i in range(43):
            v = top(sig[sig_off + 16 * i:sig_off + 16 * i + 16])
            for step in range(7 - digits[i]):
                v = th(seed, adrs(layer, idx_tree, 0, idx_leaf, i, digits[i] + step), v)
                hint.append(i)
            vals.append(v)
        assert len(hint) == 93
        hints.append(hint)
        wots_pk = th(seed, adrs(layer, idx_tree, 1, idx_leaf, 0, 0), *vals)
        auth_off = count_off + 4
        node, m_idx = wots_pk, idx_leaf
        for h in range(11):
            sib = top(sig[auth_off + 16 * h:auth_off + 16 * h + 16])
            parent = m_idx >> 1
            a = adrs(layer, idx_tree, 2, 0, h + 1, parent)
            l, rr = (sib, node) if m_idx & 1 else (node, sib)
            node = th(seed, a, l, rr)
            m_idx = parent
        current = node
        sig_off = auth_off + 176
    return current == root, hints


def toml_bytes(name: str, b: bytes) -> str:
    return f"{name} = [{', '.join(str(x) for x in b)}]\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vector", default="raw",
                    choices=["raw", "commit", "pointer-raw", "pointer-commit"])
    ap.add_argument("-o", "--out", default=str(HERE / "Prover.toml"))
    ap.add_argument("--inputs", metavar="JSON",
                    help="prove an arbitrary instance instead of the fixture: JSON with "
                         "pk_seed, pk_root (32-B top-aligned hex), opener, message, sig "
                         "(3688-B hex) and optionally commitment to cross-check")
    args = ap.parse_args()

    hx = lambda s: bytes.fromhex(s.removeprefix("0x"))  # noqa: E731
    if args.inputs:
        inp = json.loads(pathlib.Path(args.inputs).read_text())
        pk_seed, pk_root = hx(inp["pk_seed"]), hx(inp["pk_root"])
        opener, message, sig = hx(inp["opener"]), hx(inp["message"]), hx(inp["sig"])
        valid, hints = verify_c13(pk_seed, pk_root, message, sig)
        assert valid, "signature does not verify against the given key"
        commitment = kec(DOMAIN + pk_seed[:16] + pk_root[:16] + opener)
        if "commitment" in inp:
            assert commitment == hx(inp["commitment"]), "commitment mismatch"
        write_prover(args.out, message, commitment, pk_seed, pk_root, opener, sig, hints)
        print(f"inputs={args.inputs} valid=True -> {args.out}")
        return

    fx = json.loads(FIXTURE.read_text())
    pk_seed, pk_root = hx(fx["pk_seed"]), hx(fx["pk_root"])
    opener = hx(fx["opener"])
    if args.vector == "raw":
        message, sig = hx(fx["challenge"]), hx(fx["sig"])
    elif args.vector == "commit":
        message, sig = hx(fx["challenge"]), hx(fx["commit_signature"])[64:]
    else:
        sub = fx["pointer"]["raw" if args.vector == "pointer-raw" else "commit"]
        message, sig = hx(sub["digest"]), hx(sub["sig"])
        if len(sig) == 3752:
            sig = sig[64:]

    valid, hints = verify_c13(pk_seed, pk_root, message, sig)
    assert valid, "fixture signature does not verify — port mismatch"
    pk = pk_seed[:16] + pk_root[:16]
    commitment = kec(DOMAIN + pk + opener)
    assert commitment == hx(fx["commitment"]), "commitment mismatch"
    write_prover(args.out, message, commitment, pk_seed, pk_root, opener, sig, hints)
    print(f"vector={args.vector} valid=True hints={[len(h) for h in hints]} -> {args.out}")


def write_prover(path, message, commitment, pk_seed, pk_root, opener, sig, hints) -> None:
    out = []
    out.append(f'message_hi = "0x{message[:16].hex()}"\n')
    out.append(f'message_lo = "0x{message[16:].hex()}"\n')
    out.append(f'commitment_hi = "0x{commitment[:16].hex()}"\n')
    out.append(f'commitment_lo = "0x{commitment[16:].hex()}"\n')
    out.append(toml_bytes("pk_seed", pk_seed[:16]))
    out.append(toml_bytes("pk_root", pk_root[:16]))
    out.append(toml_bytes("opener", opener))
    out.append(toml_bytes("sig", sig))
    out.append("chain_hint = [[" + ", ".join(map(str, hints[0])) + "], ["
               + ", ".join(map(str, hints[1])) + "]]\n")
    pathlib.Path(path).write_text("".join(out))


if __name__ == "__main__":
    main()
