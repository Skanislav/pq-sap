#!/usr/bin/env python3
"""Witness generator for the preimage-ownership statement (D-025).

Given the spending secret, the opener and the message, checks the commitment
in Python (`pq_stealth.commit` with PREIMAGE_DOMAINS) and writes Prover.toml.

Usage: generate_prover.py [--sk HEX] [--opener HEX] [--message HEX] [-o Prover.toml]
Defaults: the demo secret from `spend_seed = 0x81*32`, the D-018 fixture's
demo shared secret for the opener, and the fixture challenge as the message.
"""

import argparse
import hashlib
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "python"))

from pq_stealth.commit import (  # noqa: E402
    PREIMAGE_DOMAINS,
    derive_commitment,
    derive_opener,
    spend_key_from_secret,
)

FIXTURE = ROOT / "python" / "scripts" / "sphincs_c13_7913_demo.json"
KEYGEN_DOMAIN = b"pq-stealth/preimage/keygen/v0"


def demo_secret(seed: bytes) -> bytes:
    return hashlib.sha256(KEYGEN_DOMAIN + seed).digest()


def toml_bytes(name: str, b: bytes) -> str:
    return f"{name} = [{', '.join(str(x) for x in b)}]\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sk")
    ap.add_argument("--opener")
    ap.add_argument("--ss", help="derive the opener from this shared secret")
    ap.add_argument("--message")
    ap.add_argument("-o", "--out", default=str(HERE / "Prover.toml"))
    args = ap.parse_args()
    hx = lambda s: bytes.fromhex(s.removeprefix("0x"))  # noqa: E731

    fx = json.loads(FIXTURE.read_text())
    sk = hx(args.sk) if args.sk else demo_secret(b"\x81" * 32)
    if args.opener:
        opener = hx(args.opener)
    else:
        ss = hx(args.ss) if args.ss else hx(fx["shared_secret_DEMO_ONLY"])
        opener = derive_opener(ss, PREIMAGE_DOMAINS)
    message = hx(args.message) if args.message else hx(fx["challenge"])

    spend_key = spend_key_from_secret(sk)
    commitment = derive_commitment(spend_key, opener, PREIMAGE_DOMAINS)

    out = [
        f'message_hi = "0x{message[:16].hex()}"\n',
        f'message_lo = "0x{message[16:].hex()}"\n',
        f'commitment_hi = "0x{commitment[:16].hex()}"\n',
        f'commitment_lo = "0x{commitment[16:].hex()}"\n',
        toml_bytes("sk", sk),
        toml_bytes("opener", opener),
    ]
    pathlib.Path(args.out).write_text("".join(out))
    print(
        f"spend_key=0x{spend_key.hex()} commitment=0x{commitment.hex()} "
        f"message=0x{message.hex()} -> {args.out}"
    )


if __name__ == "__main__":
    main()
