"""Replay the classical-spend hybrid conformance vectors.

Loads vectors/classical/v0/vectors.json and re-derives every case through
the library: the independent-implementation check. A second implementation
in any language must reproduce these same outputs from the same seeds.
"""

import json
import pathlib

import pytest

pytest.importorskip("coincurve")  # the classical scheme needs the bench extra

from coincurve import PublicKey  # noqa: E402

from pq_stealth.classical import (  # noqa: E402
    check_announcement, decode_meta_address, eth_address,
    Announcement, MetaPublic, DEFAULT,
)

VECTORS = (pathlib.Path(__file__).parent.parent
           / "vectors" / "classical" / "v0" / "vectors.json")


def unhx(s: str) -> bytes:
    return bytes.fromhex(s[2:])


@pytest.fixture(scope="module")
def doc():
    return json.loads(VECTORS.read_text())


def test_header_matches_params(doc):
    assert doc["schema"] == "v0"
    assert doc["params"] == DEFAULT.name
    assert doc["view_tag_bytes"] == DEFAULT.view_tag_bytes
    assert doc["sizes"]["meta_address"] == DEFAULT.meta_address_bytes
    assert doc["sizes"]["ephemeral_pub_key"] == DEFAULT.kem_ct_bytes


def test_every_case_replays(doc):
    pubs, dks = {}, {}
    for name, rec in doc["recipients"].items():
        spend_pub, ek = decode_meta_address(unhx(rec["meta_address"]), DEFAULT)
        pubs[name] = MetaPublic(spend_pub, ek, DEFAULT)
        dks[name] = unhx(rec["kem_dk"])

    seen = 0
    for case in doc["cases"]:
        a = case["announcement"]
        ann = Announcement(unhx(a["stealth_address"]),
                           unhx(a["ephemeral_pub_key"]), unhx(a["view_tag"]))
        r = case["recipient"]
        payment = check_announcement(pubs[r], dks[r], ann)

        if case["expect"] == "match":
            assert payment is not None, case["name"]
            assert payment.stealth_address == ann.stealth_address, case["name"]
        elif case["expect"] == "no_match":
            assert payment is None, case["name"]
        elif case["expect"] == "valid_proof":
            assert payment is not None, case["name"]
            recovered = PublicKey.from_signature_and_message(
                unhx(case["signature"]), unhx(case["challenge"]), hasher=None)
            assert eth_address(recovered) == ann.stealth_address, case["name"]
        else:
            raise AssertionError(f"unknown expect: {case['expect']}")
        seen += 1

    assert seen == len(doc["cases"]) > 0


def test_second_payment_is_unlinkable(doc):
    addrs = [c["announcement"]["stealth_address"]
             for c in doc["cases"] if c["expect"] == "match"]
    assert len(addrs) == len(set(addrs)), "matched addresses must be distinct"
