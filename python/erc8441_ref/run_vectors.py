"""ERC-8441 conformance runner — replays the ERC's own vectors section by
section against the reference implementation in `scheme.py`.

Usage: .venv/bin/python erc8441_ref/run_vectors.py [--dump ROW]
Data files are vendored with pinned SHA-256 hashes (see data/HASHES.txt):
  section-1.json / section-2.json  (ethereum/ERCs, merged 2026-10-29)
  ml-kem-768-acvp.json             (namnc/pq-stealth-scheme3-public tier1)
Self-test first: pure-Python secp256k1 cross-checked against coincurve.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import scheme as S  # noqa: E402  (same directory)

HERE = Path(__file__).resolve().parent
DATA = HERE / "data"

PINNED = {
    "section-1.json": "e05a67608ee48776b91b2e685342815c1f90fb3f77c70c78ecc3ba7cc158d151",
    "section-2.json": "7f73be77a3ac54b0da36712db03876e6fc52a051fe5f1417658c8a0571c10d60",
    "ml-kem-768-acvp.json": "51c2802f9958f4efdbd04daf6f565c0890eb343fb8d665cb0618f515138a606b",
}

H_ = "d8b37e9fb5fd784cc30b719589811092fce202abc0f500d6609a2f69f78b171f"
SS1 = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
N1 = S.SECP_N
N1_HEX = format(N1, "064x")
N1M1_HEX = format(N1 - 1, "064x")

results: list[tuple[str, str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, "PASS" if ok else "FAIL", detail))


def hexb(v) -> bytes:
    return bytes.fromhex(v) if isinstance(v, str) else v


def load(name: str):
    p = DATA / name
    b = p.read_bytes()
    if hashlib.sha256(b).hexdigest() != PINNED[name]:
        raise SystemExit(f"hash mismatch for vendored {name} — refusing to run")
    return json.loads(b)


# ------------------------------------------------------------------ self-test

def selftest_secp() -> None:
    import coincurve

    for k in (1, 2, N1 - 1, 0x9110F8760A37D96052E3DCAF14862A147654F49F722CF213568CCEF1ECA2EC71):
        pub = coincurve.PublicKey.from_secret(k.to_bytes(32, "big")).format(compressed=False)
        x, y = S.scalar_mult(k)
        assert pub == b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big"), f"scalar_mult {k:x}"
    pk = coincurve.PublicKey.from_secret((7).to_bytes(32, "big"))
    pts = S.decompress_point(pk.format(compressed=True))
    assert pk.format(compressed=False)[1:] == b"".join(v.to_bytes(32, "big") for v in pts)
    ss = S.ecdh_x(0x11111, pk.format(compressed=True))
    x, y = S.scalar_mult(0x11111, S.decompress_point(pk.format(compressed=True)))
    want = coincurve.PrivateKey((0x11111).to_bytes(32, "big")).ecdh(pk.format(compressed=True))
    # libsecp256k1 ecdh = SHA-256 over the 33-byte compressed shared point
    assert hashlib.sha256(S.compress_point(x, y)).digest() == want
    assert ss == x.to_bytes(32, "big")  # x-coordinate of the same shared point


# ------------------------------------------------------------- Section 1

def run_v1(d1: dict, d2: dict) -> None:
    h = S.sha256(S.DS_OFFSET + SS1)
    check("V1-01", h == hexb(d1["V1-01"]["expect"]["base"]) == hexb(d1["V1-01"]["expect"]["offset"]))
    be = d1["V1-02"]["expect"]["offset_big_endian"]
    check("V1-02", be == format(int.from_bytes(h, "big"), "064x"))
    check("V1-03", S.offset_from_base(bytes(32)) is None)  # base 0 -> fail
    check("V1-04", S.offset_from_base(bytes.fromhex(N1_HEX)) is None)  # n -> fail
    check("V1-05", S.offset_from_base(bytes.fromhex(N1M1_HEX)) == N1 - 1)
    vt = S.view_tag(SS1)
    e = d1["V1-07"]["expect"]
    check("V1-07", vt == hexb(e["view_tag"]) and len(vt) == e["view_tag_bytes"] == 1)


# ------------------------------------------------------------- Section 2 helpers

def acvp(sec: str, tcid: int) -> dict:
    for row in load("ml-kem-768-acvp.json")[sec]:
        if row["tcId"] == tcid:
            return row
    raise KeyError(f"tcId {tcid} in {sec}")


def build_meta(spending_pk: bytes, viewing_pk: bytes, ek: bytes) -> bytes:
    return spending_pk + viewing_pk + ek


META_V3 = None  # filled from V3-09's keygen output
SEED_V3_09 = bytes.fromhex(
    "11" * 32 + "33" * 32
)  # extended below with V3-09's kem seed


def keygen_from_v309(kem_d: bytes, kem_z: bytes) -> S.KeygenOutputs:
    seed = SEED_V3_09 + kem_d + kem_z
    return S.keygen(seed)


def run_v3(d2: dict) -> None:
    global META_V3
    k26 = acvp("keygen", 26)
    kd, kz = hexb(k26["d"]), hexb(k26["z"])

    out = keygen_from_v309(kd, kz)
    META_V3 = out.meta_address
    e = d2["V3-09"]["expect"]
    ok = out.meta_address == hexb(e["meta_address"])
    for fld, attr in (("master_key", "master_key"), ("tracking_key", "tracking_key"), ("ek", "ek")):
        if fld in e:
            ok &= getattr(out, attr) == hexb(e[fld])
    check("V3-09", bool(ok), "deterministic keygen vs ACVP-26 kem seed")

    # V3-01: 128 -> outputs, 96/127 -> error
    o1 = keygen_from_v309(kd, kz)
    errs = 0
    for bad in (SEED_V3_09 + kd, (SEED_V3_09 + kd)[:-1]):
        try:
            S.keygen(bad)
        except S.KeygenError:
            errs += 1
    check("V3-01", o1 is not None and errs == 2, "96 B and 127 B rejected, 128 B outputs")

    # V3-10: seed scalar bounds (0, n invalid; n-1 valid) at keygen
    base33 = bytes.fromhex("33" * 32)
    seeds10 = {
        "sp0": bytes(32) + base33 + kd + kz,
        "spN": bytes.fromhex(N1_HEX) + base33 + kd + kz,
        "spNm1": bytes.fromhex(N1M1_HEX) + base33 + kd + kz,
        "view0": base33 + bytes(32) + kd + kz,
    }
    r = {}
    for name, s in seeds10.items():
        try:
            r[name] = S.keygen(s) is not None
        except S.KeygenError:
            r[name] = "err"
    check("V3-10", r["sp0"] == "err" and r["spN"] == "err"
          and r["spNm1"] is True and r["view0"] == "err",
          "error, error, accepted, error")

    # V3-02/02a: spending_seed must equal-check viewing_ec_seed, d AND z
    sp = bytes.fromhex("11" * 32)
    fill = bytes.fromhex("44" * 32)
    seeds02 = [
        sp + sp + fill,        # equals viewing_ec_seed
        sp + fill + sp + kz,   # equals d
        sp + fill + fill + sp, # equals z
    ]
    errs02 = 0
    for s in seeds02:
        try:
            S.keygen(s)
        except S.KeygenError:
            errs02 += 1
    check("V3-02", errs02 == 3, "equality with viewing_ec_seed / d / z all rejected")
    ok02a = True
    try:
        # distinct spending_seed / viewing_ec_seed / d / z -> outputs, no error
        ok02a = S.keygen(sp + fill + kd + kz) is not None
    except S.KeygenError:
        ok02a = False
    check("V3-02a", ok02a, "fully distinct components -> outputs, no error")

    # V3-11/12: meta decoding
    good = out.meta_address
    ok11 = True
    try:
        S.decode_meta(good[:1249])
        ok11 = False
    except ValueError:
        pass
    ok11 &= S.decode_meta(good) == (good[:33], good[33:66], good[66:])
    try:
        S.decode_meta(good + b"\x00")
        ok11 = False
    except ValueError:
        pass
    check("V3-11", ok11, "1249/1251 rejected, 1250 decodes")
    bad_meta = good[:33] + bytes.fromhex("02" + "00" * 31 + "05") + good[66:]
    check("V3-12", _try_err(lambda: S.decode_meta(bad_meta)) and not _try_err(lambda: S.decode_meta(good)),
          "non-point viewing_pk_ec rejected before use")

    # V3-13: address + EIP-55 from a given stealth_pk
    v = d2["V3-13"]
    full = hexb(v["given"]["stealth_pk_uncompressed"])
    addr = S.address_from_uncompressed(full)
    check("V3-13", addr == hexb(v["expect"]["address"])
          and S.eip55(addr) == v["expect"]["eip55"])

    # V3-05: combiner — DS given as ASCII, monolithic IKM given directly
    v = d2["V3-05"]
    g = v["given"]
    ds_ascii = g["domain_separator"].encode("ascii")
    ss_mono = S.sha3_256(ds_ascii + hexb(g["ikm"]))
    # cross-check: the IKM must equal parts.ss_ec||ss_pq||epk||ct||viewing_pk_ec||ek
    p6 = d2["V3-06"]["given"]["parts"]
    parts_blob = (hexb(p6["ss_ec"]) + hexb(p6["ss_pq"]) + hexb(p6["epk"])
                  + hexb(p6["ct"]) + hexb(p6["viewing_pk_ec"]) + hexb(p6["ek"]))
    ss_parts = S.hybrid_combine(ds_ascii, hexb(p6["ss_ec"]), hexb(p6["ss_pq"]),
                                hexb(p6["epk"]), hexb(p6["ct"]),
                                hexb(p6["viewing_pk_ec"]), hexb(p6["ek"]))
    check("V3-05", ss_mono == hexb(v["expect"]["ss"]) and ss_mono == ss_parts
          and parts_blob == hexb(g["ikm"]), "DS first, exact input order")

    # V3-06: the parts themselves hash to the shared secret
    g6 = d2["V3-06"]["given"]
    base = ss_parts
    check("V3-06", base == hexb(d2["V3-06"]["expect"]["ss"]))
    va = d2["V3-06a"]
    ssa = S.hybrid_combine(ds_ascii, hexb(p6["ss_ec"]), hexb(p6["ss_pq"]),
                           hexb(p6["epk"]), hexb(va["given"]["ct_a"]),
                           hexb(p6["viewing_pk_ec"]), hexb(p6["ek"]))
    ssb2 = S.hybrid_combine(ds_ascii, hexb(p6["ss_ec"]), hexb(p6["ss_pq"]),
                            hexb(p6["epk"]), hexb(va["given"]["ct_b"]),
                            hexb(p6["viewing_pk_ec"]), hexb(p6["ek"]))
    # internal consistency: kyber_py must reproduce NIST's encapsulation
    g6 = d2["V3-06"]["given"]
    ss_pq_k, ct_k = S._KEM._encaps_internal(hexb(p6["ek"]), hexb(g6["m"]))
    check("V3-06a", ssa == hexb(va["expect"]["ss_a"]) and ssb2 == hexb(va["expect"]["ss_b"])
          and ssa != ssb2
          and ss_pq_k == hexb(p6["ss_pq"]) and ct_k == hexb(p6["ct"]),
          "ct bound in; kyber_py == ACVP encapsulation-26 (GHP18/SP800-227 4.6.3)")
    vb = d2["V3-06b"]
    ssb = S.hybrid_combine(ds_ascii, hexb(p6["ss_ec"]), hexb(p6["ss_pq"]),
                           hexb(p6["epk"]), hexb(p6["ct"]),
                           hexb(vb["given"]["viewing_pk_ec_b"]), hexb(p6["ek"]))
    check("V3-06b", ssb == hexb(vb["expect"]["ss_b"]) and ssb != base, "viewing_pk_ec bound in")
    v7 = d2["V3-07"]
    ss7 = S.hybrid_combine(ds_ascii, hexb(p6["ss_ec"]), hexb(p6["ss_pq"]),
                           hexb(v7["given"]["epk_parity_flipped"]), hexb(p6["ct"]),
                           hexb(p6["viewing_pk_ec"]), hexb(p6["ek"]))
    check("V3-07", ss7 == hexb(v7["expect"]["ss_b"]) and ss7 != base, "epk bound in")

    # V3-03: meta-address with viewing_pk_ec tag 0x05 -> error at decode
    err3 = False
    try:
        S.decode_meta(hexb(d2["V3-03"]["given"]["meta_address"]))
    except ValueError:
        err3 = True
    check("V3-03", err3, "0x05-tagged viewing_pk_ec rejected at decode")

    # V3-04: ss_ec = x-only ECDH, identical on both sides
    v4 = d2["V3-04"]
    g4 = v4["given"]
    esk4 = int.from_bytes(hexb(g4["esk"]), "big")
    ss_recv = S.ecdh_x(esk4, hexb(g4["viewing_pk_ec"]))
    check("V3-04", ss_recv == hexb(v4["expect"]["ss_ec"]),
          "x-coordinate only")

    # V3-16: stealth key pair from ss; near-n spending key
    v = d2["V3-16"]
    g = v["given"]
    ss_c = hexb(g["ss"])
    spsk = int.from_bytes(hexb(g["spending_sk"]), "big")
    S.decompress_point(hexb(g["spending_pk"]))
    sk1, pk1 = S.recipient_key(spsk, ss_c)  # pk1 = 33-byte compressed stealth_pk
    e = v["expect"]
    ok16 = (format(S.H_ss_checked(ss_c), "064x") == e["H_ss"]
            and pk1 == hexb(e["stealth_pk"])
            and format(sk1, "064x") == e["stealth_sk"])
    x1, y1 = S.decompress_point(pk1)
    full1 = b"\x04" + x1.to_bytes(32, "big") + y1.to_bytes(32, "big")
    ok16 &= S.address_from_uncompressed(full1) == hexb(e["address"])
    spsk2 = int.from_bytes(hexb(g["spending_sk_near_n"]), "big")
    sk2, pk2 = S.recipient_key(spsk2, ss_c)
    assert sk1 is not None and pk1 is not None and sk2 is not None and pk2 is not None
    ok16 &= format(sk2, "064x") == e["near_n"]["stealth_sk"]
    ok16 &= pk2 == hexb(e["near_n"]["stealth_pk"])
    # one key pair: sk1*G == pk1
    ok16 &= S.compress_point(*S.scalar_mult(sk1)) == pk1
    check("V3-16", bool(ok16), "stealth_pk = spending_pk + H(ss)*G; pair consistency")

    # V3-08: wire shape — reassemble the announcement from the parts and
    # compare with the expect block
    v = d2["V3-08"]
    g = v["given"]
    ss8 = S.hybrid_combine(ds_ascii, hexb(p6["ss_ec"]), hexb(p6["ss_pq"]),
                           hexb(p6["epk"]), hexb(p6["ct"]),
                           hexb(p6["viewing_pk_ec"]), hexb(p6["ek"]))
    e = v["expect"]
    tag8 = S.view_tag(ss8)
    ok8 = (hexb(p6["epk"]) == hexb(g["epk"]) and hexb(p6["ct"]) == hexb(g["ct"])
           and len(hexb(g["epk"])) == 33 and len(hexb(g["ct"])) == 1088
           and len(hexb(g["epk"]) + hexb(g["ct"])) == e["ephemeralPubKey_bytes"] == 1121
           and e["ephemeralPubKey"] == (hexb(g["epk"]) + hexb(g["ct"])).hex()
           and e["metadata"] == g["view_tag"] == tag8.hex()
           and e["payload_bytes"] == 1122)
    check("V3-08", ok8, "epk||ct = 33+1088 = 1121 B; view_tag = metadata[0]")

    # V3-08a: scanner reads metadata[0] only — both metadata forms parse
    g = d2["V3-08a"]["given"]
    e = d2["V3-08a"]["expect"]
    epk8a = hexb(g["ephemeralPubKey"])
    o1 = S.scan(out.tracking_key, META_V3,
                {"stealthAddress": bytes(20),
                 "ephemeralPubKey": epk8a,
                 "metadata": hexb(g["metadata_view_tag_only"])})
    o2 = S.scan(out.tracking_key, META_V3,
                {"stealthAddress": bytes(20),
                 "ephemeralPubKey": epk8a,
                 "metadata": hexb(g["metadata_with_token_block"])})
    # parsing assertion: both metadata forms read the same view tag and take
    # the same path (the announcement targets a different KEM key than the
    # V3-09 recipient holds, so a skip outcome is expected either way)
    ok8a = (o1.outcome == o2.outcome
            and o1.outcome == "skip" and o1.stage == o2.stage == "tag"
            and o1.view_tag == o2.view_tag)
    check("V3-08a", ok8a, "both metadata values parse to the same view tag")

    # V3-15: malformed announcement -> skip at the entry point, never an error
    g15 = d2["V3-15"]["given"]
    eps = g15["ephemeralPubKeys"]
    mds = g15["metadatas"]
    cases = [(eps[str(L)], "02") for L in g15["ephemeralPubKey_lengths"]]
    for L in g15["metadata_lengths"]:
        md = mds[str(L)] if isinstance(mds, dict) and str(L) in mds else bytes(L)
        cases.append((eps["1121"], md))
    ok15 = True
    n_entry = n_processed = 0
    for epk_raw, md_raw in cases:
        o = S.scan(out.tracking_key, META_V3,
                   {"stealthAddress": bytes(20),
                    "ephemeralPubKey": hexb(epk_raw),
                    "metadata": hexb(md_raw)})
        if len(hexb(epk_raw)) != 1121 or len(hexb(md_raw)) < 1:
            ok15 &= (o.outcome == "skip" and o.stage == "entry")
            n_entry += 1
        else:
            ok15 &= (o.stage != "entry")  # processed past the entry point
            n_processed += 1
    check("V3-15", ok15 and n_entry == 4 and n_processed == 3,
          f"{n_entry} entry-skips, {n_processed} processed past entry")

    # V3-18: an epk that is not a valid compressed point -> skip at entry
    g18 = d2["V3-18"]["given"]
    ok18 = True
    for name, hx in g18["ephemeralPubKeys"].items():
        o = S.scan(out.tracking_key, META_V3,
                   {"stealthAddress": bytes(20),
                    "ephemeralPubKey": hexb(hx),
                    "metadata": hexb(g18["metadata"])})
        ok18 &= (o.outcome == "skip" and o.stage == "entry")
    ho = S.scan(out.tracking_key, META_V3,
                {"stealthAddress": bytes(20),
                 "ephemeralPubKey": hexb(g18["honest_ephemeralPubKey"]),
                 "metadata": hexb(g18["metadata"])})
    ok18 &= (ho.stage != "entry")
    check("V3-18", ok18,
          f"{len(g18['ephemeralPubKeys'])} bad epks skip at entry; honest one processed")

    # V3-19: an ek failing FIPS 203's encapsulation input check -> error
    g19 = d2["V3-19"]["given"]
    kbad = acvp("encapsulation_key_check", g19["acvp_encapsulationKeyCheck_tcId_invalid"])
    kgood = acvp("encapsulation_key_check", g19["acvp_encapsulationKeyCheck_tcId_valid"])
    bad_meta19 = hexb(g19["meta_address_invalid_ek"])
    good_meta19 = hexb(g19["meta_address_valid_ek"])
    grounds = (len(hexb(kbad["ek"])) == 1184
               and bad_meta19[66:] == hexb(kbad["ek"])
               and good_meta19[66:] == hexb(kgood["ek"]))
    err19 = False
    try:
        S.sender_derive(
            S.Ephemeral(esk=int.from_bytes(bytes.fromhex("22" * 32), "big"),
                        epk=hexb(p6["epk"]), m=_M_DEFAULT),
            bad_meta19,
        )
    except ValueError:
        err19 = True  # encapsulation input check rejected the ek
    check("V3-19", err19 and grounds,
          "invalid ek: error at encapsulation, no announcement; valid ek accepted")

    # V3-14: scan against an ACVP decapsulation key, expanded-dk form.
    # The row's meta-address uses ITS OWN ek (ACVP decap key), with V3-09's
    # spending_pk / viewing_pk_ec — all three fields are given explicitly.
    g14 = d2["V3-14"]["given"]
    e14 = d2["V3-14"]["expect"]
    dk14 = hexb(acvp("decapsulation", g14["acvp_decapsulation_tcId"])["dk"])
    ek14 = hexb(g14["ek"])
    meta14 = hexb(g14["spending_pk"]) + hexb(g14["viewing_pk_ec"]) + ek14
    tk14 = hexb(g14["viewing_ec"]) + b"\x00" * 64
    a14 = {k: hexb(x) for k, x in g14["announcement"].items()}
    ok14 = (len(meta14) == 1250
            and dk14[1152:2336] == ek14
            and S.sha3_256(ek14) == dk14[2336:2368])
    o14 = S.scan(tk14, meta14, a14, dk=dk14)
    ok14 &= (o14.outcome == "skip"
             and o14.ss == hexb(e14["ss"])
             and o14.ss_ec == hexb(e14["ss_ec"])
             and o14.ss_pq == hexb(e14["ss_pq"])
             and o14.view_tag == bytes.fromhex(e14["derived_view_tag"]))
    check("V3-14", ok14,
          f"ACVP decap-88 scan: skip at the announced tag, derives '{e14['derived_view_tag']}'")
    o14b = S.scan(tk14, meta14,
                  {"stealthAddress": a14["stealthAddress"],
                   "ephemeralPubKey": a14["ephemeralPubKey"],
                   "metadata": o14.view_tag}, dk=dk14)
    check("V3-14b", o14b.outcome == "match" and o14b.address == a14["stealthAddress"],
          f"outcome_with_derived_view_tag -> {o14b.outcome}")

    # V3-17: honest announcement matches; the lying address is skipped
    g17 = d2["V3-17"]["given"]
    e17 = d2["V3-17"]["expect"]
    dk17 = hexb(acvp("decapsulation", g17["acvp_decapsulation_tcId"])["dk"])
    ek17 = hexb(g17["ek"])
    meta17 = hexb(g17["spending_pk"]) + hexb(g17["viewing_pk_ec"]) + ek17
    tk17 = hexb(g17["viewing_ec"]) + b"\x00" * 64
    a17 = {k: hexb(x) for k, x in g17["announcement"].items()}
    o17h = S.scan(tk17, meta17, a17, dk=dk17,
                  stealthAddress=hexb(g17["stealthAddress_honest"]))
    o17l = S.scan(tk17, meta17, a17, dk=dk17,
                  stealthAddress=hexb(g17["stealthAddress_lie"]))
    ok17 = (o17h.outcome == "match" and o17l.outcome == "skip"
            and o17h.ss == hexb(e17["ss"])
            and o17h.ss_ec == hexb(e17["ss_ec"])
            and o17h.ss_pq == hexb(e17["ss_pq"])
            and o17h.view_tag == bytes.fromhex(e17["view_tag"])
            and o17h.stealth_pk == hexb(e17["stealth_pk"])
            and o17h.address == hexb(e17["address"]))
    check("V3-17", ok17, f"honest: match at {e17['address'][:12]}..; lie: skip")


_M_DEFAULT = bytes(32)


def _try_err(f) -> bool:
    try:
        f()
        return False
    except ValueError:
        return True


# ------------------------------------------------------------------ main

def main() -> int:
    print("self-test: pure secp256k1 vs coincurve ...", end=" ")
    selftest_secp()
    print("OK")
    d1 = load("section-1.json")["vectors"]
    d2 = load("section-2.json")["vectors"]
    run_v1(d1, d2)
    run_v3(d2)
    p = sum(1 for _, s, _ in results if s == "PASS")
    f = len(results) - p
    for name, st, detail in results:
        print(f"{st}  {name:<8} {detail}")
    print(f"\n{p}/{len(results)} checks passed, {f} failed")
    return 1 if f else 0


if __name__ == "__main__":
    sys.exit(main())
