import json, hashlib, scheme as S

d2 = json.load(open("data/section-2.json"))["vectors"]
d1 = json.load(open("data/section-1.json"))["vectors"]

# V1-02: types
print("V1-02 expect types:", {k: type(v).__name__ for k, v in d1["V1-02"]["expect"].items()})
print("V1-02 value:", d1["V1-02"]["expect"]["offset_big_endian"][:20], "...")

# V3-02a: control seed length
g02a = d2["V3-02a"]["given"]
print("\nV3-02a spending_seed bytes:", len(g02a["spending_seed"]) // 2,
      "| delegated bytes:", len(g02a["delegated"]) // 2)
try:
    S.keygen(bytes.fromhex(g02a["spending_seed"]) + bytes.fromhex(g02a["delegated"]))
    print("V3-02a keygen: OK")
except S.KeygenError as e:
    print("V3-02a keygen ERROR:", e)

# V3-05/06/06a/06b: full expected values + my computations
p6 = d2["V3-06"]["given"]["parts"]
ds = b"pq-stealth/hybrid-payment/v1"
def comb(ct, vpk, ek=None, epk=None, ssec=None, sspq=None):
    return S.sha3_256(ds + (ssec or bytes.fromhex(p6["ss_ec"])) + (sspq or bytes.fromhex(p6["ss_pq"]))
                      + (epk or bytes.fromhex(p6["epk"])) + ct + vpk
                      + (ek or bytes.fromhex(p6["ek"])))
ct6, vpk6, ek6 = bytes.fromhex(p6["ct"]), bytes.fromhex(p6["viewing_pk_ec"]), bytes.fromhex(p6["ek"])
base = comb(ct6, vpk6)
print("\nV3-05 expect.ss      :", d2["V3-05"]["expect"]["ss"])
print("V3-06 expect.ss      :", d2["V3-06"]["expect"]["ss"])
print("V3-06a expect.ss_a   :", d2["V3-06a"]["expect"].get("ss_a"))
print("V3-06b expect.ss_b   :", d2["V3-06b"]["expect"].get("ss_b"))
print("my base              :", base.hex())
print("ct_a == ct6          :", bytes.fromhex(d2["V3-06a"]["given"]["ct_a"]) == ct6,
      "| cta tail:", d2["V3-06a"]["given"]["ct_a"][-16:], "ct6 tail:", p6["ct"][-16:])
ssa = comb(bytes.fromhex(d2["V3-06a"]["given"]["ct_a"]), vpk6)
print("my ss_a (ct_a)       :", ssa.hex())
# maybe 06a binds pk_b too? try viewing_pk variant
ssab = comb(bytes.fromhex(d2["V3-06a"]["given"]["ct_a"]), bytes.fromhex(d2["V3-06b"]["given"]["viewing_pk_ec_b"]))
print("my ss(ct_a,vpk_b)    :", ssab.hex())

# V3-16 near_n: exact expect
print("\nV3-16 expect.near_n  :", json.dumps(d2["V3-16"]["expect"].get("near_n")))
print("V3-16 expect.H_ss    :", d2["V3-16"]["expect"]["H_ss"])
h16 = S.sha256(b"pq-stealth/offset/v1" + bytes.fromhex(d2["V3-16"]["given"]["ss"]))
print("my H(V3-16 ss)       :", h16.hex())
sk2 = (int.from_bytes(bytes.fromhex(d2["V3-16"]["given"]["spending_sk_near_n"]), "big") + int.from_bytes(h16, "big")) % S.SECP_N
print("my near_n stealth_sk :", format(sk2, "064x"))

# V3-15: metadatas shape
g15 = d2["V3-15"]["given"]
print("\nV3-15 metadatas:", {k: (len(v) // 2 if isinstance(v, str) else v) for k, v in g15["metadatas"].items()})
print("V3-15 metadata hexes:", {k: (v[:12] if isinstance(v, str) else v) for k, v in g15["metadatas"].items()})
print("V3-15 fields_are:", g15.get("fields_are"))

# V3-08a: what does the scan actually see?
g08a = d2["V3-08a"]["given"]
ekct = bytes.fromhex(g08a["ephemeralPubKey"])
print("\nV3-08a epk==p6.epk:", ekct[:33] == bytes.fromhex(p6["epk"]), "| ct==p6.ct:", ekct[33:] == ct6)
