import hashlib
import json

acvp = json.load(open("data/ml-kem-768-acvp.json"))
for tcid in (86, 88):
    row = next(r for r in acvp["decapsulation"] if r["tcId"] == tcid)
    dk = bytes.fromhex(row["dk"])
    sec2 = json.load(open("data/section-2.json"))["vectors"]
    gkey = "V3-17" if tcid == 86 else "V3-14"
    gk = sec2[gkey]["given"]
    ekv = bytes.fromhex(gk["ek"])
    print(f"tcId {tcid}: dk len {len(dk)} (expect 2400), ek given len {len(ekv)}")
    print(f"  dk[1152:2336] == ek : {dk[1152:2336] == ekv}")
    h_ek = hashlib.sha256(ekv).digest()
    print(f"  sha256(ek)==dk[2336:2368]: {h_ek == dk[2336:2368]}")
    h_ek2 = hashlib.sha256(dk[1152:2336]).digest()
    print(f"  sha256(dk[1152:2336])==dk[2336:2368]: {h_ek2 == dk[2336:2368]}")
    # where does the given ek live in dk?
    idx = dk.find(ekv)
    print(f"  given ek found in dk at offset: {idx}")
