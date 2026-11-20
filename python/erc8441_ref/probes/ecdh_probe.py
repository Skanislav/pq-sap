import hashlib

import coincurve
import scheme as S

pk = coincurve.PublicKey.from_secret((7).to_bytes(32, "big"))
priv = coincurve.PrivateKey((0x11111).to_bytes(32, "big"))
want = priv.ecdh(pk.format(compressed=True))

# independent anchor: (0x11111 * 7) * G must equal 0x11111 * (7G)
k_prod = (0x11111 * 7) % S.SECP_N
anch = coincurve.PublicKey.from_secret(k_prod.to_bytes(32, "big")).format(
    compressed=False
)
x, y = S.scalar_mult(0x11111, S.decompress_point(pk.format(compressed=True)))
X = x.to_bytes(32, "big")
mine_un = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
print("anchor check:", anch == mine_un)

comp = S.compress_point(x, y)  # 33 bytes with tag
cands = {
    "ctr1||x||comp33": b"\x00\x00\x00\x01" + X + comp,
    "ctr1||comp33||x": b"\x00\x00\x00\x01" + comp + X,
    "x||comp33": X + comp,
    "comp33": comp,
    "x": X,
    "ctr1||comp33||y": b"\x00\x00\x00\x01" + comp + y.to_bytes(32, "big"),
}
for name, buf in cands.items():
    d = hashlib.sha256(buf).digest()
    print(("MATCH " if d == want else "no    ") + name)
print("want:", want.hex()[:16])
