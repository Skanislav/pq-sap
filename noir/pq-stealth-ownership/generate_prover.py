#!/usr/bin/env python3
"""Generate a valid witness (Prover.toml) for the ownership circuit.

Produces a self-consistent instance matching the circuit's cyclic,
non-negative arithmetic: random public A, short secret (s, e), and the
derived public t plus quotient hints, so A*s + e = q*quot + t holds exactly.

Usage: generate_prover.py N K L [ETA2]  (defaults 256 6 5 8)
"""

import sys
import secrets

Q = 8380417
N = int(sys.argv[1]) if len(sys.argv) > 1 else 256
K = int(sys.argv[2]) if len(sys.argv) > 2 else 6
L = int(sys.argv[3]) if len(sys.argv) > 3 else 5
ETA2 = int(sys.argv[4]) if len(sys.argv) > 4 else 8

rnd = secrets.SystemRandom()

A = [[[rnd.randrange(Q) for _ in range(N)] for _ in range(L)] for _ in range(K)]
s = [[rnd.randint(0, ETA2) for _ in range(N)] for _ in range(L)]
e = [[rnd.randint(0, ETA2) for _ in range(N)] for _ in range(K)]
msg = rnd.randrange(Q * 1000)

t = [[0] * N for _ in range(K)]
quot = [[0] * N for _ in range(K)]
for i in range(K):
    for m in range(N):
        acc = 0
        for j in range(L):
            for x in range(N):
                y = (m + N - x) % N
                acc += A[i][j][x] * s[j][y]
        acc += e[i][m]
        quot[i][m], t[i][m] = divmod(acc, Q)


def poly(v):
    return "[" + ", ".join(f'"{c}"' for c in v) + "]"


def mat2(v):
    return "[" + ", ".join(poly(row) for row in v) + "]"


def mat3(v):
    return "[" + ", ".join(mat2(rows) for rows in v) + "]"


with open("Prover.toml", "w") as f:
    f.write(f'msg = "{msg}"\n')
    f.write(f"a = {mat3(A)}\n")
    f.write(f"t = {mat2(t)}\n")
    f.write(f"s = {mat2(s)}\n")
    f.write(f"e = {mat2(e)}\n")
    f.write(f"quot = {mat2(quot)}\n")

print(f"wrote Prover.toml for N={N} K={K} L={L} ETA2={ETA2}")
