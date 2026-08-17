# Noir PoC — address-ownership proof (decode-in-reverse MLWE)

Proof of concept for the **application-layer ZK** direction of the scheme:
prove control of a stealth address by proving the *MLWE decode-in-reverse
relation* — knowledge of a **short** secret `(s, e)` with `A·s + e = t (mod q)`
— instead of proving a full FIPS-204 ML-DSA signature. This is exactly what a
spend needs (control of the address), and it skips the parts of signature
verification that are murderous in-circuit (SHAKE hashing, rejection sampling,
hints).

Circuit: `src/main.nr`. Witness generator: `generate_prover.py`.

## Verified end to end

At a toy size (N=8, K=2, L=2) the full flow runs with Barretenberg
(UltraHonk): `nargo execute` solves the witness, `bb prove` produces a proof,
and `bb verify` returns **"Proof verified successfully."** The message `msg`
(a userOpHash) is folded into a returned binding tag, so a proof authorizes
exactly one transaction.

## Constraint counts (measured)

| Config | K·L poly-muls | ACIR opcodes | Backend gates |
|---|---|---|---|
| toy — N=8, K=2, L=2 | 4 | 977 | 5,834 |
| unit — N=256, K=1, L=1 | 1 | 15,617 | 102,538 |
| **ML-DSA-65 — N=256, K=6, L=5** | 30 | 89,857 | **2,168,651** |

The count is dominated by the schoolbook convolution (K·L·N² ≈ 2M
multiply-adds). Two things bring a production circuit far below this:

- **NTT domain.** Doing `A·s` as pointwise products on NTT-transformed
  operands turns each poly-mul from O(N²)=65,536 into O(N log N)≈2,048 — a
  ~32× cut on the dominant term, projecting to **~100–200k gates**. (Not
  implemented here; the schoolbook version is simpler and its gate count is
  an honest upper bound.)
- **A is public.** The verifier never recomputes `A` from `rho` in-circuit;
  it's a public input, so ExpandA's SHAKE cost stays out of the circuit
  entirely.

**Why this matters:** proving full ML-DSA *verification* in-circuit is
dominated by SHAKE (ExpandA hashes the whole K×L×N matrix; the challenge and
sample-in-ball hash more), which runs to millions–tens-of-millions of gates on
its own. The decode-in-reverse relation avoids all of it. This PoC is the
evidence that the ownership statement is cheap enough to be practical — the
number the spec needs to justify the Direction-A (gas/privacy) scheme variant.

## Honest scope of this PoC

The constraint *structure and scale* match the real scheme; a production
circuit differs in details that change correctness, not gate count:

- **Cyclic, not negacyclic.** Real ML-DSA is `Z_q[X]/(X²⁵⁶+1)` (sign flip on
  wrap-around). This PoC uses plain cyclic convolution to keep the arithmetic
  sign-clean. Same N² product structure.
- **Non-negative range, not centered.** Coefficients are checked in `[0, 2η]`
  rather than `[-η, η]`. Same number of range checks.
- **Quotient-hint reduction.** `mod q` is enforced by the exact field identity
  `A·s + e = q·quot + t` with a prover-supplied `quot` (both sides < 2⁴⁰ ≪ the
  BN254 field, so the field equation *is* the integer relation).
- **Soundness of the proof itself is the backend's.** UltraHonk (BN254) is
  **not** post-quantum. Proving a lattice statement with a classical SNARK
  gives a classically-sound proof — see `docs/DECISIONS.md` (D-007): genuine PQ
  soundness needs a FRI/STARK or lattice backend, which is the frontier, not
  this PoC.

## Run

```sh
# toy config: fast prove + verify (edit globals N=8,K=2,L=2 in src/main.nr)
python3 generate_prover.py 8 2 2 8
nargo execute
bb write_vk -b target/pq_stealth_ownership.json -o target
bb prove   -b target/pq_stealth_ownership.json -w target/pq_stealth_ownership.gz -o target
bb verify  -k target/vk -p target/proof -i target/public_inputs

# full ML-DSA-65 gate count (globals N=256,K=6,L=5)
python3 generate_prover.py 256 6 5 8
nargo compile
bb gates -b target/pq_stealth_ownership.json
```
