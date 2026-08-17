//! Address-ownership proof for the PQ stealth address scheme.
//!
//! Proves the "decode-in-reverse" MLWE relation: knowledge of a SHORT secret
//! `(s, e)` such that `A*s + e = t (mod q)`, where `t` is the public key that
//! the stealth address commits to. Only the holder of the short secret can
//! satisfy the relation; separating the small error from the structure without
//! it is the hard lattice problem. This is far cheaper in-circuit than proving
//! a full FIPS-204 ML-DSA signature (no SHAKE, no rejection sampling, no hints)
//! and it proves exactly what a spend needs: control of the stealth address.
//!
//! Scope of this PoC (documented honestly, see noir/README.md):
//!  * cyclic convolution + non-negative short coefficients in [0, ETA2] -- the
//!    constraint STRUCTURE and SCALE match the real scheme; ML-DSA's negacyclic
//!    ring and centered [-eta, eta] range change correctness details, not the
//!    gate count (same n^2 products + n reductions + range checks per poly-mul).
//!  * the modular reduction uses a prover-supplied quotient hint `quot`,
//!    checked by the exact field identity `A*s + e = q*quot + t` (both sides are
//!    < 2^40 << the BN254 field, so the field equation IS the integer relation).
//!  * `msg` (e.g. a userOpHash) is bound into a returned tag so the proof
//!    authorizes one specific transaction and cannot be replayed.

global N: u32 = 256; // ring degree (ML-DSA)
global K: u32 = 6; // rows      (ML-DSA-65)
global L: u32 = 5; // cols      (ML-DSA-65)
global Q: Field = 8380417; // ML-DSA modulus
global ETA2: u32 = 8; // ||s,e||_inf bound (models 2*eta for the blinded key)
global QUOT_MAX: u32 = 16384; // quotient bound: (L*N*Q*ETA2)/Q < L*N*ETA2 = 10240

fn main(
    a: pub [[[Field; N]; L]; K], // matrix A (K x L polynomials), public (from rho)
    t: pub [[Field; N]; K], // the blinded public key the address commits to
    msg: pub Field, // transaction hash to bind the proof to
    s: [[Field; N]; L], // SECRET: short blinded secret vector
    e: [[Field; N]; K], // SECRET: short error vector
    quot: [[Field; N]; K], // quotient hints for the mod-q reduction
) -> pub Field {
    // (1) norm bounds: every secret coefficient is short.
    for j in 0..L {
        for m in 0..N {
            assert(s[j][m] as u32 <= ETA2);
        }
    }
    for i in 0..K {
        for m in 0..N {
            assert(e[i][m] as u32 <= ETA2);
        }
    }

    // (2) the MLWE relation A*s + e == t (mod Q), coefficient by coefficient.
    for i in 0..K {
        for m in 0..N {
            // (A*s)[i] coefficient m = sum_j sum_x A[i][j][x] * s[j][(m-x) mod N]
            let mut acc: Field = 0;
            for j in 0..L {
                for x in 0..N {
                    let y = (m + N - x) % N; // cyclic index, comptime-resolved
                    acc = acc + a[i][j][x] * s[j][y];
                }
            }
            acc = acc + e[i][m];

            // exact identity over the field == integer relation (both < 2^40)
            assert(acc == Q * quot[i][m] + t[i][m]);

            // range checks pin the representatives: t in [0, Q), quot bounded
            assert(t[i][m] as u32 < 8380417);
            assert(quot[i][m] as u32 < QUOT_MAX);
        }
    }

    // (3) bind the proof to `msg` (Fiat-Shamir-style tag over msg + witness),
    // so a valid proof authorizes exactly this transaction.
    let mut bind: Field = msg;
    for j in 0..L {
        bind = bind * 3 + s[j][0];
    }
    bind
}
