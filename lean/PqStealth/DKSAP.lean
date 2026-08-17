/-
DKSAP (the deployed elliptic-curve stealth scheme) and its total break under a
discrete-log oracle.

DKSAP is scheme 1 of ERC-5564: the SECP256K1 dual-key stealth address protocol,
the only stealth scheme actually deployed today and the baseline this project
measures against. It is modelled here as an instance of the same
`StealthScheme` abstraction used for the ML-KEM construction, so the two live
in one framework and the comparison is structural rather than rhetorical.

## What is proved

  1. `dksap_perfectlyComplete` -- the instance really is DKSAP: a recipient
     always detects a payment addressed to them (this is what rules out a
     vacuous model).
  2. `dksap_recover_eq_honest` -- an adversary holding the discrete logs of the
     PUBLISHED meta-address recomputes the recipient's honest stealth spending
     key exactly.
  3. `dksap_key_recovery` -- that recovered scalar is a valid secret key for
     the announced stealth public key.

## Why this is stated as key recovery, not as forgery

The question this answers is "is DKSAP forgeable by a quantum adversary". The
answer is stronger than forgeability: the adversary recovers the actual signing
key, and key recovery implies UNIVERSAL forgery (sign anything, spend
anything). Stating it that way also keeps the result equational -- there is no
probability slack anywhere below. Phrasing it instead as a distinguishing game
("advantage = 1") would be strictly weaker AND harder, since it would inherit
an address-collision term.

## What the discrete-log oracle abstracts, and what it does not

Shor's algorithm is not formalized here, and cannot be: the verification
framework this project builds on models classical probabilistic computation
only (no quantum computation, no QROM), and carries no elliptic curves at all.
What Shor CONTRIBUTES to this attack, though, is exactly one thing -- discrete
logarithms become computable -- and that is what is assumed below, in the
standard way, by taking the oracle's answers as hypotheses (`xM • g = M`).
Every step after that is ordinary algebra. So this is a proof about a scheme
relative to an assumption about the adversary, NOT a proof about a quantum
algorithm.

The load-bearing premise is that the meta-address is PUBLISHED (ERC-6538
registers `(M, V)` on-chain). An unpublished meta-address leaves an unspent
stealth address protected by hash preimage resistance -- though any output that
has been spent exposes its public key and falls anyway.

## Honest scope of the contrast with the ML-KEM scheme

The ML-KEM construction in this development contains no group element, so this
adversary gains nothing against it. That is an asymmetry, and it is NOT proved
here to be a separation: relative to a discrete-log oracle, the hardness of the
lattice assumptions is an ASSUMPTION, not a theorem. The honest statement is
that the DKSAP break below is unconditional given the oracle, while the ML-KEM
bounds hold under assumptions that the oracle is not known to affect.

Two further scope notes. The break concerns the key exchange and the spending
key derived from it; it says nothing about how value is spent in practice
today, where the accompanying design still relies on a classical
account-abstraction route. And the two consequences differ in urgency:
deanonymization is retroactive (announcements recorded now can be opened
later), whereas theft requires the funds to still be there when the capability
exists.
-/

import PqStealth.Games

open OracleComp OracleSpec

namespace PqStealth

/-! ## The group model

Matches VCVio's `DiffieHellman` file: `F` is the scalar field (exponents), `G`
the group (elliptic curve points), and `a • g` is the additive rendering of
`g^a`. Keeping the group abstract is deliberate -- the attack uses only the
group law, so nothing depends on the curve. -/

variable {F : Type} [Field F] {G : Type} [AddCommGroup G] [Module F G]

/-- The Diffie-Hellman step: sender and recipient reach the same scalar because
`r • (v • g) = v • (r • g)`. This is the identity the whole scheme rests on,
and also the reason the attack works once `v` is known. -/
theorem dksap_derivation_agrees (g : G) (h : G → F) (m v r : F) :
    (m • g) + (h (r • (v • g))) • g = (m + h (v • (r • g))) • g := by
  rw [add_smul, smul_smul, smul_smul, mul_comm]

/-! ## The scheme

`g` is the generator and `h : G -> F` abstracts the hash that turns the shared
secret point into a scalar. A recipient holds `(m, v)`, publishing
`(M, V) = (m • g, v • g)`: `m` is the spending key, `v` the viewing key. -/

section Scheme

variable [SampleableType F] [DecidableEq G] (g : G) (h : G → F)

/-- DKSAP as a stealth scheme. The announcement is the pair `(R, P)` of
ephemeral public key and stealth public key; `P` stands in for the on-chain
address, whose hashing is irrelevant to everything proved here.

Sender: draw an ephemeral `r`, publish `R = r • g`, and derive the stealth key
`P = M + h(r • V) • g`. Recipient: recompute the same scalar as `h(v • R)` and
check the resulting key against `P`. -/
def dksap : StealthScheme (G × G) (F × F) (G × G) where
  keygen := do
    let m ← ($ᵗ F)
    let v ← ($ᵗ F)
    pure ((m • g, v • g), (m, v))
  announce MV := do
    let r ← ($ᵗ F)
    pure (r • g, MV.1 + (h (r • MV.2)) • g)
  scan mv Rp := pure (decide (Rp.2 = (mv.1 + h (mv.2 • Rp.1)) • g))

/-- **Detection completeness.** A recipient always detects an announcement
addressed to them: every run of the completeness experiment returns `true`,
because the two derivations of the shared scalar agree. -/
theorem dksap_perfectlyComplete : (dksap g h).PerfectlyComplete := by
  simp [StealthScheme.PerfectlyComplete, StealthScheme.CorrectExp, dksap,
    dksap_derivation_agrees]

end Scheme

/-! ## Key recovery from the published meta-address

The adversary is given the discrete logs of the published `(M, V)` -- that is
the entire effect of the oracle -- and reconstructs the recipient's one-time
spending key for any announcement. -/

section KeyRecovery

variable (h : G → F) (g : G)

/-- What the adversary computes: the spending scalar of the announcement `R`,
from the two recovered discrete logs. No secret of the recipient is used. -/
def recover (xM xV : F) (R : G) : F := xM + h (xV • R)

/-- Injectivity of `x |-> x • g` says the generator's orbit hits each point
once, so a discrete log pins down the exact scalar rather than merely some
scalar with the same image. It holds in the prime-order group DKSAP is
instantiated over (`F = ZMod p`). It is genuinely needed: the recovered viewing
scalar is fed to `h`, so an answer that is only correct up to the group law
would derive a different shared secret. VCVio assumes the sibling condition
`Function.Bijective (· • g)` in the same situation. -/
theorem dksap_recover_eq_honest
    (hinj : Function.Injective (fun x : F => x • g))
    (m v xM xV : F) (hM : xM • g = m • g) (hV : xV • g = v • g) (R : G) :
    recover h xM xV R = m + h (v • R) := by
  rw [recover, hinj hM, hinj hV]

/-- **The break.** Given only the published meta-address `(M, V) = (m • g, v • g)`,
their discrete logs, and an announcement `(R, P)` addressed to that recipient,
the adversary outputs a scalar that is a valid secret key for the announced
stealth public key `P`. Since the recovered scalar is the recipient's own
spending key (`dksap_recover_eq_honest`), the adversary can produce every
signature the recipient could: key recovery, hence universal forgery. -/
theorem dksap_key_recovery
    (hinj : Function.Injective (fun x : F => x • g))
    (m v r xM xV : F) (hM : xM • g = m • g) (hV : xV • g = v • g) :
    (recover h xM xV (r • g)) • g = (m • g) + (h (r • (v • g))) • g := by
  rw [dksap_recover_eq_honest h g hinj m v xM xV hM hV, dksap_derivation_agrees]

end KeyRecovery

end PqStealth
