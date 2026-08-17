/-
A concrete, RUNNABLE instantiation of the DKSAP model.

Everything else in this development is abstract: the group `G`, the scalar
field `F` and the hash `h` are type variables, which is what makes the theorems
apply to any curve. The cost is that nothing can be executed and inspected.

This module fixes a tiny concrete instance so the scheme -- and the key-recovery
attack against it -- can actually be RUN with `#eval`. It is a sanity check on
the model and an entry point for reading the development, not a cryptographic
instantiation: the group here is the additive group of `ZMod 23`, in which
discrete logarithms are just division. That is precisely why the attack is
executable here, and it is also why this instance offers no security whatsoever.

The point being demonstrated: the abstract theorem `dksap_key_recovery`, applied
to these concrete numbers, says the recovered scalar is the recipient's actual
spending key -- and you can watch that happen.
-/

import PqStealth.DKSAP
import Mathlib.Algebra.Field.ZMod
import Mathlib.Tactic.NormNum.Prime

namespace PqStealth.Demo

open PqStealth

/-! ## A tiny field and a generator -/

instance : Fact (Nat.Prime 23) := ⟨by norm_num⟩

/-- Scalars and group elements both live in `ZMod 23`, viewed as a module over
itself: `x • g` is ordinary multiplication. -/
abbrev F := ZMod 23

/-- The generator. Any nonzero element works. -/
def gen : F := 5

/-- The hash carrying a shared secret point to a scalar. Any function of the
right type is allowed by the model; this one is deliberately silly, which is
part of the point -- the attack does not care what `h` is. -/
def hash (x : F) : F := 7 * x + 3

/-- The generator is nondegenerate, which is the hypothesis the key-recovery
theorem needs. In a field, `x |-> x * gen` is injective exactly when `gen` is
nonzero. -/
theorem gen_injective : Function.Injective (fun x : F => x • gen) := by
  simpa [smul_eq_mul] using mul_left_injective₀ (b := gen) (by decide)

/-! ## One recipient, one payment -/

/-- Recipient's spending secret. -/
def m : F := 9
/-- Recipient's viewing secret. -/
def v : F := 4
/-- Sender's ephemeral secret. -/
def r : F := 3

/-- Published meta-address: the spending public key. -/
def M : F := m • gen
/-- Published meta-address: the viewing public key. -/
def V : F := v • gen
/-- Announced ephemeral public key. -/
def R : F := r • gen
/-- Announced stealth public key, as the sender computes it. -/
def P : F := M + (hash (r • V)) • gen

/-- The honest recipient's one-time spending key, as they derive it while
scanning. -/
def honestKey : F := m + hash (v • R)

/-! ## The attack

Discrete logarithms in this toy group are division by the generator, so the
"oracle" is a one-liner. In a real group this step is what a quantum adversary
supplies and a classical one cannot. -/

/-- The generator's multiplicative inverse, `5 * 14 = 70 = 1 mod 23`. -/
def genInv : F := 14

/-- ...which really is the inverse. -/
theorem genInv_spec : genInv * gen = 1 := by decide

/-- The discrete-log "oracle" for this instance: multiply by the inverse of the
generator. Written as multiplication rather than division because `ZMod`
division does not reduce by computation, so the checks below would not run. -/
def dlog (x : F) : F := genInv * x

/-- What the adversary computes, from published data only: the two discrete
logs of the meta-address, then the stealth spending scalar. -/
def recovered : F := recover hash (dlog M) (dlog V) R

/-! ## Run it

`#eval` these to watch the attack succeed. `recovered` equals `honestKey`, and
scaling it by the generator lands exactly on the announced `P`. -/

#eval M          -- published spending key
#eval V          -- published viewing key
#eval R          -- announced ephemeral key
#eval P          -- announced stealth public key
#eval honestKey  -- what the recipient derives while scanning
#eval recovered  -- what the attacker derives from public data alone

/-- The attacker's scalar is the recipient's own spending key. Checked by
computation here; proved in general by `dksap_recover_eq_honest`. -/
example : recovered = honestKey := by decide

/-- The recovered scalar is a valid secret key for the announced stealth
address. Checked by computation here; proved in general by
`dksap_key_recovery`. -/
example : recovered • gen = P := by decide

/-- The same conclusion obtained from the ABSTRACT theorem rather than by
computation, to confirm the general result really does cover this instance. -/
example : recovered • gen = M + (hash (r • V)) • gen :=
  dksap_key_recovery hash gen gen_injective m v r (dlog M) (dlog V)
    (by decide) (by decide)

end PqStealth.Demo
