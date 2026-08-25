import PqStealth.DKSAP
import VCVio.OracleComp.RunIO
import Mathlib.Algebra.Field.ZMod
import Mathlib.Tactic.NormNum.Prime

/-!
# A runnable DKSAP instance

Everything else here is abstract, which is what makes the theorems apply to any
curve and also what makes nothing executable. This module fixes a tiny instance
-- the additive group of `ZMod 23`, where discrete logs are division -- so the
scheme and the attack can be RUN: exactly why the attack is executable here, and
why the instance offers no security. Each `#eval` is wrapped in `#guard_msgs`,
so the numbers in the docstrings are build-checked assertions.

See `docs/dksap-asymmetry.md`.
-/

namespace PqStealth.Demo

open PqStealth

/-! ## A tiny field and a generator -/

/-- `23` is prime, so `ZMod 23` is a field. -/
instance instFactPrime23 : Fact (Nat.Prime 23) := ⟨by norm_num⟩

/-- Scalars and group elements both live in `ZMod 23`, viewed as a module over
itself: `x • g` is ordinary multiplication. In this instance `smul_eq_mul` holds definitionally (`x • g = x * g` in `ZMod 23`),
so `recover`/`dlog` below are plain field arithmetic; the general theorems only
use the group law. -/
abbrev F := ZMod 23

/-- The generator. Any nonzero element works. -/
def gen : F := 5

/-- The hash carrying a shared secret point to a scalar. Deliberately silly,
which is part of the point: the attack does not care what `h` is. -/
def hash (x : F) : F := 7 * x + 3

/-- Nondegeneracy of the generator, the hypothesis key recovery needs. -/
theorem gen_injective : Function.Injective (fun x : F => x • gen) := by
  simpa only [smul_eq_mul] using mul_left_injective₀ (b := gen) (by decide)

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
/-- The recipient's one-time spending key, as they derive it while scanning. -/
def honestKey : F := m + hash (v • R)

/-! ## The attack

In a real group this step is what a quantum adversary supplies. -/

/-- The generator's multiplicative inverse, `5 * 14 = 70 = 1 mod 23`. -/
def genInv : F := 14

/-- ...which really is the inverse. -/
theorem genInv_spec : genInv * gen = 1 := by decide

/-- The discrete-log "oracle": multiply by the inverse of the generator. Written
as multiplication because `ZMod` division does not reduce by computation. -/
def dlog (x : F) : F := genInv * x

/-- What the adversary computes, from published data only. -/
def recovered : F := recover hash (dlog M) (dlog V) R

/-! ## Run it -/

/-- info: 22 -/
#guard_msgs in
#eval M          -- published spending key

/-- info: 20 -/
#guard_msgs in
#eval V          -- published viewing key

/-- info: 15 -/
#guard_msgs in
#eval R          -- announced ephemeral key

/-- info: 21 -/
#guard_msgs in
#eval P          -- announced stealth public key

/-- info: 18 -/
#guard_msgs in
#eval honestKey  -- what the recipient derives while scanning

/-- info: 18 -/
#guard_msgs in
#eval recovered  -- what the attacker derives from public data alone

/-- The attacker's scalar is the recipient's own spending key; proved in general
by `dksap_recover_eq_honest`. -/
example : recovered = honestKey := by decide

/-- The recovered scalar is a valid secret key for the announced stealth
address; proved in general by `dksap_key_recovery`. -/
example : recovered • gen = P := by decide

/-- The same conclusion from the ABSTRACT theorem rather than by computation. -/
example : recovered • gen = M + (hash (r • V)) • gen :=
  dksap_key_recovery hash gen gen_injective m v r (dlog M) (dlog V)
    (by decide) (by decide)

/-! ## The abstract scheme, instantiated

The scheme of `DKSAP.lean` is a `StealthScheme` over any field, module and hash;
here it is built at this instance, which is the kernel-checked witness that the
hypothesis bundle of every DKSAP theorem is jointly inhabited. -/

/-- DKSAP at the toy instance. -/
def scheme : StealthScheme (F × F) (F × F) (F × F) := dksap gen hash

/-- Nondegeneracy in the form the unlinkability theorems take: on a finite
field, injective is bijective. -/
theorem gen_bijective : Function.Bijective (fun x : F => x • gen) :=
  Finite.injective_iff_bijective.mp gen_injective

/-- Detection completeness, from the abstract theorem. -/
example : scheme.PerfectlyComplete := dksap_perfectlyComplete gen hash

/-- Unlinkability from DDH and entropy smoothing, from the abstract theorem, for
any adversary against this instance. -/
example (adv : StealthScheme.UnlinkAdv (F × F) (F × F)) :
    scheme.unlinkAdvantage adv ≤
      (DiffieHellman.ddhDistAdvantage gen (ddhReductionDKSAP hash adv true) +
          EntropySmoothing.advantage F gen (fun (_ : Fin 1) => hash)
            (esReductionDKSAP gen adv true)) +
        (DiffieHellman.ddhDistAdvantage gen (ddhReductionDKSAP hash adv false) +
          EntropySmoothing.advantage F gen (fun (_ : Fin 1) => hash)
            (esReductionDKSAP gen adv false)) :=
  dksap_unlinkAdvantage_le_ddh_add_es gen hash adv gen_bijective

-- The scheme's own scanner, run on the announcement above: detection fires.
/-- info: true -/
#guard_msgs in
#eval OracleComp.runIO (scheme.scan (m, v) (R, P))

-- The completeness experiment, actually run (keys and ephemeral scalar drawn at
-- random): it returns `true` on every run, which is what `dksap_perfectlyComplete`
-- says.
/-- info: true -/
#guard_msgs in
#eval OracleComp.runIO scheme.CorrectExp

end PqStealth.Demo
