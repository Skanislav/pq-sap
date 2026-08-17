/-
Build-checked axiom audit for the headline theorems.

`#print axioms t` lists the axioms in `t`'s dependency cone, and any `sorry`
anywhere in that cone adds `sorryAx` to the list. Wrapping the command in
`#guard_msgs` turns the printed list into an assertion: the expected text is
the docstring, and a mismatch is a compile ERROR rather than an `info:` line
someone has to read. Because this module imports the whole development and the
root module imports it, `lake build` fails the moment any headline theorem
starts depending on a `sorry` or on a new axiom.

The expected lists are the ones actually observed, not a uniform aspiration:
the pure-algebra facts `beta_blinded_eq_two_beta` and `meta_address_roundtrips`
need only `propext`, and the DKSAP key-recovery pair needs `propext` and
`Quot.sound`. Freezing each theorem's own list is what makes a *newly*
classical proof visible.

`whitespace := lax` is required because `#print axioms` line-wraps its output
for names long enough to exceed the pretty-printer width, so the same three
axioms print on one line for most theorems and on three lines for
`StealthScheme.unlinkAdvantage_eq_branchDistAdvantage`. Lax matching compares
the text with runs of whitespace collapsed, which makes every block below
identical in shape and independent of name length.
-/

import PqStealth.Blinding
import PqStealth.Invariants
import PqStealth.Games
import PqStealth.KEMAnonymity
import PqStealth.MLKEMInstance
import PqStealth.Ownership
import PqStealth.SharedSecretHiding
import PqStealth.AnonymityFromSPR
import PqStealth.DKSAP
import PqStealth.Demo
import PqStealth.Falsification
import PqStealth.DKSAPClassical

/-! ## Algebraic core (`Blinding`) -/

/-- info: 'PqStealth.blinded_key_correctness' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms PqStealth.blinded_key_correctness

/-- info: 'PqStealth.stealth_pk_eq_blinded_keypair' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms PqStealth.stealth_pk_eq_blinded_keypair

/-- info: 'PqStealth.stealth_pk_rounding_error_concrete' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms PqStealth.stealth_pk_rounding_error_concrete

/-! ## Signing invariants, ownership bridge, encodings (`Invariants`) -/

/-- info: 'PqStealth.cInfNorm_add_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms PqStealth.cInfNorm_add_le

/-- info: 'PqStealth.blinded_norm_bound' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms PqStealth.blinded_norm_bound

/-- info: 'PqStealth.beta_blinded_eq_two_beta' depends on axioms: [propext] -/
#guard_msgs (whitespace := lax) in
#print axioms PqStealth.beta_blinded_eq_two_beta

/-- info: 'PqStealth.ownership_iff_signing' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms PqStealth.ownership_iff_signing

/-- info: 'PqStealth.blinded_is_ownership_witness' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms PqStealth.blinded_is_ownership_witness

/-- info: 'PqStealth.stealth_pk_roundtrips' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms PqStealth.stealth_pk_roundtrips

/-- info: 'PqStealth.meta_address_roundtrips' depends on axioms: [propext] -/
#guard_msgs (whitespace := lax) in
#print axioms PqStealth.meta_address_roundtrips

/-! ## Unlinkability game (`Games`) -/

/-- info: 'PqStealth.StealthScheme.unlinkAdvantage_eq_branchDistAdvantage' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms PqStealth.StealthScheme.unlinkAdvantage_eq_branchDistAdvantage

/-! ## KEM anonymity and the two KEM-based schemes (`KEMAnonymity`) -/

/-- info: 'PqStealth.KEM.anonAdvantage_eq_branchDistAdvantage' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms PqStealth.KEM.anonAdvantage_eq_branchDistAdvantage

/-- info: 'PqStealth.unlinkAdvantage_ofKEM_eq_anonAdvantage' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms PqStealth.unlinkAdvantage_ofKEM_eq_anonAdvantage

/-- info: 'PqStealth.unlinkAdvantage_ofKEMFull_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms PqStealth.unlinkAdvantage_ofKEMFull_le

/-! ## Shared-secret hiding as a real-or-random bias (`SharedSecretHiding`) -/

/-- info: 'PqStealth.sharedSecretHidingTrue_eq_rorBias' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms PqStealth.sharedSecretHidingTrue_eq_rorBias

/-- info: 'PqStealth.sharedSecretHidingFalse_eq_rorBias' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms PqStealth.sharedSecretHidingFalse_eq_rorBias

/-! ## Specialization to VCVio's ML-KEM (`MLKEMInstance`) -/

/-- info: 'PqStealth.mlkem_unlinkAdvantage_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms PqStealth.mlkem_unlinkAdvantage_le

/-! ## Anonymity from ciphertext pseudorandomness (`AnonymityFromSPR`) -/

/-- info: 'PqStealth.KEM.anonAdvantage_le_sprAdv' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms PqStealth.KEM.anonAdvantage_le_sprAdv

/-- info: 'PqStealth.unlinkAdvantage_ofKEMFull_le_full_decomposition' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms PqStealth.unlinkAdvantage_ofKEMFull_le_full_decomposition

/-- info: 'PqStealth.mlkem_unlinkAdvantage_le_full_decomposition' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms PqStealth.mlkem_unlinkAdvantage_le_full_decomposition

/-! ## Spend side (`Ownership`) -/

/-- info: 'PqStealth.honest_witness_valid' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms PqStealth.honest_witness_valid

/-! ## DKSAP: completeness and the quantum key-recovery attack (`DKSAP`) -/

/-- info: 'PqStealth.dksap_perfectlyComplete' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms PqStealth.dksap_perfectlyComplete

/-- info: 'PqStealth.dksap_recover_eq_honest' depends on axioms: [propext, Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms PqStealth.dksap_recover_eq_honest

/-- info: 'PqStealth.dksap_key_recovery' depends on axioms: [propext, Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms PqStealth.dksap_key_recovery

/-! ## DKSAP under a classical adversary (`DKSAPClassical`) -/

/-- info: 'PqStealth.dksapIdeal_unlinkAdvantage_eq_zero' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms PqStealth.dksapIdeal_unlinkAdvantage_eq_zero

/-- info: 'PqStealth.dksap_unlinkAdvantage_le_hashedDH' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms PqStealth.dksap_unlinkAdvantage_le_hashedDH

/-! ## Negative control (`Falsification`) -/

/-- info: 'PqStealth.dksapBroken_not_perfectlyComplete' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms PqStealth.dksapBroken_not_perfectlyComplete
