import PqStealth.Blinding
import PqStealth.Invariants
import PqStealth.Games
import PqStealth.KEMAnonymity
import PqStealth.MultiUnlink
import PqStealth.ConstructionA
import PqStealth.SharedSecretHiding
import PqStealth.AnonymityFromSPR
import PqStealth.MLKEM
import PqStealth.Ownership
import PqStealth.DKSAP
import PqStealth.Demo
import PqStealth.Controls

/-!
# Build-checked axiom audit

`#print axioms t` lists the axioms in `t`'s dependency cone; any `sorry` in that
cone adds `sorryAx`. Wrapping it in `#guard_msgs` turns the printed list into an
assertion, so a mismatch is a compile ERROR rather than an `info:` line someone
has to read. This module imports the whole development and the root imports it,
so `lake build` fails the moment a headline theorem gains a `sorry` or an axiom.

The expected lists are the ones actually observed, not a uniform aspiration:
the pure-algebra facts need only `propext`, the DKSAP key-recovery pair needs
`propext` and `Quot.sound`. Freezing each theorem's own list is what makes a
newly classical proof visible. `whitespace := lax` is required because
`#print axioms` line-wraps for long names.
-/

/-! ## Algebraic core (`Blinding`) -/

/-- info: 'PqStealth.blinded_key_correctness' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.blinded_key_correctness

/-- info: 'PqStealth.stealth_pk_eq_blinded_keypair' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.stealth_pk_eq_blinded_keypair

/-- info: 'PqStealth.stealth_pk_rounding_error_concrete' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.stealth_pk_rounding_error_concrete

/-! ## Signing invariants, ownership bridge, encodings (`Invariants`) -/

/-- info: 'PqStealth.cInfNorm_add_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.cInfNorm_add_le

/-- info: 'PqStealth.blinded_norm_bound' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.blinded_norm_bound

/-- info: 'PqStealth.beta_blinded_eq_two_beta' depends on axioms: [propext] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.beta_blinded_eq_two_beta

/-- info: 'PqStealth.ownership_iff_signing' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.ownership_iff_signing

/-- info: 'PqStealth.blinded_is_ownership_witness' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.blinded_is_ownership_witness

/-- info: 'PqStealth.stealth_pk_roundtrips' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.stealth_pk_roundtrips

/-- info: 'PqStealth.meta_address_roundtrips' depends on axioms: [propext] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.meta_address_roundtrips

/-! ## Unlinkability game (`Games`) -/

/-- info: 'PqStealth.StealthScheme.unlinkAdvantage_eq_branchDistAdvantage' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.StealthScheme.unlinkAdvantage_eq_branchDistAdvantage

/-! ## KEM anonymity and the two KEM-based schemes (`KEMAnonymity`) -/

/-- info: 'PqStealth.KEM.anonAdvantage_eq_branchDistAdvantage' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.KEM.anonAdvantage_eq_branchDistAdvantage

/-- info: 'PqStealth.unlinkAdvantage_ofKEM_eq_anonAdvantage' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.unlinkAdvantage_ofKEM_eq_anonAdvantage

/-- info: 'PqStealth.unlinkAdvantage_ofKEMFull_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.unlinkAdvantage_ofKEMFull_le

/-! ## Shared-secret hiding as a real-or-random bias (`SharedSecretHiding`) -/

/-- info: 'PqStealth.sharedSecretHiding_eq_rorBias' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.sharedSecretHiding_eq_rorBias

/-! ## Anonymity from ciphertext pseudorandomness (`AnonymityFromSPR`) -/

/-- info: 'PqStealth.KEM.anonAdvantage_le_sprAdv' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.KEM.anonAdvantage_le_sprAdv

/-- info: 'PqStealth.unlinkAdvantage_ofKEMFull_le_full_decomposition' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.unlinkAdvantage_ofKEMFull_le_full_decomposition

/-! ## Spend side (`Ownership`) -/

/-- info: 'PqStealth.honest_witness_valid' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.honest_witness_valid

/-! ## DKSAP: completeness and the quantum key-recovery attack (`DKSAP`) -/

/-- info: 'PqStealth.dksap_perfectlyComplete' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.dksap_perfectlyComplete

/-- info: 'PqStealth.dksap_recover_eq_honest' depends on axioms: [propext, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.dksap_recover_eq_honest

/-- info: 'PqStealth.dksap_key_recovery' depends on axioms: [propext, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.dksap_key_recovery

/-! ## DKSAP under a classical adversary (`DKSAP`) -/

/-- info: 'PqStealth.dksapIdeal_unlinkAdvantage_eq_zero' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.dksapIdeal_unlinkAdvantage_eq_zero

/-- info: 'PqStealth.dksap_unlinkAdvantage_le_hashedDH' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.dksap_unlinkAdvantage_le_hashedDH

/-! ## Negative control (`Controls`) -/

/-- info: 'PqStealth.dksapBroken_not_perfectlyComplete' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.dksapBroken_not_perfectlyComplete

/-! ## Honest signing keys (`Invariants`) -/

/-- info: 'PqStealth.blinded_is_signing_key' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.blinded_is_signing_key

/-! ## Detection completeness of the KEM-based scheme (`KEMAnonymity`) -/

/-- info: 'PqStealth.perfectlyComplete_ofKEMFull' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.perfectlyComplete_ofKEMFull

/-! ## Construction A inside the game model (`ConstructionA`) -/

/-- info: 'PqStealth.auxKeyIndependence_eq_zero_of_pk_independent' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.auxKeyIndependence_eq_zero_of_pk_independent

/-- info: 'PqStealth.ConstructionA.stealthAddr_eq_blinded_pk' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.ConstructionA.stealthAddr_eq_blinded_pk

/-- info: 'PqStealth.ConstructionA.announced_key_isOwnershipWitness' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.ConstructionA.announced_key_isOwnershipWitness

/-- info: 'PqStealth.ConstructionA.unlinkAdvantage_scheme_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.ConstructionA.unlinkAdvantage_scheme_le

/-- info: 'PqStealth.ConstructionA.idealAux_indep_of_t' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.ConstructionA.idealAux_indep_of_t

/-! ## Hiding terms are VCVio's KEM IND-CPA advantage (`SharedSecretHiding`) -/

/-- info: 'PqStealth.sharedSecretHiding_eq_indCpaAdvantage' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.sharedSecretHiding_eq_indCpaAdvantage

/-- info: 'PqStealth.unlinkAdvantage_ofKEMFull_le_indCpa' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.unlinkAdvantage_ofKEMFull_le_indCpa

/-! ## ML-KEM-768 without instance hypotheses (`MLKEM`) -/

/-- info: 'PqStealth.mlkem768_unlinkAdvantage_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.mlkem768_unlinkAdvantage_le

/-- info: 'PqStealth.mlkem768_unlinkAdvantage_le_full_decomposition' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.mlkem768_unlinkAdvantage_le_full_decomposition

/-- info: 'PqStealth.mlkem768_unlinkAdvantage_le_indCpa' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.mlkem768_unlinkAdvantage_le_indCpa

/-- info: 'PqStealth.isEmpty_sampleableType_mlkem768Ciphertext' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.isEmpty_sampleableType_mlkem768Ciphertext

/-! ## Spend forgery as matrix-SIS (`Ownership`) -/

/-- info: 'PqStealth.spendForgeryAdvantage_eq_sis_advantage' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.spendForgeryAdvantage_eq_sis_advantage

/-- info: 'PqStealth.spendForgeryAdvantage_le_msis' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.spendForgeryAdvantage_le_msis

/-- info: 'PqStealth.mldsa_spendForgeryAdvantage_eq_sis_advantage' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.mldsa_spendForgeryAdvantage_eq_sis_advantage

/-- info: 'PqStealth.augmentedSISProblem_isValid_eq_matrixProblem' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.augmentedSISProblem_isValid_eq_matrixProblem

/-! ## Game-layer controls (`Controls`) -/

/-- info: 'PqStealth.unlinkAdvantage_leakyAdv_eq_one_sub_keyCollisionProb' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.unlinkAdvantage_leakyAdv_eq_one_sub_keyCollisionProb

/-- info: 'PqStealth.leakyKEM_anonAdvantage_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.leakyKEM_anonAdvantage_eq

/-- info: 'PqStealth.deadKEM_ofKEMFull_not_perfectlyComplete' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.deadKEM_ofKEMFull_not_perfectlyComplete

/-- info: 'PqStealth.perfectlyComplete_ofKEMFullNoTag' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.perfectlyComplete_ofKEMFullNoTag

/-- info: 'PqStealth.probOutput_falsePositiveExp_ofKEMFullNoTag_eq_one' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.probOutput_falsePositiveExp_ofKEMFullNoTag_eq_one

/-! ## Multi-challenge unlinkability (`MultiUnlink`) -/

/-- info: 'PqStealth.StealthScheme.unlinkAdvantageMulti_eq_branchDistAdvantage' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.StealthScheme.unlinkAdvantageMulti_eq_branchDistAdvantage

/-- info: 'ProbComp.boolDistAdvantage_le_sum_hybrids' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms ProbComp.boolDistAdvantage_le_sum_hybrids

/-- info: 'PqStealth.StealthScheme.evalDist_announceList_append_cons' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.StealthScheme.evalDist_announceList_append_cons

/-- info: 'PqStealth.StealthScheme.unlinkAdvantage_hybridAdv_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.StealthScheme.unlinkAdvantage_hybridAdv_eq

/-- info: 'PqStealth.StealthScheme.unlinkAdvantageMulti_le_sum' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.StealthScheme.unlinkAdvantageMulti_le_sum

/-- info: 'PqStealth.StealthScheme.unlinkAdvantageMulti_le_mul' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.StealthScheme.unlinkAdvantageMulti_le_mul
