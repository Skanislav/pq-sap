import PqStealth.Blinding
import PqStealth.Invariants
import PqStealth.Games
import PqStealth.KEMAnonymity
import PqStealth.MultiUnlink
import PqStealth.MultiRecipient
import PqStealth.ConstructionA
import PqStealth.BlindingROM
import PqStealth.SharedSecretHiding
import PqStealth.AnonymityFromSPR
import PqStealth.MLKEM
import PqStealth.SPRTwoHop
import PqStealth.Ownership
import PqStealth.DKSAP
import PqStealth.DKSAPOracle
import PqStealth.ROMUpToBad
import PqStealth.Reorder
import PqStealth.Soundness
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

/-- info: 'PqStealth.stealth_pk_rounding_error' depends on axioms: [propext] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.stealth_pk_rounding_error

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

/-- info: 'PqStealth.meta_address_roundtrips' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.meta_address_roundtrips

/-- info: 'PqStealth.meta_address_roundtrips_5633' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.meta_address_roundtrips_5633

/-- info: 'PqStealth.meta_address_zk_roundtrips' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.meta_address_zk_roundtrips

/-- info: 'PqStealth.meta_address_zk_roundtrips_1217' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.meta_address_zk_roundtrips_1217

/-- info: 'PqStealth.metaAddress_size_mldsa65_mlkem768' depends on axioms: [propext] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.metaAddress_size_mldsa65_mlkem768

/-- info: 'PqStealth.metaAddressZk_size_mlkem768' does not depend on any axioms -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.metaAddressZk_size_mlkem768

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

/-- info: 'PqStealth.dksap_derivation_agrees' depends on axioms: [propext, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.dksap_derivation_agrees

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


/-- info: 'PqStealth.hashedDH_le_ddh_add_es' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.hashedDH_le_ddh_add_es

/-- info: 'PqStealth.dksap_unlinkAdvantage_le_ddh_add_es' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.dksap_unlinkAdvantage_le_ddh_add_es

/-- info: 'PqStealth.evalDist_pull₆' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.evalDist_pull₆

/-! ## DKSAP with a discrete-log oracle (`DKSAPOracle`) -/

/-- info: 'PqStealth.dlogAttack_isTotalQueryBound' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.dlogAttack_isTotalQueryBound

/-- info: 'PqStealth.dlogAttack_not_isTotalQueryBound_one' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.dlogAttack_not_isTotalQueryBound_one

/-- info: 'PqStealth.dksapAnnounce_mem_announce_support' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.dksapAnnounce_mem_announce_support

/-- info: 'PqStealth.dlogAttack_key_recovery' depends on axioms: [propext, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.dlogAttack_key_recovery

/-- info: 'PqStealth.dlogAttack_forall_key_recovery' depends on axioms: [propext, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.dlogAttack_forall_key_recovery

/-! ## DKSAP in the random-oracle model (`DKSAPOracle`) -/

/-- info: 'PqStealth.dksapROIdeal_boolDistAdvantage_eq_zero' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.dksapROIdeal_boolDistAdvantage_eq_zero

/-- info: 'PqStealth.dksap_unlinkAdvantageRO_le_hashedDHRO' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.dksap_unlinkAdvantageRO_le_hashedDHRO

/-- info: 'PqStealth.dksapRORun_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.dksapRORun_eq

/-- info: 'PqStealth.hashedDHRO_le_dksapROBadProb' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.hashedDHRO_le_dksapROBadProb

/-- info: 'PqStealth.dksap_unlinkAdvantageRO_le_badProb' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.dksap_unlinkAdvantageRO_le_badProb

/-! ## Identical until bad for the lazy random oracle (`ROMUpToBad`) -/

/-- info: 'PqStealth.tvDist_programmedROImpl_trackingROImpl_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.tvDist_programmedROImpl_trackingROImpl_le

/-- info: 'PqStealth.tvDist_run'_roImpl_cacheOr_le_probEvent_bad' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.tvDist_run'_roImpl_cacheOr_le_probEvent_bad

/-- info: 'PqStealth.probEvent_flag_programmed_eq_tracking' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.probEvent_flag_programmed_eq_tracking

/-- info: 'PqStealth.boolDistAdvantage_run'_cacheQuery_run'_empty_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.boolDistAdvantage_run'_cacheQuery_run'_empty_le

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

/-- info: 'PqStealth.auxKeyIndependence_tagOnly_eq_zero' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.auxKeyIndependence_tagOnly_eq_zero

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

/-! ## The two MLWE hops of SPR (`SPRTwoHop`) -/

/-- info: 'PqStealth.KEM.evalDist_anonSetup_bind_anonBranch' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.KEM.evalDist_anonSetup_bind_anonBranch

/-- info: 'PqStealth.LearningWithErrors.advantage_eq_boolDistAdvantage' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.LearningWithErrors.advantage_eq_boolDistAdvantage

/-- info: 'PqStealth.idealEncrypt_pkOf' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.idealEncrypt_pkOf

/-- info: 'PqStealth.game0_keyHopProblem' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.game0_keyHopProblem

/-- info: 'PqStealth.game1_keyHopProblem' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.game1_keyHopProblem

/-- info: 'PqStealth.game0_ctHopProblem' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.game0_ctHopProblem

/-- info: 'PqStealth.game1_ctHopProblem' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.game1_ctHopProblem

/-- info: 'PqStealth.simulatorGap_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.simulatorGap_le

/-- info: 'PqStealth.sprAdv_le_two_hop_decomposition' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.sprAdv_le_two_hop_decomposition

/-- info: 'PqStealth.mlkem768_sprAdv_le_two_hop_decomposition' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.mlkem768_sprAdv_le_two_hop_decomposition

/-! ## Spend forgery as matrix-SIS (`Ownership`) -/

/-- info: 'PqStealth.spendForgeryAdvantage_eq_sis_advantage' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.spendForgeryAdvantage_eq_sis_advantage

/-- info: 'PqStealth.spendForgeryAdvantage_le_augmentedSIS' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.spendForgeryAdvantage_le_augmentedSIS

/-- info: 'PqStealth.mldsa_spendForgeryAdvantage_eq_sis_advantage' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.mldsa_spendForgeryAdvantage_eq_sis_advantage

/-- info: 'PqStealth.augmentedSISProblem_isValid_eq_matrixProblem' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.augmentedSISProblem_isValid_eq_matrixProblem

/-- info: 'PqStealth.spendForgeryAdvantage_ne_top' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.spendForgeryAdvantage_ne_top

/-- info: 'PqStealth.augmentedWitness_ne_zero' depends on axioms: [propext, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.augmentedWitness_ne_zero

/-- info: 'PqStealth.honest_augmented_witness_valid' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.honest_augmented_witness_valid

/-- info: 'PqStealth.ownershipValid_mldsaShort_iff_isSigningKey' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.ownershipValid_mldsaShort_iff_isSigningKey

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

/-- info: 'PqStealth.ProbComp.boolDistAdvantage_le_sum_hybrids' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.ProbComp.boolDistAdvantage_le_sum_hybrids

/-- info: 'PqStealth.StealthScheme.evalDist_announceList_append_cons' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.StealthScheme.evalDist_announceList_append_cons

/-- info: 'PqStealth.StealthScheme.unlinkAdvantage_hybridAdv_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.StealthScheme.unlinkAdvantage_hybridAdv_eq

/-- info: 'PqStealth.StealthScheme.unlinkAdvantageMulti_le_sum' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.StealthScheme.unlinkAdvantageMulti_le_sum

/-- info: 'PqStealth.StealthScheme.unlinkAdvantageMulti_le_mul' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.StealthScheme.unlinkAdvantageMulti_le_mul

/-! ## Detection soundness (`Soundness`) -/

/-- info: 'PqStealth.dksap_falsePositiveRate_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.dksap_falsePositiveRate_eq

/-- info: 'PqStealth.dksap_falsePositiveRate_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.dksap_falsePositiveRate_le

/-- info: 'PqStealth.falsePositiveRate_ofKEMFull_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.falsePositiveRate_ofKEMFull_le

/-- info: 'PqStealth.decapsRoR_eq_zero_of_decaps_uniform' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.decapsRoR_eq_zero_of_decaps_uniform

/-- info: 'PqStealth.falsePositiveRate_ofKEMFull_le_of_decaps_uniform' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.falsePositiveRate_ofKEMFull_le_of_decaps_uniform

/-- info: 'PqStealth.auxCollisionFree_taggedAux' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.auxCollisionFree_taggedAux

/-- info: 'PqStealth.soundWithin_ofKEMFull_taggedAux' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.soundWithin_ofKEMFull_taggedAux

/-- info: 'PqStealth.soundWithin_ofKEMFull_oneByteTag' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.soundWithin_ofKEMFull_oneByteTag

/-- info: 'PqStealth.soundWithin_ofKEMFull_byteTag' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.soundWithin_ofKEMFull_byteTag

/-- info: 'PqStealth.falsePositiveRate_ofKEMFullNoTag_eq_one' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.falsePositiveRate_ofKEMFullNoTag_eq_one

/-! ## `n`-recipient unlinkability (`MultiRecipient`) -/

/-- info: 'PqStealth.StealthScheme.evalDist_pubKeysN_update' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.StealthScheme.evalDist_pubKeysN_update

/-- info: 'PqStealth.StealthScheme.evalDist_pubKeysN_embedPair' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.StealthScheme.evalDist_pubKeysN_embedPair

/-- info: 'PqStealth.StealthScheme.unlinkAdvantageN_eq_branchDistAdvantage' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.StealthScheme.unlinkAdvantageN_eq_branchDistAdvantage

/-- info: 'PqStealth.StealthScheme.evalDist_unlinkBranch_pairGuessAdv' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.StealthScheme.evalDist_unlinkBranch_pairGuessAdv

/-- info: 'PqStealth.StealthScheme.sum_probOutput_unlinkBranchNAt' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.StealthScheme.sum_probOutput_unlinkBranchNAt

/-- info: 'PqStealth.StealthScheme.unlinkAdvantageN_le_sum' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.StealthScheme.unlinkAdvantageN_le_sum

/-- info: 'PqStealth.StealthScheme.unlinkAdvantageN_le_mul' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.StealthScheme.unlinkAdvantageN_le_mul

/-! ## The address hash as a random oracle (`BlindingROM`) -/

/-- info: 'PqStealth.ConstructionA.simulateQ_romImpl_liftComp' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.ConstructionA.simulateQ_romImpl_liftComp

/-- info: 'PqStealth.ConstructionA.run_hashAddrRO_empty' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.ConstructionA.run_hashAddrRO_empty

/-- info: 'PqStealth.ConstructionA.blindGameRO_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.ConstructionA.blindGameRO_eq

/-- info: 'PqStealth.ConstructionA.blindingAdvantageRO_eq_zero_of_no_query' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.ConstructionA.blindingAdvantageRO_eq_zero_of_no_query

/-- info: 'PqStealth.ConstructionA.blindingAdvantageRO_le_blindBadProb' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms PqStealth.ConstructionA.blindingAdvantageRO_le_blindBadProb
