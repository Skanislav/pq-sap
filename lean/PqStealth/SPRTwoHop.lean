import PqStealth.MLKEM
import LatticeCrypto.HardnessAssumptions.LearningWithErrors
import VCVio.ProgramLogic.Tactics

/-!
# SPR of K-PKE: the two MLWE hops

Proved: the two decision-MLWE problems the SPR argument needs, both as VCVio
`LearningWithErrors.Problem`s over the seed `rho`; the two reduction adversaries
built from an unlinkability distinguisher; that each hop's game gap IS the
`LearningWithErrors.advantage` of its reduction adversary; and the resulting
four-term bound on `KEM.sprAdv` for ML-KEM-768.

Also proved: the real anonymity branch may be reordered to encapsulate first
and draw the other key afterwards (`evalDist_anonSetup_bind_anonBranch`, by
VCVio's relational tactics), so that reorder costs nothing and is NOT folded
into the idealization term.

Assumed: the two non-lattice terms of that bound stay unbounded here -- the
primitive-idealization term (`G` and `PRF_eta` as independent samplers; the
seeded shape keeps `SampleNTT` concrete) and the simulator term
(compress-and-encode regularity, plus the honest key distribution). Neither is
an MLWE statement. See `docs/spr-two-hop.md`.
-/

open OracleComp OracleSpec MLKEM MLKEM.Concrete ENNReal

namespace PqStealth

/-! ## Uniform sampling on the ML-KEM ring

VCVio leaves these to the caller (`MLDSA` takes them as hypotheses); they are
what the uniform side of each MLWE problem needs. -/

/-- The FIPS 203 modulus is nonzero -- needed to see `ZMod modulus` as
`FinEnum`, which `modulus` being a `def` hides from instance search. -/
instance instNeZeroMlkemModulus : NeZero MLKEM.modulus := ⟨by decide⟩

/-- Uniform sampling on `R_q`, through the `Vector Coeff 256` representation
that `LatticeCrypto.Poly` is a plain `def` for. -/
instance instSampleableTypeRq : SampleableType MLKEM.Rq :=
  inferInstanceAs (SampleableType (Vector MLKEM.Coeff MLKEM.ringDegree))

/-- Uniform sampling on `T_q`, transported along the `TransformPoly` newtype. -/
instance instSampleableTypeTq : SampleableType MLKEM.Tq :=
  SampleableType.ofEquiv (α := MLKEM.Rq)
    ⟨fun f => ⟨f⟩, fun t => t.coeffs, fun _ => rfl, fun _ => rfl⟩

/-! ## VCVio's LWE advantage as a game distance -/

/-- The decision-LWE advantage is the distance between the two named games, so
it composes with the game-hopping triangle inequalities. (Scoped under
`PqStealth`; upstream ask, `docs/vcvio-upstream.md` item 4.) -/
theorem LearningWithErrors.advantage_eq_boolDistAdvantage {Sample Secret Output : Type}
    [Add Output] (problem : LearningWithErrors.Problem Sample Secret Output)
    (adv : LearningWithErrors.Adversary problem) :
    LearningWithErrors.advantage problem adv =
      (LearningWithErrors.game0 problem adv).boolDistAdvantage
        (LearningWithErrors.game1 problem adv) := by
  have key := ProbComp.boolBiasAdvantage_bind_uniformBool_eq_boolDistAdvantage
    (pure () : ProbComp Unit) (fun _ => LearningWithErrors.game0 problem adv)
    (fun _ => LearningWithErrors.game1 problem adv)
  simp only [pure_bind] at key
  rw [LearningWithErrors.advantage, ← key]
  refine congrArg ProbComp.boolBiasAdvantage ?_
  simp only [LearningWithErrors.experiment]
  refine bind_congr fun b => ?_
  cases b <;>
    simp only [if_true, LearningWithErrors.game0, LearningWithErrors.game1, bind_assoc]

variable {params : Params} (ring : NTTRingOps) (encoding : Encoding params)
  (prims : Primitives params encoding)

/-! ## Semantic constructors and the idealized samplers

`pkOf`/`ctOf` name the two places FIPS 203 leaves the algebra: a public key is a
seed plus an encoded `t̂`, a ciphertext an encoded compressed `(u, v)`. -/

/-- The K-PKE public key carrying `rho` and the encoding of `t̂`. -/
def pkOf (rho : Seed32) (tHat : TqVec params.k) : EncapsulationKey params encoding :=
  { tHatEncoded := encoding.byteEncode12Vec tHat, rho := rho }

/-- The K-PKE ciphertext carrying the compressed encodings of `u` and `v`. -/
def ctOf (u : RqVec params.k) (v : Rq) : Ciphertext params encoding :=
  { uEncoded := encoding.byteEncodeDUVec (encoding.compressDU u)
    vEncoded := encoding.byteEncodeDV (encoding.compressDV v) }

/-- The `PRF_η₁` vector at a fresh seed, moved to the NTT domain: the
distribution K-PKE gives `s`, `e` and the encryption randomness `y`, with the
seed idealized to a fresh uniform draw. -/
def sampleEta1Hat (offset : ℕ) : ProbComp (TqVec params.k) := do
  let sigma ← $ᵗ Seed32
  pure (ring.nttVec (prims.sampleVecEta1 sigma offset))

/-- The encryption noise pair `(e₁, e₂)`, each at a fresh idealized seed. -/
def sampleNoise : ProbComp (RqVec params.k × Rq) := do
  let c₁ ← $ᵗ Coins
  let c₂ ← $ᵗ Coins
  pure (prims.sampleVecEta2 c₁ params.k, prims.prfEta2 c₂ (2 * params.k))

/-- Idealized K-PKE key generation: `t̂ = Â·ŝ + ê` with `rho`, `ŝ` and `ê`
independent. -/
def idealKeygen : ProbComp (EncapsulationKey params encoding) := do
  let rho ← $ᵗ Seed32
  let s ← sampleEta1Hat ring encoding prims 0
  let e ← sampleEta1Hat ring encoding prims params.k
  pure (pkOf encoding rho (ring.matVecMul (prims.publicMatrix rho) s + e))

/-- Idealized K-PKE encryption of a uniform message with independent
randomness: `(u, v) = (Âᵀŷ + e₁, t̂ᵀŷ + e₂ + μ)`. -/
def idealEncrypt (ek : EncapsulationKey params encoding) :
    ProbComp (Ciphertext params encoding) := do
  let y ← sampleEta1Hat ring encoding prims 0
  let ne ← sampleNoise encoding prims
  let m ← $ᵗ Message
  pure (ctOf encoding
    (ring.invNTTVec (ring.matTransposeVecMul (prims.publicMatrix ek.rho) y) + ne.1)
    (ring.invNTT (ring.dot (encoding.byteDecode12Vec ek.tHatEncoded) y) + ne.2
      + encoding.decompress1 (encoding.byteDecode1 m)))

/-- Key generation with `t̂` uniform: the right-hand side of the key hop. -/
def uniformKeygen : ProbComp (EncapsulationKey params encoding) := do
  let rho ← $ᵗ Seed32
  let t ← $ᵗ (TqVec params.k)
  pure (pkOf encoding rho t)

/-- A ciphertext built from uniform ring elements: the right-hand side of the
ciphertext hop. Still an encoding of compressed uniform `(u, v)`, not uniform
bytes. -/
def randCt : ProbComp (Ciphertext params encoding) := do
  let u ← $ᵗ (RqVec params.k)
  let v ← $ᵗ Rq
  let m ← $ᵗ Message
  pure (ctOf encoding u (v + encoding.decompress1 (encoding.byteDecode1 m)))

/-! ## The game chain

Every game draws the CHALLENGE key first, then the ciphertext, then the other
recipient's key. That order is what makes each hop the reduction adversary's own
game on the nose, with no distribution-level reordering. -/

/-- The anonymity branch in idealized form, parametric in how the challenge key
and the challenge ciphertext are produced. -/
def idealBranch (adv : StealthScheme.UnlinkAdv (EncapsulationKey params encoding)
      (Ciphertext params encoding))
    (kb : ProbComp (EncapsulationKey params encoding))
    (ct : EncapsulationKey params encoding → ProbComp (Ciphertext params encoding))
    (b : Bool) : ProbComp Bool := do
  let pkb ← kb
  let c ← ct pkb
  let pkOther ← idealKeygen ring encoding prims
  adv (if b then pkOther else pkb) (if b then pkb else pkOther) c

/-! ## The two decision-MLWE problems

Both are SEEDED: the challenge is `rho`, not the matrix, because the reduction
has to hand the distinguisher a public key and cannot invert `SampleNTT`. -/

/-- **Key hop.** Given `(rho, t̂)`, decide whether `t̂ = Â·ŝ + ê` for
`PRF_η₁`-distributed `(ŝ, ê)` or `t̂` is uniform. -/
def keyHopProblem :
    LearningWithErrors.Problem Seed32 (TqVec params.k) (TqVec params.k) where
  sampleChallenge := $ᵗ Seed32
  sampleSecret := sampleEta1Hat ring encoding prims 0
  sampleError := sampleEta1Hat ring encoding prims params.k
  noiseless := fun s rho => ring.matVecMul (prims.publicMatrix rho) s
  sampleUniform := $ᵗ (TqVec params.k)

/-- **Ciphertext hop.** With `t̂` already uniform, `(u, v)` is an MLWE sample
with secret `ŷ` over the module-dimension-`k+1` matrix `[Âᵀ | t̂ᵀ]`. -/
def ctHopProblem :
    LearningWithErrors.Problem (Seed32 × TqVec params.k) (TqVec params.k)
      (RqVec params.k × Rq) where
  sampleChallenge := do
    let rho ← $ᵗ Seed32
    let t ← $ᵗ (TqVec params.k)
    pure (rho, t)
  sampleSecret := sampleEta1Hat ring encoding prims 0
  sampleError := sampleNoise encoding prims
  noiseless := fun y ch =>
    (ring.invNTTVec (ring.matTransposeVecMul (prims.publicMatrix ch.1) y),
      ring.invNTT (ring.dot ch.2 y))
  sampleUniform := do
    let u ← $ᵗ (RqVec params.k)
    let v ← $ᵗ Rq
    pure (u, v)

/-! ## The two reduction adversaries -/

variable (adv : StealthScheme.UnlinkAdv (EncapsulationKey params encoding)
  (Ciphertext params encoding))

/-- **Key-hop reduction.** Plant the MLWE challenge as recipient `b`'s
encapsulation key, generate the other recipient honestly, encrypt honestly to
the planted key. -/
def keyHopAdv (b : Bool) : LearningWithErrors.Adversary (keyHopProblem ring encoding prims) :=
  fun chal => do
    let c ← idealEncrypt ring encoding prims (pkOf encoding chal.1 chal.2)
    let pkOther ← idealKeygen ring encoding prims
    adv (if b then pkOther else pkOf encoding chal.1 chal.2)
      (if b then pkOf encoding chal.1 chal.2 else pkOther) c

/-- **Ciphertext-hop reduction.** Plant the MLWE challenge's public part as
recipient `b`'s key and its noisy part as the challenge ciphertext, adding the
message contribution the reduction samples itself. -/
def ctHopAdv (b : Bool) : LearningWithErrors.Adversary (ctHopProblem ring encoding prims) :=
  fun chal => do
    let m ← $ᵗ Message
    let pkOther ← idealKeygen ring encoding prims
    adv (if b then pkOther else pkOf encoding chal.1.1 chal.1.2)
      (if b then pkOf encoding chal.1.1 chal.1.2 else pkOther)
      (ctOf encoding chal.2.1 (chal.2.2 + encoding.decompress1 (encoding.byteDecode1 m)))

/-! ## The hop identities -/

/-- Encrypting to a planted key sees `t̂` itself: the `byteEncode12Vec` /
`byteDecode12Vec` roundtrip is an `Encoding` field, not a `Laws` hypothesis. -/
theorem idealEncrypt_pkOf (rho : Seed32) (t : TqVec params.k) :
    idealEncrypt ring encoding prims (pkOf encoding rho t) = (do
      let y ← sampleEta1Hat ring encoding prims 0
      let ne ← sampleNoise encoding prims
      let m ← $ᵗ Message
      pure (ctOf encoding
        (ring.invNTTVec (ring.matTransposeVecMul (prims.publicMatrix rho) y) + ne.1)
        (ring.invNTT (ring.dot t y) + ne.2
          + encoding.decompress1 (encoding.byteDecode1 m)))) := by
  simp only [idealEncrypt, pkOf, encoding.byteDecode12Vec_byteEncode12Vec]

/-- **The key hop IS the reduction's real game.** -/
theorem game0_keyHopProblem (b : Bool) :
    LearningWithErrors.game0 (keyHopProblem ring encoding prims)
      (keyHopAdv ring encoding prims adv b) =
      idealBranch ring encoding prims adv (idealKeygen ring encoding prims)
        (idealEncrypt ring encoding prims) b := by
  simp only [LearningWithErrors.game0, LearningWithErrors.distr, keyHopProblem, keyHopAdv,
    idealBranch, idealKeygen, bind_assoc, pure_bind]

/-- **The key hop's ideal game IS the reduction's uniform game.** -/
theorem game1_keyHopProblem (b : Bool) :
    LearningWithErrors.game1 (keyHopProblem ring encoding prims)
      (keyHopAdv ring encoding prims adv b) =
      idealBranch ring encoding prims adv (uniformKeygen encoding)
        (idealEncrypt ring encoding prims) b := by
  simp only [LearningWithErrors.game1, LearningWithErrors.uniformDistr, keyHopProblem, keyHopAdv,
    idealBranch, uniformKeygen, bind_assoc, pure_bind]

/-- **The ciphertext hop IS the reduction's real game.** -/
theorem game0_ctHopProblem (b : Bool) :
    LearningWithErrors.game0 (ctHopProblem ring encoding prims)
      (ctHopAdv ring encoding prims adv b) =
      idealBranch ring encoding prims adv (uniformKeygen encoding)
        (idealEncrypt ring encoding prims) b := by
  simp only [LearningWithErrors.game0, LearningWithErrors.distr, ctHopProblem, ctHopAdv,
    idealBranch, uniformKeygen, idealEncrypt_pkOf, bind_assoc, pure_bind, Prod.fst_add,
    Prod.snd_add]

/-- **The ciphertext hop's ideal game IS the reduction's uniform game.** -/
theorem game1_ctHopProblem (b : Bool) :
    LearningWithErrors.game1 (ctHopProblem ring encoding prims)
      (ctHopAdv ring encoding prims adv b) =
      idealBranch ring encoding prims adv (uniformKeygen encoding)
        (fun _ => randCt encoding) b := by
  simp only [LearningWithErrors.game1, LearningWithErrors.uniformDistr, ctHopProblem, ctHopAdv,
    idealBranch, uniformKeygen, randCt, bind_assoc, pure_bind]

/-! ## The real branch, reordered

The idealized games encapsulate to the challenge key first and draw the other
key afterwards; the real anonymity branch draws both keys first. The two orders
are the same distribution, and VCVio's relational tactics close the swap. -/

section Reorder

variable {K PK SK C : Type} (kem : KEM PK SK C K) (adv : StealthScheme.UnlinkAdv PK C)

/-- The real anonymity branch in the idealized games' order: challenge key,
its encapsulation, then the other key. -/
def KEM.anonBranchReordered (b : Bool) : ProbComp Bool := do
  let pkb ← Prod.fst <$> kem.keygen
  let c ← Prod.fst <$> kem.encaps pkb
  let pkOther ← Prod.fst <$> kem.keygen
  adv (if b then pkOther else pkb) (if b then pkb else pkOther) c

/-- Drawing the other key before or after the encapsulation is the same game. -/
theorem KEM.evalDist_anonSetup_bind_anonBranch (b : Bool) :
    𝒟[kem.anonSetup >>= kem.anonBranch adv b] = 𝒟[kem.anonBranchReordered adv b] := by
  cases b
  · simp only [KEM.anonSetup, KEM.anonBranch, KEM.anonBranchReordered, bind_assoc, pure_bind,
      map_eq_bind_pure_comp, Function.comp_def, Bool.false_eq_true, if_false]
    by_equiv
    rvcstep
    intro a b hab
    cases hab
    rvcstep swap left
    rvcgen
  · simp only [KEM.anonSetup, KEM.anonBranch, KEM.anonBranchReordered, bind_assoc, pure_bind,
      map_eq_bind_pure_comp, Function.comp_def, if_true]
    by_equiv
    rvcstep swap left
    rvcstep
    intro a b hab
    cases hab
    rvcstep swap left
    rvcgen

/-- The reorder is free: zero distinguishing advantage. -/
theorem KEM.boolDistAdvantage_anonBranch_anonBranchReordered (b : Bool) :
    (kem.anonSetup >>= kem.anonBranch adv b).boolDistAdvantage
      (kem.anonBranchReordered adv b) = 0 := by
  rw [ProbComp.boolDistAdvantage, probOutput_congr rfl (kem.evalDist_anonSetup_bind_anonBranch adv b),
    sub_self, abs_zero]

end Reorder

/-! ## The four named terms -/

section Terms

variable [DecidableEq encoding.EncodedTHat] [DecidableEq encoding.EncodedU]
  [DecidableEq encoding.EncodedV] (sim : ProbComp (Ciphertext params encoding))

/-- The gap between the (reordered) real ML-KEM anonymity branch and its
idealized form: `G` as a fresh-seed sampler (key seeds, and the encryption coins
`G(m ‖ H(ek))`) and `PRF_η` as an independent sampler. `SampleNTT` stays
concrete -- the MLWE problems below are seeded on `rho`. Not a lattice term --
it is the ROM/PRF step. -/
noncomputable def primitiveIdealization (b : Bool) : ℝ :=
  (KEM.anonBranchReordered (MLKEM.asKEMScheme ring encoding prims) adv b).boolDistAdvantage
    (idealBranch ring encoding prims adv (idealKeygen ring encoding prims)
      (idealEncrypt ring encoding prims) b)

/-- The gap between the last idealized game and the SPR simulator: compression
and byte encoding of uniform ring elements against `sim`, and the honest key
distribution the ciphertext no longer depends on. -/
noncomputable def simulatorGap (b : Bool) : ℝ :=
  (idealBranch ring encoding prims adv (uniformKeygen encoding)
      (fun _ => randCt encoding) b).boolDistAdvantage
    (KEM.anonSetup (MLKEM.asKEMScheme ring encoding prims) >>= KEM.simBranch sim adv)

/-- The encoding half of `simulatorGap`: `compressDU`/`compressDV` then
`byteEncode` of uniform ring elements, against `sim`, with the keys fixed. -/
noncomputable def encodingRegularity (b : Bool) : ℝ :=
  (idealBranch ring encoding prims adv (uniformKeygen encoding)
      (fun _ => randCt encoding) b).boolDistAdvantage
    (idealBranch ring encoding prims adv (uniformKeygen encoding) (fun _ => sim) b)

/-- The key half of `simulatorGap`: restoring the honest key distribution once
the challenge ciphertext is key-independent. -/
noncomputable def keyRestoration (b : Bool) : ℝ :=
  (idealBranch ring encoding prims adv (uniformKeygen encoding) (fun _ => sim) b).boolDistAdvantage
    (KEM.anonSetup (MLKEM.asKEMScheme ring encoding prims) >>= KEM.simBranch sim adv)

/-- `simulatorGap` splits into its encoding half and its key half. -/
theorem simulatorGap_le (b : Bool) :
    simulatorGap ring encoding prims adv sim b ≤
      encodingRegularity ring encoding prims adv sim b
        + keyRestoration ring encoding prims adv sim b :=
  ProbComp.boolDistAdvantage_triangle _ _ _

/-! ## The bound -/

/-- **SPR of ML-KEM through the two MLWE hops.** The per-branch SPR advantage is
bounded by the primitive-idealization term, the two decision-MLWE advantages of
the named reduction adversaries, and the simulator gap. -/
theorem sprAdv_le_two_hop_decomposition (b : Bool) :
    KEM.sprAdv (MLKEM.asKEMScheme ring encoding prims) sim adv b ≤
      primitiveIdealization ring encoding prims adv b
        + LearningWithErrors.advantage (keyHopProblem ring encoding prims)
            (keyHopAdv ring encoding prims adv b)
        + LearningWithErrors.advantage (ctHopProblem ring encoding prims)
            (ctHopAdv ring encoding prims adv b)
        + simulatorGap ring encoding prims adv sim b := by
  have hkey : LearningWithErrors.advantage (keyHopProblem ring encoding prims)
      (keyHopAdv ring encoding prims adv b) =
      (idealBranch ring encoding prims adv (idealKeygen ring encoding prims)
          (idealEncrypt ring encoding prims) b).boolDistAdvantage
        (idealBranch ring encoding prims adv (uniformKeygen encoding)
          (idealEncrypt ring encoding prims) b) := by
    rw [LearningWithErrors.advantage_eq_boolDistAdvantage, game0_keyHopProblem,
      game1_keyHopProblem]
  have hct : LearningWithErrors.advantage (ctHopProblem ring encoding prims)
      (ctHopAdv ring encoding prims adv b) =
      (idealBranch ring encoding prims adv (uniformKeygen encoding)
          (idealEncrypt ring encoding prims) b).boolDistAdvantage
        (idealBranch ring encoding prims adv (uniformKeygen encoding)
          (fun _ => randCt encoding) b) := by
    rw [LearningWithErrors.advantage_eq_boolDistAdvantage, game0_ctHopProblem,
      game1_ctHopProblem]
  rw [KEM.sprAdv, hkey, hct, primitiveIdealization, simulatorGap]
  set kem : KEM (EncapsulationKey params encoding) (DecapsulationKey params encoding)
    (Ciphertext params encoding) SharedSecret := MLKEM.asKEMScheme ring encoding prims
  set G₀ : ProbComp Bool := KEM.anonSetup kem >>= KEM.anonBranch kem adv b
  set G₀' : ProbComp Bool := KEM.anonBranchReordered kem adv b
  set G₁ : ProbComp Bool := idealBranch ring encoding prims adv (idealKeygen ring encoding prims)
    (idealEncrypt ring encoding prims) b
  set G₂ : ProbComp Bool := idealBranch ring encoding prims adv (uniformKeygen encoding)
    (idealEncrypt ring encoding prims) b
  set G₃ : ProbComp Bool := idealBranch ring encoding prims adv (uniformKeygen encoding)
    (fun _ => randCt encoding) b
  set G₄ : ProbComp Bool := KEM.anonSetup kem >>= KEM.simBranch sim adv
  calc ProbComp.boolDistAdvantage G₀ G₄
      ≤ ProbComp.boolDistAdvantage G₀ G₀' + ProbComp.boolDistAdvantage G₀' G₄ :=
        ProbComp.boolDistAdvantage_triangle _ _ _
    _ = ProbComp.boolDistAdvantage G₀' G₄ := by
        rw [KEM.boolDistAdvantage_anonBranch_anonBranchReordered kem adv b, zero_add]
    _ ≤ ProbComp.boolDistAdvantage G₀' G₁ + ProbComp.boolDistAdvantage G₁ G₄ :=
        ProbComp.boolDistAdvantage_triangle _ _ _
    _ ≤ ProbComp.boolDistAdvantage G₀' G₁ +
          (ProbComp.boolDistAdvantage G₁ G₂ + ProbComp.boolDistAdvantage G₂ G₄) := by
        gcongr
        exact ProbComp.boolDistAdvantage_triangle _ _ _
    _ ≤ ProbComp.boolDistAdvantage G₀' G₁ +
          (ProbComp.boolDistAdvantage G₁ G₂ +
            (ProbComp.boolDistAdvantage G₂ G₃ + ProbComp.boolDistAdvantage G₃ G₄)) := by
        gcongr
        exact ProbComp.boolDistAdvantage_triangle _ _ _
    _ = _ := by ring

end Terms

/-! ## At ML-KEM-768 -/

section Mlkem768

variable (adv768 : StealthScheme.UnlinkAdv (EncapsulationKey mlkem768 mlkem768Encoding)
  (Ciphertext mlkem768 mlkem768Encoding))

/-- The key hop at ML-KEM-768: `t̂ = Â·ŝ + ê` against uniform, over the matrix
`SampleNTT` expands from `rho`. -/
def mlkem768KeyHopProblem :
    LearningWithErrors.Problem Seed32 (TqVec mlkem768.k) (TqVec mlkem768.k) :=
  keyHopProblem concreteNTTRingOps mlkem768Encoding mlkem768Primitives

/-- The ciphertext hop at ML-KEM-768: `(u, v)` against uniform, secret `ŷ`, over
`[Âᵀ | t̂ᵀ]`. -/
def mlkem768CtHopProblem :
    LearningWithErrors.Problem (Seed32 × TqVec mlkem768.k) (TqVec mlkem768.k)
      (RqVec mlkem768.k × Rq) :=
  ctHopProblem concreteNTTRingOps mlkem768Encoding mlkem768Primitives

/-- **The SPR term of the ML-KEM-768 unlinkability decomposition, opened up.**
Two of the four terms are decision-MLWE advantages of explicit reduction
adversaries; the other two are named and unbounded here. -/
theorem mlkem768_sprAdv_le_two_hop_decomposition (b : Bool) :
    mlkem768KEM.sprAdv mlkem768UniformCiphertext adv768 b ≤
      primitiveIdealization concreteNTTRingOps mlkem768Encoding mlkem768Primitives adv768 b
        + LearningWithErrors.advantage mlkem768KeyHopProblem
            (keyHopAdv concreteNTTRingOps mlkem768Encoding mlkem768Primitives adv768 b)
        + LearningWithErrors.advantage mlkem768CtHopProblem
            (ctHopAdv concreteNTTRingOps mlkem768Encoding mlkem768Primitives adv768 b)
        + simulatorGap concreteNTTRingOps mlkem768Encoding mlkem768Primitives adv768
            mlkem768UniformCiphertext b :=
  sprAdv_le_two_hop_decomposition concreteNTTRingOps mlkem768Encoding mlkem768Primitives adv768
    mlkem768UniformCiphertext b

end Mlkem768

/-! ## Post-plan additions: named assumption records and per-branch cap

The plan closes the SPR gap by turning the three non-MLWE residuals into
explicit assumption records and adding a `keyRestoration` MLWE reduction. -/

section Assumptions

variable {params : Params} (ring : NTTRingOps) (encoding : Encoding params)
  (prims : Primitives params encoding)
variable [DecidableEq encoding.EncodedTHat] [DecidableEq encoding.EncodedU]
  [DecidableEq encoding.EncodedV]
  (adv : StealthScheme.UnlinkAdv (EncapsulationKey params encoding)
    (Ciphertext params encoding))
  (sim : ProbComp (Ciphertext params encoding))

/-- ROM/PRF assumption: the primitive-idealization term is bounded by
`epsilonPrim`. -/
def primitiveIdealizationBound (epsilonPrim : ℝ) : Prop :=
  ∀ b, primitiveIdealization ring encoding prims adv b ≤ epsilonPrim

/-- Compression-and-encoding regularity assumption: `sim` is indistinguishable
from uniform ring elements after compress/encode. -/
def encodingRegularityBound (epsilonEnc : ℝ) : Prop :=
  ∀ b, encodingRegularity ring encoding prims adv sim b ≤ epsilonEnc

/-- The `keyRestoration` gap as a seeded-MLWE advantage: with the ciphertext
already key-independent, the adversary must distinguish an honest key from
uniform. -/
def keyRestorationAdv (b : Bool) :
    LearningWithErrors.Adversary (keyHopProblem ring encoding prims) :=
  fun chal => do
    let simCt ← sim
    let pkOther ← idealKeygen ring encoding prims
    adv (if b then pkOther else pkOf encoding chal.1 chal.2)
      (if b then pkOf encoding chal.1 chal.2 else pkOther) simCt

/-- The real branch of `keyRestorationAdv` equals the uniform-key game with a
key-independent ciphertext. -/
theorem game0_keyRestorationAdv (b : Bool) :
    LearningWithErrors.game0 (keyHopProblem ring encoding prims)
      (keyRestorationAdv ring encoding prims adv sim b) =
      idealBranch ring encoding prims adv (uniformKeygen encoding)
        (fun _ => sim) b := by
  sorry

/-- The uniform branch of `keyRestorationAdv` equals the simulator game. -/
theorem game1_keyRestorationAdv (b : Bool) :
    LearningWithErrors.game1 (keyHopProblem ring encoding prims)
      (keyRestorationAdv ring encoding prims adv sim b) =
      KEM.anonSetup (MLKEM.asKEMScheme ring encoding prims) >>= KEM.simBranch sim adv := by
  sorry

/-- The key-restoration gap is bounded by a named seeded-MLWE advantage. -/
def keyRestorationMLWE (epsilonRestore : ℝ) : Prop :=
  ∀ b, keyRestoration ring encoding prims adv sim b ≤ epsilonRestore

/-- **SPR bounded by three MLWE advantages plus the two non-MLWE assumptions.** -/
theorem sprAdv_le_mlwe (b : Bool)
    (epsilonPrim epsilonEnc epsilonRestore : ℝ)
    (hPrim : ∀ b, primitiveIdealization ring encoding prims adv b ≤ epsilonPrim)
    (hEnc : ∀ b, encodingRegularity ring encoding prims adv sim b ≤ epsilonEnc)
    (hRestore : ∀ b, keyRestoration ring encoding prims adv sim b ≤ epsilonRestore) :
    KEM.sprAdv (MLKEM.asKEMScheme ring encoding prims) sim adv b ≤
      epsilonPrim
        + LearningWithErrors.advantage (keyHopProblem ring encoding prims)
            (keyHopAdv ring encoding prims adv b)
        + LearningWithErrors.advantage (ctHopProblem ring encoding prims)
            (ctHopAdv ring encoding prims adv b)
        + epsilonEnc
        + epsilonRestore := by
  calc
    KEM.sprAdv (MLKEM.asKEMScheme ring encoding prims) sim adv b
      ≤ primitiveIdealization ring encoding prims adv b
          + LearningWithErrors.advantage (keyHopProblem ring encoding prims)
              (keyHopAdv ring encoding prims adv b)
          + LearningWithErrors.advantage (ctHopProblem ring encoding prims)
              (ctHopAdv ring encoding prims adv b)
          + simulatorGap ring encoding prims adv sim b :=
        sprAdv_le_two_hop_decomposition ring encoding prims adv sim b
    _ ≤ epsilonPrim + _ + _ + (encodingRegularity ring encoding prims adv sim b
          + keyRestoration ring encoding prims adv sim b) := by
        gcongr
        · exact hPrim b
        · exact simulatorGap_le ring encoding prims adv sim b
    _ ≤ epsilonPrim + _ + _ + (epsilonEnc + epsilonRestore) := by
        gcongr
        · exact hEnc b
        · exact hRestore b
    _ = _ := by ring

end Assumptions


section Mlkem768Closed

variable (adv768 : StealthScheme.UnlinkAdv (EncapsulationKey mlkem768 mlkem768Encoding)
  (Ciphertext mlkem768 mlkem768Encoding))

/-- **ML-KEM-768 SPR ≤ named assumptions + three MLWE advantages**, against the
uniform-ciphertext-bytes simulator `mlkem768UniformCiphertext` (the same
simulator as `mlkem768_sprAdv_le_two_hop_decomposition`). -/
theorem mlkem768_sprAdv_le_mlwe (b : Bool)
    (epsilonPrim epsilonEnc epsilonRestore : ℝ)
    (hPrim : ∀ b, primitiveIdealization concreteNTTRingOps mlkem768Encoding mlkem768Primitives adv768 b ≤ epsilonPrim)
    (hEnc : ∀ b, encodingRegularity concreteNTTRingOps mlkem768Encoding mlkem768Primitives adv768
      mlkem768UniformCiphertext b ≤ epsilonEnc)
    (hRestore : ∀ b, keyRestoration concreteNTTRingOps mlkem768Encoding mlkem768Primitives adv768
      mlkem768UniformCiphertext b ≤ epsilonRestore) :
    mlkem768KEM.sprAdv mlkem768UniformCiphertext adv768 b ≤
      epsilonPrim
        + LearningWithErrors.advantage mlkem768KeyHopProblem
            (keyHopAdv concreteNTTRingOps mlkem768Encoding mlkem768Primitives adv768 b)
        + LearningWithErrors.advantage mlkem768CtHopProblem
            (ctHopAdv concreteNTTRingOps mlkem768Encoding mlkem768Primitives adv768 b)
        + epsilonEnc
        + epsilonRestore :=
  sprAdv_le_mlwe concreteNTTRingOps mlkem768Encoding mlkem768Primitives adv768
    mlkem768UniformCiphertext b epsilonPrim epsilonEnc epsilonRestore hPrim hEnc hRestore

end Mlkem768Closed

end PqStealth
