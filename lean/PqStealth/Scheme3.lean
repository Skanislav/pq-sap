import PqStealth.HybridKEM

/-!
# ERC-8441 scheme 3 announcement model

This module gives the scheme-3 wire-level objects a typed Lean model and lifts
the parallel ECDH/ML-KEM construction from `HybridKEM`. The component KEMs,
their public-key reconstruction functions, and the specified domain-separated
combiner are parameters. It proves that component correctness transfers through
the hybrid KEM and into scanning, and that scheme 3 is an instance of the
existing full-announcement unlinkability theorem.

The byte encoding of `epk || ct` is intentionally outside this model. Its
fixed-width parsing and point/key validation are syntax obligations of the ERC;
here `Scheme3Ciphertext` is the corresponding typed value.
-/

open OracleComp OracleSpec

namespace PqStealth

/-! ## Typed scheme-3 values -/

/-- ERC-8441's registered meta-address, before byte serialization:
`spending_pk || viewing_pk_ec || ek`. -/
structure Scheme3MetaAddress (SpendingPub ViewingPub EncapsulationKey : Type) where
  /-- The recipient's ordinary secp256k1 spending public key. -/
  spendingPub : SpendingPub
  /-- The recipient's secp256k1 ECDH viewing public key. -/
  viewingPub : ViewingPub
  /-- The recipient's checked ML-KEM encapsulation key. -/
  encapsulationKey : EncapsulationKey

/-- The scanner-delegable private state: the ECDH viewing secret and ML-KEM
tracking/decapsulation state. The master spending secret is deliberately absent. -/
structure Scheme3TrackingKey (ViewingSecret DecapsulationKey : Type) where
  /-- The private scalar corresponding to `Scheme3MetaAddress.viewingPub`. -/
  viewingSecret : ViewingSecret
  /-- The ML-KEM decapsulation/tracking key material. -/
  decapsulationKey : DecapsulationKey

/-- The typed counterpart of ERC-8441's `ephemeralPubKey = epk || ct` field. -/
structure Scheme3Ciphertext (EphemeralPub KemCiphertext : Type) where
  /-- The sender's fresh SEC1-encoded ephemeral public key. -/
  ephemeralPub : EphemeralPub
  /-- The ML-KEM ciphertext addressed to the recipient's encapsulation key. -/
  kemCiphertext : KemCiphertext

/-- A typed ERC-8441 announcement:
`(epk, ct, view_tag(ss), stealth_address(ss))`. -/
abbrev Scheme3Announcement (EphemeralPub KemCiphertext ViewTag Address : Type) :=
  Scheme3Ciphertext EphemeralPub KemCiphertext × (ViewTag × Address)

/-- The ERC-5564 `ephemeralPubKey` field before fixed-width concatenation. -/
def Scheme3Announcement.ephemeralPubKey {EphemeralPub KemCiphertext ViewTag Address : Type}
    (announcement : Scheme3Announcement EphemeralPub KemCiphertext ViewTag Address) :
    Scheme3Ciphertext EphemeralPub KemCiphertext :=
  announcement.1

/-- The one-byte view tag field. Its byte width is a serialization invariant. -/
def Scheme3Announcement.viewTag {EphemeralPub KemCiphertext ViewTag Address : Type}
    (announcement : Scheme3Announcement EphemeralPub KemCiphertext ViewTag Address) : ViewTag :=
  announcement.2.1

/-- The announced stealth address. -/
def Scheme3Announcement.stealthAddress {EphemeralPub KemCiphertext ViewTag Address : Type}
    (announcement : Scheme3Announcement EphemeralPub KemCiphertext ViewTag Address) : Address :=
  announcement.2.2

/-! ## Construction from an abstract hybrid KEM -/

/-- Scheme 3's public auxiliary data. The hybrid KEM is responsible for deriving
`hybridSecret` from `ECDH(esk, viewing_pk_ec)`, ML-KEM encapsulation, the domain
separator, and all six bound inputs. The address derivation receives the
recipient's spending public key, as in ERC-8441 §2.4. -/
def scheme3Aux {SpendingPub ViewingPub EncapsulationKey HybridSecret ViewTag Address : Type}
    (viewTag : HybridSecret → ViewTag)
    (stealthAddress : SpendingPub → HybridSecret → Address) :
    HybridSecret → Scheme3MetaAddress SpendingPub ViewingPub EncapsulationKey → ViewTag × Address :=
  fun sharedSecret metaAddress =>
    (viewTag sharedSecret, stealthAddress metaAddress.spendingPub sharedSecret)

/-- Lift a hybrid KEM on `(viewing_pk_ec, ek)` into the registered scheme-3
meta-address by generating the independent spending public key. The spending
secret stays outside the scanning KEM, as it does in ERC-8441. -/
def scheme3HybridKEM
    {SpendingPub ViewingPub EncapsulationKey ViewingSecret DecapsulationKey EphemeralPub KemCiphertext
      HybridSecret : Type}
    (spendingPubGen : ProbComp SpendingPub)
    (hybridKem : KEM (ViewingPub × EncapsulationKey) (ViewingSecret × DecapsulationKey)
      (EphemeralPub × KemCiphertext) HybridSecret) :
    KEM
      (Scheme3MetaAddress SpendingPub ViewingPub EncapsulationKey)
      (Scheme3TrackingKey ViewingSecret DecapsulationKey)
      (Scheme3Ciphertext EphemeralPub KemCiphertext)
      HybridSecret where
  keygen := do
    let spendingPub ← spendingPubGen
    let keys ← hybridKem.keygen
    pure ({ spendingPub, viewingPub := keys.1.1, encapsulationKey := keys.1.2 },
      { viewingSecret := keys.2.1, decapsulationKey := keys.2.2 })
  encaps := fun metaAddress => do
    let ck ← hybridKem.encaps (metaAddress.viewingPub, metaAddress.encapsulationKey)
    pure ({ ephemeralPub := ck.1.1, kemCiphertext := ck.1.2 }, ck.2)
  decaps := fun trackingKey ciphertext =>
    hybridKem.decaps (trackingKey.viewingSecret, trackingKey.decapsulationKey)
      (ciphertext.ephemeralPub, ciphertext.kemCiphertext)

/-- Support-level correctness transfers from a hybrid KEM on the viewing and
ML-KEM components to its scheme-3 meta-address adapter. -/
theorem scheme3HybridKEM_correctOnSupport
    {SpendingPub ViewingPub EncapsulationKey ViewingSecret DecapsulationKey EphemeralPub KemCiphertext
      HybridSecret : Type}
    (spendingPubGen : ProbComp SpendingPub)
    (hybridKem : KEM (ViewingPub × EncapsulationKey) (ViewingSecret × DecapsulationKey)
      (EphemeralPub × KemCiphertext) HybridSecret)
    (hcorrect : hybridKem.CorrectOnSupport) :
    (scheme3HybridKEM spendingPubGen hybridKem).CorrectOnSupport := by
  intro metaAddress trackingKey hkey ciphertext sharedSecret hciphertext secretOpt hdecaps
  rw [scheme3HybridKEM, support_bind] at hkey
  simp only [Set.mem_iUnion] at hkey
  obtain ⟨spendingPub, hspendingPub, hkey⟩ := hkey
  rw [support_bind] at hkey
  simp only [Set.mem_iUnion] at hkey
  obtain ⟨keys, hkeys, hkey⟩ := hkey
  simp only [support_pure, Set.mem_singleton_iff] at hkey
  have hmeta : metaAddress =
      { spendingPub, viewingPub := keys.1.1, encapsulationKey := keys.1.2 } :=
    congrArg Prod.fst hkey
  have htracking : trackingKey =
      { viewingSecret := keys.2.1, decapsulationKey := keys.2.2 } :=
    congrArg Prod.snd hkey
  subst metaAddress
  subst trackingKey
  rw [scheme3HybridKEM, support_bind] at hciphertext
  simp only [Set.mem_iUnion] at hciphertext
  obtain ⟨ck, hck, hciphertext⟩ := hciphertext
  simp only [support_pure, Set.mem_singleton_iff] at hciphertext
  have hcipher : ciphertext =
      { ephemeralPub := ck.1.1, kemCiphertext := ck.1.2 } :=
    congrArg Prod.fst hciphertext
  have hsecret : sharedSecret = ck.2 := congrArg Prod.snd hciphertext
  subst ciphertext
  have hOpt : secretOpt = some ck.2 :=
    hcorrect keys.1 keys.2 hkeys ck.1 ck.2 hck secretOpt hdecaps
  simpa only [hsecret] using hOpt

/-- Perfect correctness transfers through `scheme3HybridKEM`. -/
theorem scheme3HybridKEM_perfectlyCorrect
    {SpendingPub ViewingPub EncapsulationKey ViewingSecret DecapsulationKey EphemeralPub KemCiphertext
      HybridSecret : Type}
    [DecidableEq HybridSecret]
    (spendingPubGen : ProbComp SpendingPub)
    (hybridKem : KEM (ViewingPub × EncapsulationKey) (ViewingSecret × DecapsulationKey)
      (EphemeralPub × KemCiphertext) HybridSecret)
    (hcorrect : hybridKem.PerfectlyCorrect ProbCompRuntime.probComp) :
    (scheme3HybridKEM spendingPubGen hybridKem).PerfectlyCorrect ProbCompRuntime.probComp :=
  KEM.perfectlyCorrect_of_correctOnSupport _ <|
    scheme3HybridKEM_correctOnSupport spendingPubGen hybridKem
      (KEM.correctOnSupport_of_perfectlyCorrect hybridKem hcorrect)

/-- The concrete scheme-3 hybrid KEM shape: an ECDH component supplies `epk`
and `ss_ec`; an ML-KEM component supplies `ct` and `ss_pq`; `combine` is the
draft's fixed domain-separated combiner over both public keys, both ciphertexts,
and both component secrets. -/
def scheme3HybridKEMOfComponents
    {SpendingPub ViewingPub EncapsulationKey ViewingSecret DecapsulationKey EphemeralPub KemCiphertext
      EcdhSecret KemSecret HybridSecret : Type}
    (spendingPubGen : ProbComp SpendingPub)
    (ecdhKem : KEM ViewingPub ViewingSecret EphemeralPub EcdhSecret)
    (mlkem : KEM EncapsulationKey DecapsulationKey KemCiphertext KemSecret)
    (viewingPublicOfSecret : ViewingSecret → ViewingPub)
    (encapsulationPublicOfSecret : DecapsulationKey → EncapsulationKey)
    (combine : ViewingPub → EncapsulationKey → EphemeralPub → KemCiphertext →
      EcdhSecret → KemSecret → HybridSecret) :
    KEM
      (Scheme3MetaAddress SpendingPub ViewingPub EncapsulationKey)
      (Scheme3TrackingKey ViewingSecret DecapsulationKey)
      (Scheme3Ciphertext EphemeralPub KemCiphertext)
      HybridSecret :=
  scheme3HybridKEM spendingPubGen
    (KEM.parallel ecdhKem mlkem viewingPublicOfSecret encapsulationPublicOfSecret combine)

/-- Correctness of the ECDH and ML-KEM components propagates through the
bound-input combiner and into the scheme-3 scanner KEM. -/
theorem scheme3HybridKEMOfComponents_perfectlyCorrect
    {SpendingPub ViewingPub EncapsulationKey ViewingSecret DecapsulationKey EphemeralPub KemCiphertext
      EcdhSecret KemSecret HybridSecret : Type}
    [DecidableEq EcdhSecret] [DecidableEq KemSecret] [DecidableEq HybridSecret]
    (spendingPubGen : ProbComp SpendingPub)
    (ecdhKem : KEM ViewingPub ViewingSecret EphemeralPub EcdhSecret)
    (mlkem : KEM EncapsulationKey DecapsulationKey KemCiphertext KemSecret)
    (viewingPublicOfSecret : ViewingSecret → ViewingPub)
    (encapsulationPublicOfSecret : DecapsulationKey → EncapsulationKey)
    (combine : ViewingPub → EncapsulationKey → EphemeralPub → KemCiphertext →
      EcdhSecret → KemSecret → HybridSecret)
    (hviewing : ecdhKem.PublicKeyBound viewingPublicOfSecret)
    (hencapsulation : mlkem.PublicKeyBound encapsulationPublicOfSecret)
    (hecdh : ecdhKem.PerfectlyCorrect ProbCompRuntime.probComp)
    (hmlkem : mlkem.PerfectlyCorrect ProbCompRuntime.probComp) :
    (scheme3HybridKEMOfComponents spendingPubGen ecdhKem mlkem viewingPublicOfSecret
      encapsulationPublicOfSecret combine).PerfectlyCorrect ProbCompRuntime.probComp :=
  scheme3HybridKEM_perfectlyCorrect spendingPubGen _ <|
    KEM.parallel_perfectlyCorrect ecdhKem mlkem viewingPublicOfSecret
      encapsulationPublicOfSecret combine hviewing hencapsulation hecdh hmlkem

/-- ERC-8441 scheme 3, parameterized by its hybrid ECDH/ML-KEM KEM. The KEM's
public key is the registered meta-address, its private key is the tracking key,
its ciphertext is the typed `(epk, ct)` pair, and its shared key is the output
of the draft's hybrid combiner. -/
def StealthScheme.scheme3
    {SpendingPub ViewingPub EncapsulationKey ViewingSecret DecapsulationKey EphemeralPub KemCiphertext
      HybridSecret ViewTag Address : Type}
    [DecidableEq ViewTag] [DecidableEq Address]
    (hybridKem : KEM
      (Scheme3MetaAddress SpendingPub ViewingPub EncapsulationKey)
      (Scheme3TrackingKey ViewingSecret DecapsulationKey)
      (Scheme3Ciphertext EphemeralPub KemCiphertext)
      HybridSecret)
    (viewTag : HybridSecret → ViewTag)
    (stealthAddress : SpendingPub → HybridSecret → Address) :
    StealthScheme
      (Scheme3MetaAddress SpendingPub ViewingPub EncapsulationKey)
      (Scheme3TrackingKey ViewingSecret DecapsulationKey ×
        Scheme3MetaAddress SpendingPub ViewingPub EncapsulationKey)
      (Scheme3Announcement EphemeralPub KemCiphertext ViewTag Address) :=
  StealthScheme.ofKEMFull hybridKem (scheme3Aux viewTag stealthAddress)

/-- Sender-side expansion of `StealthScheme.scheme3.announce`: the hybrid KEM
emits the typed `(epk, ct)` pair and combined secret, then the announcement
contains the view tag and address derived from that same secret. -/
theorem scheme3_announce
    {SpendingPub ViewingPub EncapsulationKey ViewingSecret DecapsulationKey EphemeralPub KemCiphertext
      HybridSecret ViewTag Address : Type}
    [DecidableEq ViewTag] [DecidableEq Address]
    (hybridKem : KEM
      (Scheme3MetaAddress SpendingPub ViewingPub EncapsulationKey)
      (Scheme3TrackingKey ViewingSecret DecapsulationKey)
      (Scheme3Ciphertext EphemeralPub KemCiphertext)
      HybridSecret)
    (viewTag : HybridSecret → ViewTag)
    (stealthAddress : SpendingPub → HybridSecret → Address)
    (metaAddress : Scheme3MetaAddress SpendingPub ViewingPub EncapsulationKey) :
    (StealthScheme.scheme3 hybridKem viewTag stealthAddress).announce metaAddress =
      (do
        let ck ← hybridKem.encaps metaAddress
        pure (ck.1, (viewTag ck.2, stealthAddress metaAddress.spendingPub ck.2))) := rfl

/-- Scheme-3 detection is perfectly complete if the supplied hybrid KEM is
perfectly correct. This assumes the sender and scanner implement the same
hybrid combiner; it does not prove the combiner's security. -/
theorem scheme3_perfectlyComplete
    {SpendingPub ViewingPub EncapsulationKey ViewingSecret DecapsulationKey EphemeralPub KemCiphertext
      HybridSecret ViewTag Address : Type}
    [DecidableEq HybridSecret] [DecidableEq ViewTag] [DecidableEq Address]
    (hybridKem : KEM
      (Scheme3MetaAddress SpendingPub ViewingPub EncapsulationKey)
      (Scheme3TrackingKey ViewingSecret DecapsulationKey)
      (Scheme3Ciphertext EphemeralPub KemCiphertext)
      HybridSecret)
    (viewTag : HybridSecret → ViewTag)
    (stealthAddress : SpendingPub → HybridSecret → Address)
    (hkem : hybridKem.PerfectlyCorrect ProbCompRuntime.probComp) :
    (StealthScheme.scheme3 hybridKem viewTag stealthAddress).PerfectlyComplete :=
  perfectlyComplete_ofKEMFull hybridKem (scheme3Aux viewTag stealthAddress) hkem

/-- Scheme 3 inherits the full-announcement unlinkability decomposition. The
four terms make the dependency boundary explicit: two hybrid-secret hiding
terms, address/tag key-independence, and anonymity of the `(epk, ct)` hybrid
ciphertext. Bounds for the hybrid combiner and the component KEMs are separate
assumptions, not conclusions of this theorem. -/
theorem scheme3_unlinkAdvantage_le
    {SpendingPub ViewingPub EncapsulationKey ViewingSecret DecapsulationKey EphemeralPub KemCiphertext
      HybridSecret ViewTag Address : Type}
    [SampleableType HybridSecret] [DecidableEq ViewTag] [DecidableEq Address]
    (hybridKem : KEM
      (Scheme3MetaAddress SpendingPub ViewingPub EncapsulationKey)
      (Scheme3TrackingKey ViewingSecret DecapsulationKey)
      (Scheme3Ciphertext EphemeralPub KemCiphertext)
      HybridSecret)
    (viewTag : HybridSecret → ViewTag)
    (stealthAddress : SpendingPub → HybridSecret → Address)
    (adv : StealthScheme.UnlinkAdv
      (Scheme3MetaAddress SpendingPub ViewingPub EncapsulationKey)
      (Scheme3Announcement EphemeralPub KemCiphertext ViewTag Address)) :
    (StealthScheme.scheme3 hybridKem viewTag stealthAddress).unlinkAdvantage adv ≤
      sharedSecretHiding hybridKem (scheme3Aux viewTag stealthAddress) adv true
      + auxKeyIndependence hybridKem (scheme3Aux viewTag stealthAddress) adv
      + hybridKem.anonAdvantage (adv.cipherOf (scheme3Aux viewTag stealthAddress))
      + sharedSecretHiding hybridKem (scheme3Aux viewTag stealthAddress) adv false :=
  unlinkAdvantage_ofKEMFull_le hybridKem (scheme3Aux viewTag stealthAddress) adv

end PqStealth
