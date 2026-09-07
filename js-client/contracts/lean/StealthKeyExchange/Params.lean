/-!
# The key-exchange parameter table

Mirror of the constants and pure functions of `src/StealthKeyExchange.sol`: the
discovery-KEM parameter sets, their byte sizes (FIPS 203 Table 3; the X-Wing
draft for the PQ/T hybrid, D-017), the paired ML-DSA set's packed `t`, and the
length-to-set lookups the contract uses to type a ciphertext or an
encapsulation key. `scripts/check_constants.py` fails the build if a number
here drifts from the Solidity source or from the conformance vectors.
-/

namespace StealthKeyExchange

/-- ERC-5564 scheme ID of the post-quantum scheme (`SCHEME_ID`). -/
def schemeId : Nat := 2

/-- `metadata[0]` is the view tag (`VIEW_TAG_BYTES`). -/
def viewTagBytes : Nat := 1

/-- Discovery-KEM parameter sets — `enum Kem` in the contract, in the same order
(so the constructor index is the ABI value). -/
inductive Kem where
  /-- ML-KEM-512, paired with ML-DSA-44 (NIST level 1). -/
  | mlkem512
  /-- ML-KEM-768, paired with ML-DSA-65 (level 3) — the default and only MUST. -/
  | mlkem768
  /-- ML-KEM-1024, paired with ML-DSA-87 (level 5). -/
  | mlkem1024
  /-- MLKEM768-X25519 (X-Wing), the optional PQ/T hybrid; spending stays ML-DSA-65. -/
  | xwing
  deriving DecidableEq, Repr, Inhabited

/-- Ciphertext (`ephemeralPubKey`) length in bytes (`ciphertextBytes`). -/
def Kem.ciphertextBytes : Kem → Nat
  | .mlkem512 => 768
  | .mlkem768 => 1088
  | .mlkem1024 => 1568
  | .xwing => 1120

/-- Encapsulation (viewing) key length in bytes (`encapsulationKeyBytes`). -/
def Kem.encapsulationKeyBytes : Kem → Nat
  | .mlkem512 => 800
  | .mlkem768 => 1184
  | .mlkem1024 => 1568
  | .xwing => 1216

/-- Packed full-precision `t` of the paired ML-DSA set, `k · 256 · 23 / 8`
(`packedTBytes`). -/
def Kem.packedTBytes : Kem → Nat
  | .mlkem512 => 2944
  | .mlkem1024 => 5888
  | .mlkem768 => 4416
  | .xwing => 4416

/-- Meta-address version byte of the FIPS 203 sets (`META_VERSION_MLKEM`). -/
def metaVersionMlkem : UInt8 := 0x01

/-- Meta-address version byte of the hybrid set (`META_VERSION_XWING`). -/
def metaVersionXwing : UInt8 := 0x02

/-- Meta-address version byte of a set (`metaAddressVersion`). -/
def Kem.metaAddressVersion : Kem → UInt8
  | .xwing => metaVersionXwing
  | _ => metaVersionMlkem

/-- `version(1) ‖ rho(32) ‖ pack23(t) ‖ ek` (`metaAddressBytes`). -/
def Kem.metaAddressBytes (k : Kem) : Nat :=
  1 + 32 + k.packedTBytes + k.encapsulationKeyBytes

/-- The set whose ciphertext has `n` bytes (`kemOfCiphertextLength`; `none`
where the contract reverts with `UnsupportedCiphertextLength`). -/
def kemOfCiphertextLength (n : Nat) : Option Kem :=
  if n = 1088 then some .mlkem768
  else if n = 1120 then some .xwing
  else if n = 768 then some .mlkem512
  else if n = 1568 then some .mlkem1024
  else none

/-- The set whose encapsulation key has `n` bytes (`kemOfEncapsulationKeyLength`). -/
def kemOfEncapsulationKeyLength (n : Nat) : Option Kem :=
  if n = 1184 then some .mlkem768
  else if n = 1216 then some .xwing
  else if n = 800 then some .mlkem512
  else if n = 1568 then some .mlkem1024
  else none

/-! ## The table is consistent: every lookup inverts its size function -/

/-- A ciphertext of a set's length is typed as that set. -/
theorem kemOfCiphertextLength_ciphertextBytes (k : Kem) :
    kemOfCiphertextLength k.ciphertextBytes = some k := by
  cases k <;> rfl

/-- An encapsulation key of a set's length is typed as that set. -/
theorem kemOfEncapsulationKeyLength_encapsulationKeyBytes (k : Kem) :
    kemOfEncapsulationKeyLength k.encapsulationKeyBytes = some k := by
  cases k <;> rfl

/-- The lookup succeeds exactly on the four ciphertext lengths, and returns the
set with that length: the ciphertext lengths are pairwise distinct, so the
ciphertext identifies its parameter set. -/
theorem kemOfCiphertextLength_eq_some_iff {n : Nat} {k : Kem} :
    kemOfCiphertextLength n = some k ↔ n = k.ciphertextBytes := by
  constructor
  · intro h
    unfold kemOfCiphertextLength at h
    split at h
    · cases Option.some.inj h; assumption
    · split at h
      · cases Option.some.inj h; assumption
      · split at h
        · cases Option.some.inj h; assumption
        · split at h
          · cases Option.some.inj h; assumption
          · exact nomatch h
  · intro h
    subst h
    exact kemOfCiphertextLength_ciphertextBytes k

/-- Same for encapsulation keys. -/
theorem kemOfEncapsulationKeyLength_eq_some_iff {n : Nat} {k : Kem} :
    kemOfEncapsulationKeyLength n = some k ↔ n = k.encapsulationKeyBytes := by
  constructor
  · intro h
    unfold kemOfEncapsulationKeyLength at h
    split at h
    · cases Option.some.inj h; assumption
    · split at h
      · cases Option.some.inj h; assumption
      · split at h
        · cases Option.some.inj h; assumption
        · split at h
          · cases Option.some.inj h; assumption
          · exact nomatch h
  · intro h
    subst h
    exact kemOfEncapsulationKeyLength_encapsulationKeyBytes k

/-- The size functions are injective: no two sets share a ciphertext length. -/
theorem Kem.ciphertextBytes_injective {a b : Kem}
    (h : a.ciphertextBytes = b.ciphertextBytes) : a = b := by
  have := kemOfCiphertextLength_eq_some_iff.mpr h
  rw [kemOfCiphertextLength_ciphertextBytes] at this
  exact Option.some.inj this

/-- No two sets share an encapsulation-key length either. -/
theorem Kem.encapsulationKeyBytes_injective {a b : Kem}
    (h : a.encapsulationKeyBytes = b.encapsulationKeyBytes) : a = b := by
  have := kemOfEncapsulationKeyLength_eq_some_iff.mpr h
  rw [kemOfEncapsulationKeyLength_encapsulationKeyBytes] at this
  exact Option.some.inj this

/-! ## The ERC draft's numbers, by `rfl` -/

/-- The default set's meta-address: `1 + 32 + 4416 + 1184 = 5633`. -/
theorem metaAddressBytes_mlkem768 : Kem.mlkem768.metaAddressBytes = 5633 := rfl

/-- The hybrid set's meta-address: `1 + 32 + 4416 + 1216 = 5665`. -/
theorem metaAddressBytes_xwing : Kem.xwing.metaAddressBytes = 5665 := rfl

/-- Level 1: `1 + 32 + 2944 + 800 = 3777`. -/
theorem metaAddressBytes_mlkem512 : Kem.mlkem512.metaAddressBytes = 3777 := rfl

/-- Level 5: `1 + 32 + 5888 + 1568 = 7489`. -/
theorem metaAddressBytes_mlkem1024 : Kem.mlkem1024.metaAddressBytes = 7489 := rfl

/-- The meta-address lengths are pairwise distinct as well, so together with the
version byte a meta-address identifies its set. -/
theorem Kem.metaAddressBytes_injective {a b : Kem}
    (h : a.metaAddressBytes = b.metaAddressBytes) : a = b := by
  cases a <;> cases b <;> first | rfl | exact absurd h (by decide)

end StealthKeyExchange
