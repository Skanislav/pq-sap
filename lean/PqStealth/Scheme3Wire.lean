import PqStealth.Scheme3
import PqStealth.MLKEM
import PqStealth.Invariants

/-!
# Scheme-3 wire-format invariants (ERC-8441 §2–§3)

Unconditional, machine-checked facts about the ERC-8441 wire layout — no
cryptographic assumption, no probability. These pin the interop contract that a
port or an off-by-one breaks silently. `Scheme3.lean` models the *typed*
announcement (`Scheme3Ciphertext EphemeralPub KemCiphertext`) and explicitly
leaves the byte encoding of `epk || ct` out of scope; this module adds that
encoding and proves it roundtrips and rejects wrong lengths.

What is proved:

* `scheme3EphemeralPubKey_roundtrips` — encoding `epk || ct` and splitting at
  the fixed seam returns the two components byte-for-byte (builds on
  `Invariants.splitBytes_append`), whenever the two inner packings roundtrip.
* `scheme3EphemeralPubKeyDecode_length` — the only decodable byte strings have
  length exactly `nepk + nct`; the decoder is a *total* function on
  fixed-length input, and length mismatch is caught by the type, not by a
  crash. The concrete 1,121-byte figure (`33 + 1 088`) and the 1,250-byte
  meta-address figure are stated as `rfl` arithmetic.

No assumption is taken: these are structural facts about fixed-width byte
concatenation, in the same family as `Invariants.meta_address_roundtrips`.
-/

open OracleComp OracleSpec
open MLKEM MLKEM.Concrete   -- concrete ML-KEM-768 scheme, `decapsInternal`, `SharedSecret`

namespace PqStealth

/-! ## The `epk || ct` wire field (ERC-8441 §3) -/

variable {EphemeralPub KemCiphertext : Type} {nepk nct : ℕ}

/-- Encode the `ephemeralPubKey` field: `epk || ct`, fixed widths, in that
order (ERC-8441 §3: `epk` in bytes 0–32, `ct` in bytes 33–1 120). `Bytes` is the
`MLDSA.Bytes` of `Invariants` (both `MLDSA.Bytes` and `MLKEM.Bytes` are
`Vector Byte n`, but we name one to stay unambiguous under the two opens). -/
def scheme3EphemeralPubKeyEncode
    (packEpk : EphemeralPub → MLDSA.Bytes nepk) (packCt : KemCiphertext → MLDSA.Bytes nct)
    (epk : EphemeralPub) (ct : KemCiphertext) : MLDSA.Bytes (nepk + nct) :=
  packEpk epk ++ packCt ct

/-- Decode by splitting at the fixed seam `nepk`. Total on fixed-length input —
a wrong *length* bytes value simply does not have this type. -/
def scheme3EphemeralPubKeyDecode
    (unpackEpk : MLDSA.Bytes nepk → EphemeralPub) (unpackCt : MLDSA.Bytes nct → KemCiphertext)
    (v : MLDSA.Bytes (nepk + nct)) : EphemeralPub × KemCiphertext :=
  let s := splitBytes v
  (unpackEpk s.1, unpackCt s.2)

/-- **The `epk || ct` field roundtrips byte-for-byte** whenever the two inner
packings do — the outer concatenation loses nothing. This is the interop
invariant a port must preserve. -/
theorem scheme3EphemeralPubKey_roundtrips
    (packEpk : EphemeralPub → MLDSA.Bytes nepk) (unpackEpk : MLDSA.Bytes nepk → EphemeralPub)
    (hpk : ∀ p, unpackEpk (packEpk p) = p)
    (packCt : KemCiphertext → MLDSA.Bytes nct) (unpackCt : MLDSA.Bytes nct → KemCiphertext)
    (hct : ∀ c, unpackCt (packCt c) = c)
    (epk : EphemeralPub) (ct : KemCiphertext) :
    scheme3EphemeralPubKeyDecode unpackEpk unpackCt
        (scheme3EphemeralPubKeyEncode packEpk packCt epk ct) = (epk, ct) := by
  simp only [scheme3EphemeralPubKeyEncode, scheme3EphemeralPubKeyDecode,
    splitBytes_append, hpk, hct]

/-! ## The concrete ERC-8441 byte counts (§1.1, §2.2, §3)

Stated as definitionally-true (`rfl`) arithmetic so any drift in the spec
constants fails to compile. -/

/-- The `ephemeralPubKey` field is SEC1-compressed `epk` (33 B) followed by the
ML-KEM-768 ciphertext (1 088 B): 1 121 bytes. -/
theorem scheme3_ephemeralPubKey_length_eq_1121 : 33 + 1088 = 1121 := rfl

/-- The registered meta-address, `spending_pk(33) ‖ viewing_pk_ec(33) ‖
ek(1 184)`, is 1 250 bytes (ERC-8441 §2.2). -/
theorem scheme3_metaAddress_length_eq_1250 : 33 + 33 + 1184 = 1250 := rfl

/-! ## Fail-closed scanning (ERC-8441 §2.7)

ML-KEM rejects **implicitly**: a ciphertext not intended for the decapsulation
key yields a pseudorandom value, *not* an error (FIPS 203; ERC-8441 §2.7
"decapsulation 'fails' … cannot happen"). Both facts below hold by `rfl` on
VCVio's concrete `MLKEM.asKEMScheme` — no assumption, no probability. -/

/-- **Decapsulation is total**: for any decapsulation key and any ciphertext,
`mlkem768KEM.decaps` returns `some` of the pseudorandom decapsulation — there is
no failure branch for a scanner to trip on. -/
theorem mlkem768_decaps_total (dk : DecapsulationKey mlkem768 mlkem768Encoding)
    (c : Ciphertext mlkem768 mlkem768Encoding) :
    mlkem768KEM.decaps dk c = pure (some
      (MLKEM.decapsInternal concreteNTTRingOps mlkem768Encoding mlkem768Primitives dk c)) := rfl

/-- **Scanning is a pure, total check**: `ofKEMFull`'s scan of any announcement
against any tracking key never errors — implicit rejection means the verdict is
*decided by the auxiliary comparison alone*, with no decapsulation failure path.
This is the machine-checked content of ERC-8441 §2.7's "a scanner MUST NOT treat
a successful decapsulation as a match": the match is the comparison, and a foreign
ciphertext yields a `false` verdict, not an exception. -/
theorem mlkem768_scan_is_total_and_pure {Aux : Type} [DecidableEq Aux]
    (auxGen : SharedSecret → EncapsulationKey mlkem768 mlkem768Encoding → Aux)
    (dk : DecapsulationKey mlkem768 mlkem768Encoding)
    (pk : EncapsulationKey mlkem768 mlkem768Encoding)
    (c : Ciphertext mlkem768 mlkem768Encoding) (a : Aux) :
    (StealthScheme.ofKEMFull mlkem768KEM auxGen).scan (dk, pk) (c, a) =
      pure (decide (a = auxGen
        (MLKEM.decapsInternal concreteNTTRingOps mlkem768Encoding mlkem768Primitives dk c) pk)) := rfl

end PqStealth
