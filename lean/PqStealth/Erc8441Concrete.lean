import PqStealth.Crypto.Sha256
import PqStealth.Crypto.Keccak

/-!
# ERC-8441 schemeId 3 — concrete scheme layer (UNCHECKED DRAFT)

Executable spec of ERC-8441 schemeId 3 as written (ERC merge `4878022`,
vectors sha256-pinned in `python/erc8441_ref/data/`, byte-equality replayed
by the Python harness in `python/erc8441_ref/`), expressed at the VCVio pin
`a5f474fd` with no upstream changes: SHA-256 =
`SLHDSA.Concrete.Sha2.sha256` (FIPS 180-4), SHA3-256 =
`SLHDSA.Concrete.Keccak.sha3_256` (FIPS 202, 0x06 pad) — both executable
`Id.run` implementations already in the pin's `HashSig` library.

**Status.** This build host has no Lean toolchain (4 cores / 7 GB;
see `lean/docs/pins-2026-11-17.md`), so nothing in this file is
typechecked yet. The definitions are plain computable terms (no tactics
in defs); the short proofs are best-effort and expected to close with
minor simp adjustments at the first `lake build
PqStealth.Erc8441Concrete`. The file is intentionally NOT imported by
`PqStealth.lean` yet, so it does not join the default build until it is
verified. Numeric constants (p, n, DS, byte lengths) were checked against
the ERC text and the Python conformance harness, not against Lean.

Constructions (ERC §1.1–§1.3, §2): combiner
`hybrid_combine = SHA3-256(DS ‖ ss_ec ‖ ss_pq ‖ epk ‖ ct ‖ viewing_pk_ec ‖ ek)`
(§1.2, `ss_ec` = x-coordinate alone); offset `SHA256("pq-stealth/offset/v1" ‖ ss)`
with fail-on-out-of-range — an `Option Scalar`, NOT mod-reduction (§1.3
diff vs ERC-5564); view tag = first byte of SHA-256 under its own domain
(§1.3); meta-address `spending_pk ‖ viewing_pk_ec ‖ ek` = 1250 B (§2.2, ek
= 1184 B per FIPS 203 §7.1 = 3·384+32); announcement payload `epk ‖ ct` =
1121 B (§2.3); seed envelope 128 B (§2.1).
-/

open PqStealth.Crypto.Sha256 PqStealth.Crypto.Keccak

namespace PqStealth.Erc8441

/-! ## Curve constants (SEC 2 / ERC §2.2); numerals cross-checked in Python -/

/-- secp256k1 field prime `p = 2²⁵⁶ − 2³² − 977`. -/
def Secp256k1.p : ℕ := 115792089237316195423570985008687907853269984665640564039457584007908834671663

/-- secp256k1 group order `n`. Standard constant; what the scheme layer
uses is only `0 < n` and `n < p`, plus rejection sampling against it. -/
def Secp256k1.n : ℕ := 115792089237316195423570985008687907852837564279074904382605163141518161494337

/-- `n < p` (numeral comparison, native_decide — safe: both sides are
closed numerals). -/
theorem Secp256k1.n_lt_p : Secp256k1.n < Secp256k1.p := by native_decide

/-- Generative secp256k1 scalars, rejection-sampled into `[0, n)`. -/
abbrev Scalar := Fin Secp256k1.n

/-! ## Domain separators (ERC §2.4, §1.3 — verbatim strings) -/

/-- Combiner domain separator, §2.4: 28 ASCII bytes. -/
def domainSeparator : String := "pq-stealth/hybrid-payment/v1"

/-- Offset domain string, §1.3 (replaces ERC-5564's undomained SHA-256). -/
def offsetDomain : String := "pq-stealth/offset/v1"

/-- View-tag domain string, §1.3 (separate digest by design). -/
def viewTagDomain : String := "pq-stealth/view-tag/v1"

/-- ASCII bytes of a string. -/
def asciiBytes (s : String) : ByteArray := s.toUTF8

/-- The DS constant encodes to exactly 28 bytes. -/
theorem domainSeparator_bytes_length : (asciiBytes domainSeparator).size = 28 := by
  native_decide

/-! ## Byte helpers -/

/-- 32-be big-endian little-endian-neutral rendering: byte `i` (MSB first)
of `x` in `w` bytes. -/
def bytesBE (x w : ℕ) : ByteArray := Id.run do
  let mut out := ByteArray.emptyWithCapacity w
  for i in [0:w] do
    out := out.push (UInt8.ofNat ((x / 2 ^ (8 * (w - 1 - i))) % 256))
  return out

/-- Big-endian interpretation of a byte-array as a natural number. -/
def natOfBE (b : ByteArray) : ℕ :=
  b.foldl (fun acc byte => acc * 256 + byte.toNat) 0

/-- Round-trip for `w = 32` when `x < 2²⁵⁶`: `natOfBE (bytesBE x 32) = x`.
Sorry-gated: a byte-index induction needs the `push`/`foldl` characterization
of the `Id.run` loop; one line each in `simp []`-with-steps, closed at the
first lake build. -/
theorem natOfBE_bytesBE_32 (x : ℕ) (hx : x < 2 ^ 256) :
    natOfBE (bytesBE x 32) = x := by
  sorry

/-! ## The hybrid combiner (ERC §1.2; the SP 800-227 canonicalization) -/

/--
`hybridCombine ds ssEc ssPq epk ct viewingPkEc ek`
  = SHA3-256(ds ‖ ssEc ‖ ssPq ‖ epk ‖ ct ‖ viewingPkEc ‖ ek).

Per ERC §1.2 note 1, `ssEc` is the 32-byte x-coordinate ALONE (not the
33-byte compressed point).
-/
def hybridCombine (ds ssEc ssPq epk ct viewingPkEc ek : ByteArray) : ByteArray :=
  sha3_256 (ds ++ ssEc ++ ssPq ++ epk ++ ct ++ viewingPkEc ++ ek)

/-- Digest sizes of the pin's two hashes are 32 bytes. Sorry-gated: one
`simp` over `Keccak.squeeze`/`Sha2.sha256` unfolding. -/
theorem sha3_256_length (b : ByteArray) : (sha3_256 b).size = 32 := by
  sorry

theorem sha256_length (b : ByteArray) : (sha256 b).size = 32 := by
  sorry

/-- Combiner output is 32 bytes. -/
theorem hybridCombine_length (ds ssEc ssPq epk ct viewingPkEc ek : ByteArray) :
    (hybridCombine ds ssEc ssPq epk ct viewingPkEc ek).size = 32 :=
  sha3_256_length _

/-! ## View tag and offset (ERC §1.3) -/

/-- `view_tag(ss) = SHA256("pq-stealth/view-tag/v1" ‖ ss)[0..1]` — 1 B. -/
def viewTag (ss : ByteArray) : ByteArray :=
  (sha256 (asciiBytes viewTagDomain ++ ss)).extract 0 1

/-- The view tag is one byte. -/
theorem viewTag_length (ss : ByteArray) : (viewTag ss).size = 1 := by
  have hd : (sha256 (asciiBytes viewTagDomain ++ ss)).size = 32 := sha256_length _
  sorry -- ByteArray.extract length: stop-start = 1 given size ≥ 1.

/--
`offset(ss) = SHA256("pq-stealth/offset/v1" ‖ ss)` read big-endian, then a
**fail** if `t ≥ n` — reduction mod n is FORBIDDEN (ERC §1.3 note 2 vs
ERC-5564). `none` is the ERC's "fail the entire derivation" branch.
-/
def offsetScalar (ss : ByteArray) : Option Scalar :=
  let t := natOfBE (sha256 (asciiBytes offsetDomain ++ ss))
  if h : t < Secp256k1.n then some ⟨t, h⟩ else none

/-! ## Wire formats (ERC §2.1–§2.4) -/

/-- Compressed secp256k1 point (`0x02‖x` or `0x03‖x`, 33 B). -/
abbrev Point33 : Type := ByteArray

/-- ML-KEM-768 encapsulation key: 1184 B (FIPS 203 §7.1: 3·384 + 32). -/
theorem ek_length : 1184 = 3 * 384 + 32 := by native_decide

/-- The meta-address length budget: 33 + 33 + 1184 = 1250 B (ERC §2.2). -/
theorem meta_length : 1250 = 33 + 33 + 1184 := by native_decide

/-- The announcement payload budget: `epk ‖ ct` = 33 + 1088 = 1121 B
(ERC §2.3; 1088 = ML-KEM-768 ciphertext per FIPS 203 §7.2). -/
theorem announcement_payload_length : 1121 = 33 + 1088 := by native_decide

/-- The seed envelope: 32+32+64 = 128 B (§2.1: spending_seed ‖ viewing_ec_seed
‖ (d ‖ z)). -/
theorem seed_envelope_length : 128 = 32 + 32 + 64 := by native_decide

end PqStealth.Erc8441
