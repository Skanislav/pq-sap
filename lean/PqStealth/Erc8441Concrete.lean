import PqStealth.Crypto.Sha256
import PqStealth.Crypto.Keccak

/-!
# ERC-8441 schemeId 3 — concrete scheme layer

Executable spec of ERC-8441 schemeId 3 as written (ERC merge `4878022`,
vectors sha256-pinned in `python/erc8441_ref/data/`, byte-equality replayed
by the Python harness in `python/erc8441_ref/`), expressed at the VCVio pin
`a5f474fd` with no upstream changes: SHA-256 =
`SLHDSA.Concrete.Sha2.sha256` (FIPS 180-4), SHA3-256 =
`SLHDSA.Concrete.Keccak.sha3_256` (FIPS 202, 0x06 pad) — both executable
`Id.run` implementations already in the pin's `HashSig` library.

**Status.** Fully typechecked with Lean v4.32.0 at the pinned VCVio
(compile exit 0, zero errors, zero warnings, zero sorries; digest-size and
round-trip theorems proved — see `natOfBE_bytesBE_32`, `sha3_256_length`,
`sha256_length`, `viewTag_length`). Not yet imported by `PqStealth.lean`,
so it does not join the default build until the import wire-up. Numeric
constants (p, n, DS, byte lengths) are checked by `native_decide` / the
proved theorems below.

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

/-- Twin of `bytesBE` as a pure `List.foldl` (proof-side rendering). -/
def digit (x w i : Nat) : Nat := (x / 2 ^ (8 * (w - 1 - i))) % 256

/-- Byte value `v % 256`. -/
def u8 (v : Nat) : UInt8 := UInt8.ofNat (v % 256)

/-- Twin of `bytesBE` as a pure `List.foldl` of pushes. -/
def bytesBE_F (x w : Nat) : ByteArray :=
  List.foldl (fun (s : ByteArray) (i : Nat) => s.push (u8 (digit x w i)))
      (ByteArray.emptyWithCapacity w) (List.range w)

/-- Twin of `natOfBE` (same term; the name is distinct for the fold lemmas). -/
def natOfBE_F (b : ByteArray) : Nat := b.foldl (fun acc byte => acc * 256 + byte.toNat) 0

/-- `natOfBE` and its twin are definitionally equal. -/
theorem natOfBE_eq_natOfBE_F (b : ByteArray) : natOfBE b = natOfBE_F b := rfl

theorem u8_toNat (v : Nat) : (u8 v).toNat = v % 256 := by
  unfold u8
  simp only [UInt8.toNat_ofNat']
  rw [show (2 ^ 8 : Nat) = 256 from rfl, Nat.mod_mod_of_dvd _ (Nat.dvd_refl 256)]

theorem u8_toNat_mod (v : Nat) : (u8 (v % 256)).toNat = v % 256 := by
  rw [u8_toNat]
  exact Nat.mod_mod_of_dvd _ (Nat.dvd_refl 256)

/-- Loop machinery: `ByteArray.foldlM.loop` closed at count 0 (both `dif`
branches are `rfl`). -/
theorem loop_zero (g : Nat → UInt8 → Id Nat) (as : ByteArray) (stop : Nat) (h : stop ≤ as.size)
    (j acc : Nat) :
    (ByteArray.foldlM.loop g as stop h 0 j acc : Id Nat) = pure acc := by
  unfold ByteArray.foldlM.loop
  split
  · rfl
  · rfl

/-- Loop machinery: one `foldlM.loop` step peels the head byte (the byte is
consumed via an explicit equality so the read is pinned). -/
theorem loop_step (g : Nat → UInt8 → Id Nat) (as : ByteArray) (stop : Nat) (h : stop ≤ as.size)
    (i j acc : Nat) (hj : j < stop) :
    (ByteArray.foldlM.loop g as stop h (i+1) j acc : Id Nat)
      = (do let acc' ← g acc as[j]
            ByteArray.foldlM.loop g as stop h i (j+1) acc') := by
  unfold ByteArray.foldlM.loop
  rw [dif_pos hj]
  cases i with
  | zero => rfl
  | succ k => rfl

theorem loop_step' (g : Nat → UInt8 → Id Nat) (as : ByteArray) (stop : Nat) (h : stop ≤ as.size)
    (i j acc : Nat) (hj : j < stop) (X : UInt8) (hX : as[j] = X) :
    (ByteArray.foldlM.loop g as stop h (i+1) j acc : Id Nat)
      = (do let acc' ← g acc X
            ByteArray.foldlM.loop g as stop h i (j+1) acc') := by
  rw [loop_step g as stop h i j acc hj, hX]

/-- Window induction: folding the last `m` bytes of `bs.push b` starting at `j`
(with `j + m = (bs.push b).size`) equals folding the `bs`-window `j..size`
and applying `f … b` at the end. -/
theorem foldl_push_aux (f : Nat → UInt8 → Nat) (bs : ByteArray) (b : UInt8) :
    ∀ (m j acc : Nat), j + m = (bs.push b).size → j ≤ bs.size →
    (ByteArray.foldlM.loop (fun x1 x2 => pure (f x1 x2)) (bs.push b) (bs.push b).size
        (Nat.le_refl (bs.push b).size) m j acc : Id Nat).run
      = f ((ByteArray.foldlM.loop (fun x1 x2 => pure (f x1 x2)) bs bs.size
            (Nat.le_refl bs.size) (bs.size - j) j acc : Id Nat).run) b := by
  intro m
  induction m with
  | zero =>
    intro j acc hjm hj
    have hp : (bs.push b).size = bs.size + 1 := ByteArray.size_push
    omega
  | succ k ih =>
    intro j acc hjm hj
    have hp : (bs.push b).size = bs.size + 1 := ByteArray.size_push
    have hlt : j < (bs.push b).size := by omega
    by_cases hjs : j < bs.size
    · -- head byte bs[j]!: peel one step from each loop
      rw [loop_step' (fun x1 x2 => pure (f x1 x2)) (bs.push b) (bs.push b).size
          (Nat.le_refl (bs.push b).size) k j acc hlt (bs[j]!)
          ((getElem!_pos (bs.push b) j (by omega)).symm.trans
            (ByteArray.getElem!_push_lt bs b j hjs))]
      rw [show bs.size - j = (bs.size - j - 1) + 1 from by omega,
        loop_step' (fun x1 x2 => pure (f x1 x2)) bs bs.size (Nat.le_refl bs.size)
          (bs.size - j - 1) j acc (by omega) (bs[j]!)
          ((getElem!_pos bs j (by omega : j < bs.size)).symm)]
      simp only [pure_bind]
      have hih := ih (j + 1) (f acc bs[j]!) (by omega) (by omega)
      rw [show bs.size - (j + 1) = bs.size - j - 1 from by omega] at hih
      exact hih
    · -- j = bs.size: the last byte is b itself
      have hje : j = bs.size := by omega
      subst hje
      rw [loop_step' (fun x1 x2 => pure (f x1 x2)) (bs.push b) (bs.push b).size
          (Nat.le_refl (bs.push b).size) k bs.size acc hlt b
          ((getElem!_pos (bs.push b) bs.size (by omega)).symm.trans
            (ByteArray.getElem!_push_eq bs b))]
      simp only [pure_bind]
      have hk : k = 0 := by omega
      rw [hk, loop_zero]
      rw [show bs.size - bs.size = 0 from by omega, loop_zero]
      rfl

/-- Key lemma: `ByteArray.foldl` over `push` separates the last byte. -/
theorem foldl_push (f : Nat → UInt8 → Nat) (init : Nat) (bs : ByteArray) (b : UInt8) :
    ByteArray.foldl f init (bs.push b) = f (ByteArray.foldl f init bs) b := by
  show ((ByteArray.foldlM (fun x1 x2 => pure (f x1 x2)) init (bs.push b) 0 (bs.push b).size : Id Nat).run
    = f ((ByteArray.foldlM (fun x1 x2 => pure (f x1 x2)) init bs 0 bs.size : Id Nat).run) b)
  rw [ByteArray.foldlM.eq_def, ByteArray.foldlM.eq_def,
    dif_pos (Nat.le_refl _), dif_pos (Nat.le_refl _)]
  show (ByteArray.foldlM.loop (fun x1 x2 => pure (f x1 x2)) (bs.push b) (bs.push b).size
      (Nat.le_refl (bs.push b).size) ((bs.push b).size - 0) 0 init : Id Nat).run
    = f (ByteArray.foldlM.loop (fun x1 x2 => pure (f x1 x2)) bs bs.size
          (Nat.le_refl bs.size) (bs.size - 0) 0 init : Id Nat).run b
  simp only [Nat.sub_zero]
  exact foldl_push_aux f bs b ((bs.push b).size) 0 init (Nat.zero_add _)
    (Nat.zero_le bs.size)

/-- Horner step for the big-endian fold: appending byte `byt` multiplies by
256 and adds. -/
theorem natOfBE_push (bs : ByteArray) (byt : UInt8) :
    natOfBE (bs.push byt) = natOfBE bs * 256 + byt.toNat := by
  unfold natOfBE
  rw [foldl_push]

/-- Digit `i` of the `w+1`-byte rendering is digit `i` of the `w`-byte
rendering of `x / 256` (proven below via digit_shift on the twin). -/
theorem digit_shift (x w i : Nat) (hi : i < w) :
    digit x (w+1) i = digit (x / 256) w i := by
  unfold digit at *
  have h1 : 8 * (w + 1 - 1 - i) = 8 + 8 * (w - 1 - i) := by omega
  rw [h1]
  have h2 : 2 ^ (8 + 8 * (w - 1 - i)) = 2 ^ 8 * 2 ^ (8 * (w - 1 - i)) := Nat.pow_add _ _ _
  rw [h2, show (2 : Nat) ^ 8 = 256 from rfl, Nat.div_div_eq_div_mul]

theorem u8_digit_top (x w : Nat) :
    u8 (digit x (w+1) w) = u8 (x % 256) := by
  unfold digit u8
  rw [show (8 * (w + 1 - 1 - w) : Nat) = 0 from by omega, Nat.pow_zero, Nat.div_one]

/-- Fold over a list with a body that agrees pointwise: same result. -/
theorem foldl_body_congr {β α} (l : List α)
    (f g : β → α → β) (h : ∀ a ∈ l, ∀ (b : β), f b a = g b a) (init : β) :
    List.foldl f init l = List.foldl g init l := by
  induction l generalizing init with
  | nil => rfl
  | cons a l ih =>
    rw [List.foldl_cons, List.foldl_cons]
    rw [h a (by simp only [List.mem_cons, true_or]) init]
    exact ih (fun a' hm b => h a' (by simp only [List.mem_cons, hm, or_true]) b) (g init a)

theorem emptyWithCapacity_data (w : Nat) :
    (ByteArray.emptyWithCapacity w).data = ByteArray.empty.data := by
  rfl

/-- Fold with bodies agreeing pointwise on `.data` and `g` respecting seed
`.data` agreement: results agree on `.data`. -/
theorem foldl_data_congr {α} (l : List α) (f g : ByteArray → α → ByteArray)
    (h_body : ∀ a ∈ l, ∀ (b : ByteArray), (f b a).data = (g b a).data)
    (h_g_seed : ∀ a ∈ l, ∀ (s1 s2 : ByteArray), s1.data = s2.data → (g s1 a).data = (g s2 a).data)
    (s1 s2 : ByteArray) (h_seed : s1.data = s2.data) :
    (List.foldl f s1 l).data = (List.foldl g s2 l).data := by
  induction l generalizing s1 s2 with
  | nil => exact h_seed
  | cons a l ih =>
    simp only [List.foldl_cons]
    apply ih
    · intro a' hm b; exact h_body a' (by simp only [List.mem_cons, hm, or_true]) b
    · intro a' hm s1' s2' h; exact h_g_seed a' (by simp only [List.mem_cons, hm, or_true]) s1' s2' h
    · have h_step : (f s1 a).data = (g s2 a).data := by
        rw [h_body a (by simp only [List.mem_cons, true_or]) s1]
        exact h_g_seed a (by simp only [List.mem_cons, true_or]) s1 s2 h_seed
      exact h_step

/-- Do-loop rendering equals the `List.foldl` twin (byte `i` = digit `i`). -/
theorem bytesBE_eq_bytesBE_F (x w : Nat) : bytesBE x w = bytesBE_F x w := by
  unfold bytesBE bytesBE_F
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', List.forIn_pure_yield_eq_foldl,
    Std.Legacy.Range.size, Nat.div_one, Nat.add_sub_cancel_right, Nat.sub_zero,
    List.range_eq_range', Id.run_bind, Id.run_pure]
  congr 1
  funext s i
  simp only [digit, u8]
  rw [Nat.mod_mod_of_dvd _ (Nat.dvd_refl 256)]

/-- bytesBE_F successor shape (fold form): the `w+1`-byte rendering of `x` is
the fold-rendering of `x / 256` plus the top byte `x % 256`. -/
theorem bytesBE_F_succ (x w : Nat) :
    bytesBE_F x (w + 1)
      = (List.foldl (fun (s : ByteArray) (i : Nat) => s.push (u8 (digit (x / 256) w i)))
          (ByteArray.emptyWithCapacity w) (List.range w)).push (u8 (x % 256)) := by
  have hr : List.range (w + 1) = List.range w ++ [w] := List.range_succ
  rw [bytesBE_F, hr]
  rw [List.foldl_append, List.foldl_cons, List.foldl_nil]
  rw [u8_digit_top x w]
  have h_eq :
      (List.foldl (fun s i => s.push (u8 (digit x (w + 1) i))) (ByteArray.emptyWithCapacity (w + 1)) (List.range w)).data
    = (List.foldl (fun s i => s.push (u8 (digit (x / 256) w i))) (ByteArray.emptyWithCapacity w) (List.range w)).data := by
    have h_seed : (ByteArray.emptyWithCapacity (w + 1)).data = (ByteArray.emptyWithCapacity w).data := rfl
    apply foldl_data_congr (List.range w)
      (fun s i => s.push (u8 (digit x (w + 1) i)))
      (fun s i => s.push (u8 (digit (x / 256) w i)))
    · intro i hi s
      rw [ByteArray.data_push, ByteArray.data_push]
      rw [digit_shift x w i (List.mem_range.mp hi)]
    · intro i hi s1 s2 h
      rw [ByteArray.data_push, ByteArray.data_push, h]
    · exact h_seed
  apply ByteArray.ext
  rw [ByteArray.data_push, ByteArray.data_push, h_eq]

theorem bytesBE_F_succ' (x w : Nat) :
    bytesBE_F x (w + 1) = (bytesBE_F (x / 256) w).push (u8 (x % 256)) := by
  rw [bytesBE_F_succ x w]
  rfl

/-- Horner step for the big-endian fold: appending byte `byt` multiplies by
256 and adds. -/
theorem natOfBE_F_push (bs : ByteArray) (byt : UInt8) :
    natOfBE_F (bs.push byt) = natOfBE_F bs * 256 + byt.toNat := by
  unfold natOfBE_F
  rw [foldl_push]

/-- Horner induction (on the F-twins): big-endian fold of the `w`-byte
rendering of `x` below `2^(8w)` returns `x % 2^(8w)`. -/
theorem natOfBE_F_bytesBE_F (w : Nat) :
    ∀ x, x < 2 ^ (8 * w) → natOfBE_F (bytesBE_F x w) = x % 2 ^ (8 * w) := by
  induction w with
  | zero =>
    intro x hx
    have hz : natOfBE_F (bytesBE_F x 0) = 0 := by
      unfold bytesBE_F natOfBE_F
      rw [List.range_zero, List.foldl_nil]
      rfl
    rw [hz, show (8 : Nat) * 0 = 0 from rfl, Nat.pow_zero, Nat.mod_one]
  | succ w ih =>
    intro x hx
    have hpa : 2 ^ (8 * (w + 1)) = 256 * 2 ^ (8 * w) := by
      have hs8 : 8 * (w + 1) = 8 + 8 * w := by
        rw [Nat.mul_add, Nat.mul_one, Nat.add_comm]
      rw [hs8, Nat.pow_add]
    have hq : x / 256 < 2 ^ (8 * w) := by omega
    have hs : bytesBE_F x (w + 1) = (bytesBE_F (x / 256) w).push (u8 (x % 256)) :=
      bytesBE_F_succ' x w
    rw [hs, natOfBE_F_push, u8_toNat_mod, ih (x / 256) hq, Nat.mod_eq_of_lt hq,
      Nat.mod_eq_of_lt hx, Nat.mul_comm (x / 256) 256]
    exact Nat.div_add_mod x 256

/-- Round-trip for `w = 32` when `x < 2²⁵⁶`: `natOfBE (bytesBE x 32) = x`. -/
theorem natOfBE_bytesBE_32 (x : ℕ) (hx : x < 2 ^ 256) :
    natOfBE (bytesBE x 32) = x := by
  rw [bytesBE_eq_bytesBE_F, natOfBE_eq_natOfBE_F]
  rw [natOfBE_F_bytesBE_F 32 x hx]
  rw [show (8 : Nat) * 32 = 256 from rfl, Nat.mod_eq_of_lt hx]

/-! ## The hybrid combiner (ERC §1.2; the SP 800-227 canonicalization) -/

/--
`hybridCombine ds ssEc ssPq epk ct viewingPkEc ek`
  = SHA3-256(ds ‖ ssEc ‖ ssPq ‖ epk ‖ ct ‖ viewingPkEc ‖ ek).

Per ERC §1.2 note 1, `ssEc` is the 32-byte x-coordinate ALONE (not the
33-byte compressed point).
-/
def hybridCombine (ds ssEc ssPq epk ct viewingPkEc ek : ByteArray) : ByteArray :=
  sha3_256 (ds ++ ssEc ++ ssPq ++ epk ++ ct ++ viewingPkEc ++ ek)

/-- Digest sizes of the pin's two hashes are 32 bytes. -/
private theorem foldlRange_size (g : Nat → UInt8) : ∀ n : ℕ,
    (List.foldl (fun (b : ByteArray) (a : Nat) => b.push (g a)) ByteArray.empty (List.range' 0 n)).size = n := by
  intro n
  induction n with
  | zero =>
    simp only [show (List.range' 0 0 : List Nat) = [] from rfl, List.foldl_nil,
      ByteArray.size_empty]
  | succ n ih =>
    have hr : List.range' 0 (n+1) = List.range' 0 n ++ List.range' n 1 := by
      have h := List.range'_append_1 (s := 0) (m := n) (n := 1)
      simp only [Nat.zero_add] at h
      exact h.symm
    have hlast : List.range' n 1 = [n] := rfl
    show (List.foldl (fun (b : ByteArray) (a : Nat) => b.push (g a)) ByteArray.empty (List.range' 0 (n+1))).size = n + 1
    rw [hr, hlast, List.foldl_append, List.foldl_cons, List.foldl_nil]
    have hpush := ByteArray.size_push
      (bs := List.foldl (fun (b : ByteArray) (a : Nat) => b.push (g a)) ByteArray.empty (List.range' 0 n))
      (b := g n)
    rw [hpush, ih]

private theorem pushLoop_size (g : Nat → UInt8) (n : ℕ) :
    (Id.run do
      let mut out := ByteArray.empty
      for i in [0:n] do
        out := out.push (g i)
      return out).size = n := by
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', List.forIn_pure_yield_eq_foldl,
    Std.Legacy.Range.size, Nat.div_one, Nat.add_sub_cancel_right, Nat.sub_zero]
  show (List.foldl (fun (b : ByteArray) (a : Nat) => b.push (g a)) ByteArray.empty (List.range' 0 n)).size = n
  exact foldlRange_size g n

/-- `squeeze` is literally the push-loop shown, definitionally. -/
theorem squeeze_eq_pushLoop (s : Array UInt64) (outLen : Nat) :
    PqStealth.Crypto.Keccak.squeeze s outLen = (Id.run do
      let mut out := ByteArray.empty
      for i in [0:outLen] do
        out := out.push (((s[i / 8]! >>> ((i % 8) * 8).toUInt64) &&& 0xFF).toUInt8)
      return out) := rfl

theorem sha3_256_length (b : ByteArray) : (sha3_256 b).size = 32 := by
  show (PqStealth.Crypto.Keccak.squeeze (absorb b 136 0x06) 32).size = 32
  rw [squeeze_eq_pushLoop]
  exact pushLoop_size
    (fun i => (((absorb b 136 0x06)[i / 8]! >>> ((i % 8) * 8).toUInt64) &&& 0xFF).toUInt8) 32

/-- Big-endian 4-byte serialization is 4 bytes. -/
theorem u32be_size (x : UInt32) : (PqStealth.Crypto.Sha256.u32be x).size = 4 := rfl

/-- Appending `n` big-endian 4-byte words to the empty array: size `4n`. -/
theorem app4_size : ∀ n : ℕ, ∀ (f : Nat → UInt32),
    (List.foldl (fun (o : ByteArray) (i : Nat) => o ++ PqStealth.Crypto.Sha256.u32be (f i))
      ByteArray.empty (List.range' 0 n)).size = 4 * n := by
  intro n
  induction n with
  | zero =>
    intro f
    simp only [show (List.range' 0 0 : List Nat) = [] from rfl, List.foldl_nil,
      ByteArray.size_empty, Nat.mul_zero]
  | succ n ih =>
    intro f
    have hr : List.range' 0 (n+1) = List.range' 0 n ++ List.range' n 1 := by
      have h := List.range'_append_1 (s := 0) (m := n) (n := 1)
      simp only [Nat.zero_add] at h
      exact h.symm
    have hlast : List.range' n 1 = [n] := rfl
    rw [hr, hlast, List.foldl_append, List.foldl_cons, List.foldl_nil]
    have hstep : (List.foldl (fun o i => o ++ PqStealth.Crypto.Sha256.u32be (f i))
        ByteArray.empty (List.range' 0 n) ++ PqStealth.Crypto.Sha256.u32be (f n)).size
        = 4 * n + 4 * 1 := by
      rw [ByteArray.size_append, ih f]
      rw [u32be_size]
    rw [hstep]
    rfl

theorem sha256_length (b : ByteArray) : (sha256 b).size = 32 := by
  have hs : sha256 b = List.foldl (fun (o : ByteArray) (i : Nat) => o ++ PqStealth.Crypto.Sha256.u32be
      ((List.foldl (fun x2 a => PqStealth.Crypto.Sha256.compress x2 (PqStealth.Crypto.Sha256.pad b)
            (a * 64)) PqStealth.Crypto.Sha256.iv
          (List.range' 0 ((PqStealth.Crypto.Sha256.pad b).size / 64)))[i]!))
    ByteArray.empty (List.range' 0 8) := by
    unfold sha256
    simp only [Std.Legacy.Range.forIn_eq_forIn_range', List.forIn_pure_yield_eq_foldl,
      Std.Legacy.Range.size, Nat.div_one, Nat.add_sub_cancel_right, Nat.sub_zero,
      Id.run_bind, Id.run_pure]
  rw [hs]
  rw [app4_size 8 (fun i => _)]

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
  unfold viewTag
  rw [ByteArray.size_extract, hd]
  rfl

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
