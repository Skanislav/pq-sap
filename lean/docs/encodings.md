# Encodings: what is concrete in Lean and what is still a parameter

Companion to `PqStealth/Invariants.lean` §3 (issue #10 in `improvements.md`).

## The two wire formats

`TECHNICAL_SPEC.md` §3 fixes the meta-address as

    version(1) ‖ rho(32) ‖ pack23(t) ‖ ek

and `DECISIONS.md` D-012 the reduced ZK-spend layout as

    version(1) ‖ commitment(32) ‖ ek

Both are modelled in Lean as honest fixed-length byte strings —
`Bytes n := Vector UInt8 n`, VCVio's `MLDSA.Bytes` — not as a record:

* `metaAddressEncode` is literally `#v[version] ++ (rho ++ (packT t ++ packEk ek))`
  at type `Bytes (1 + (32 + (nt + nek)))`;
* `metaAddressDecode` splits at the fixed offsets `1`, `33`, `33 + nt` with
  `splitBytes`, defined by `Vector.extract` + `Vector.cast`;
* `meta_address_roundtrips` / `meta_address_zk_roundtrips` prove
  `decode (encode …) = (version, rho, t, ek)` from the single byte-level lemma
  `splitBytes_append : splitBytes (a ++ b) = (a, b)`.

The type is written right-nested (`1 + (32 + (nt + nek))`) on purpose: that is
the association `splitBytes` peels from the front, and it avoids a `Vector.cast`
on every use. The concrete corollaries `meta_address_roundtrips_5633` and
`meta_address_zk_roundtrips_1217` restate the same fact with every binder at a
literal length (`Bytes 4416`, `Bytes 1184`, `Bytes 32`); the `: Bytes 5633` /
`: Bytes 1217` ascription on the encoded argument typechecks by definitional
unfolding of the numerals but, being elaboration-time only, does not survive
into the stored type — the total is carried by the size theorems below.

## The lengths

| Quantity | Lean | Value |
|---|---|---|
| `pack23(t)`, ML-DSA-65 | `packedTBytes mldsa65 = mldsa65.k * ringDegree * qBits / 8` | 4416 |
| ML-KEM-768 `ek` | `MLKEM.Params.publicKeyBytes MLKEM.mlkem768 = 384 * k + 32` | 1184 |
| Meta-address | `metaAddress_size_mldsa65_mlkem768` | **5633** |
| ZK-spend meta-address | `metaAddressZk_size_mlkem768` | **1217** |

`qBits = 23` is a literal (`q = 8380417 < 2^23`, the spec's `Q_BITS`); it is not
derived from `Nat.log2 (modulus - 1) + 1` because `Nat.log2` is well-founded
recursion and does not reduce by `rfl`. The `/ 8` is exact for every approved
ML-DSA set since `8 ∣ 256`, so `packedTBytes p = p.k * 736`.

The `ek` length is taken from VCVio (`MLKEM.Params.publicKeyBytes`) rather than
written out, so the 5,633 stays tied to the upstream parameter record.

## What is still a parameter, and why

`packT : T → Bytes nt` and `packEk : Ek → Bytes nek` are parameters carrying
roundtrip hypotheses, exactly as `stealth_pk_roundtrips` takes `enc.Laws`.
This is forced by the pinned VCVio (`a5f474fd`), not a modelling shortcut:

* `MLDSA.Encoding` (`LatticeCrypto/MLDSA/Encoding.lean`) keeps `EncodedPK`,
  `EncodedSK`, `EncodedSig` as abstract `Type`s. `pkEncode` packs `(rho, t1)`,
  the *rounded* high part — the meta-address must carry full-precision `t`
  (TECHNICAL_SPEC §3), so `pkEncode` is the wrong encoder here even if it were
  byte-valued.
* The concrete ML-DSA bit-packers (`LatticeCrypto/MLDSA/Concrete/Encoding.lean`:
  `simpleBitPackPoly`, `bitPackPoly`) return `ByteArray` — no length index — and
  carry no roundtrip lemma. There is no `pack23` upstream at all.
* `MLKEM.Encoding.EncodedTHat` is likewise abstract, concretely `ByteArray`, and
  `mlkem768EncodingLaws` (`MLKEM/Concrete/Instance.lean:133`) proves only the
  ciphertext/message laws — `byteDecode12Vec_byteEncode12Vec` is a field of the
  encoding bundle, but again at `ByteArray`, not `Bytes 1184`.

So the honest statement is: **the outer layout is concrete and proved lossless;
the two inner packers are assumed lossless.** Closing the remaining gap means
either upstreaming length-indexed byte encoders with laws to VCVio, or writing a
23-bit little-endian bit-packer `Vector (Fin 8380417) (k*256) → Bytes (k*736)`
with a roundtrip proof here. The latter is a self-contained mini-project
(digit-level reasoning about `Nat.ofDigits`/`Nat.digits` with fixed padding) and
was not attempted under issue #10.
