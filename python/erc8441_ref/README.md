# erc8441_ref — second implementation conformance harness (python)

Clean-room reference implementation of **ERC-8441 schemeId 3** (hybrid
ML-KEM-768 + secp256k1 stealth addresses) plus a runner that replays the
ERC's own 29 published vectors (section-1 + section-2) byte-for-byte,
anchored to NIST ACVP ML-KEM-768 cases for KEM behavior.

Status: **30/30 checks PASS** (self-test included; exit 0).

## Run

```sh
cd python/erc8441_ref
../.venv/bin/python run_vectors.py
```

## What is proven by this

- Keygen: 128-byte seed, scalar/length/equality validation, determinism
  against ACVP keygen tcId 26's `(d, z)` (V3-01/02/02a/09/10).
- Meta-address decoding: 1250 B, both points on secp256k1, tag 0x02/0x03
  only (V3-03/11/12).
- Combiner: `SHA3-256(DS ‖ ss_ec ‖ ss_pq ‖ epk ‖ ct ‖ viewing_pk_ec ‖ ek)`,
  DS first, every input bound (V3-05/06/06a/06b/07). `kyber_py` also
  reproduces NIST's ACVP encapsulation-26 `(k, c)` from the same `(ek, m)`
  (V3-06a internal check).
- ECDH: x-coordinate-only, identical on both sides (V3-04).
- Announcement wire: `epk ‖ ct` = 1121 B, view tag = metadata[0], trailing
  token metadata ignored (V3-08/08a).
- Scan: entry-point shape checks are skips, never errors; bad epk points
  skip at entry; view-tag mismatch skips but records ss/derived tag; wrong
  announced address skips; honest announcement matches to the derived
  address (V3-08a/14/14b/15/17/18). ACVP decapsulation rows (tcId 86/88,
  including implicit-rejection modified-ciphertext cases) drive the KEM
  side via the expanded-dk form with the FIPS 203 layout
  (`ek = dk[1152:2336]`, `K = SHA3-256(ek) = dk[2336:2368]`).
- Offset: `H(ss) = SHA256("pq-stealth/offset/v1" ‖ ss)`, big-endian, with
  the fail-not-reduce range check 0 < H < n (V1-01..05, section-1).
- View tag: `SHA256("pq-stealth/view-tag/v1" ‖ ss)[0]`, 1 byte (V1-07).
- Stealth key pair: `stealth_pk = spending_pk + H(ss)·G`, `stealth_sk =
  (spending_sk + H(ss)) mod n`, near-n spending keys included, and the
  pair self-consistency `stealth_sk·G = stealth_pk` (V3-16).
- Address: keccak of the uncompressed stealth point minus the 0x04 prefix,
  last 20 bytes, with EIP-55 checksum (V3-13).
- ek validation: an ek failing FIPS 203's encapsulation input check is an
  error at encapsulation and no announcement is made (V3-19).

## Conformance posture

The ERC text marks the domain-separator constant (`V3-05`/`V3-19` rows) as
`provisional` — its own implementation produced these bytes and an
independent blinded re-derivation from the prose agreed, but *no outside
implementation had adopted it*. As of this harness there is now a second,
codebase-disjoint implementation agreeing byte-for-byte on the full
29-vector suite, including the DS rows.

Self-test: the pure-Python secp256k1 is cross-checked against coincurve
(libsecp256k1), including the observation that libsecp's
`ecdh` = SHA-256 over the 33-byte compressed shared point (SP 800-56A
compressed OtherInput). Probes that document intermediate derivations are
kept under `probes/`.
