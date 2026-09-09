/**
 * SPHINCS- C13 as an ERC-7913 spend signer (D-018).
 *
 * C13 is the Verity Labs machine-checked hash-based verifier (WOTS+C / FORS+C,
 * keccak256, FIPS 205 uncompressed ADRS; n = 16, h = 22, d = 2, a = 19, k = 7,
 * w = 8; 3,688-byte signatures, 2^22 signatures per key). Its Solidity is
 * vendored verbatim at contracts/src/vendor/sphincs-minus/ and wrapped by two
 * ERC-7913 signers in contracts/src/SphincsC13Signer7913.sol:
 *
 *   SphincsC13Signer7913        key = pk (32 B)                      sig = 3,688 B
 *   SphincsC13CommitSigner7913  key = keccak(DOMAIN || pk || opener)  sig = pk || opener || c13sig (3,752 B)
 *
 * This module holds the byte-level conventions both sides agree on, mirrored
 * by python/scripts/sphincs_c13_7913_demo.py (the fixture generator). The
 * e2e test asserts the two implementations agree byte for byte.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatHex, hexToBytes, keccak256, stringToHex, type Address, type Hex } from 'viem';

export const SPHINCS_C13 = {
  /** Hash output truncation (bytes). Public key = two n-byte halves. */
  n: 16,
  publicKeyLength: 32,
  signatureLength: 3688,
  openerLength: 32,
  /** Commitment domain tag — 32 ASCII bytes, `bytes32` on-chain. */
  commitDomain: 'pq-stealth/sphincs-c13/commit/v0',
  /** Opener KDF domain tag (off-chain only). */
  openDomain: 'pq-stealth/sphincs-c13/open/v0',
  /** Key-derivation domain tag for the recipient's C13 seed material. */
  keygenDomain: 'pq-stealth/sphincs-c13/keygen/v0',
  /** IERC7913SignatureVerifier.verify.selector */
  erc7913Magic: '0x024ad318' as Hex,
} as const;

const LOW_128 = (1n << 128n) - 1n;

/** The 32-byte ERC-7913 `key` from the verifier's two top-aligned bytes32 words. */
export function sphincsC13Key(pkSeed: Hex, pkRoot: Hex): Hex {
  for (const [name, w] of [['pkSeed', pkSeed], ['pkRoot', pkRoot]] as const) {
    if (w.length !== 66) throw new Error(`${name}: expected bytes32`);
    if ((BigInt(w) & LOW_128) !== 0n) throw new Error(`${name}: low 128 bits must be zero (n = 16)`);
  }
  return concatHex([pkSeed.slice(0, 34) as Hex, pkRoot.slice(0, 34) as Hex]);
}

/** Inverse of sphincsC13Key: the two top-aligned bytes32 words the raw verifier takes. */
export function splitSphincsC13Key(key: Hex): { pkSeed: Hex; pkRoot: Hex } {
  if (key.length !== 2 + 2 * SPHINCS_C13.publicKeyLength) throw new Error('key: expected 32 bytes');
  const pad = '0'.repeat(32);
  return {
    pkSeed: (key.slice(0, 34) + pad) as Hex,
    pkRoot: ('0x' + key.slice(34, 66) + pad) as Hex,
  };
}

/** opener = SHA-256(openDomain || ss). Never the shared secret itself. */
export function sphincsC13Opener(sharedSecret: Uint8Array): Hex {
  const dom = hexToBytes(stringToHex(SPHINCS_C13.openDomain));
  const buf = new Uint8Array(dom.length + sharedSecret.length);
  buf.set(dom); buf.set(sharedSecret, dom.length);
  return bytesToHex(sha256(buf)); // no Buffer: this runs in the browser too
}

/** key for SphincsC13CommitSigner7913: keccak256(commitDomain || pk || opener). */
export function sphincsC13Commitment(pk: Hex, opener: Hex): Hex {
  return keccak256(concatHex([stringToHex(SPHINCS_C13.commitDomain), pk, opener]));
}

/** signature for SphincsC13CommitSigner7913: pk || opener || c13sig. */
export function sphincsC13CommitSignature(pk: Hex, opener: Hex, sig: Hex): Hex {
  return concatHex([pk, opener, sig]);
}

/** ERC-7913 signer bytes: `verifier || key`. */
export function erc7913Signer(verifier: Address, key: Hex): Hex {
  return concatHex([verifier, key]);
}
