/**
 * Explicit account profiles for the commitment meta-address (format 0x02).
 * Mirror of `python/pq_stealth/profiles.py`; the bytes are defined there.
 *
 * A 0x02 meta-address is `0x02 || spendKey(32) || kemEk`. The 32-byte spend
 * key is opaque: which scheme, hash domains, chain, and account code interpret
 * it is an *account profile* the application selects explicitly and out of
 * band, before sending or scanning — never inferred from the commitment,
 * guessed by trial verification, or deferred to deployment time.
 *
 * Three identifiers, three roles: the meta-address version byte (`0x02`)
 * describes the encoding; the ERC-5564 scheme ID describes announcement
 * interpretation (unchanged by anything here); the account profile describes
 * the selected authorization and deployment behaviour.
 *
 * Trust boundary: a profile name is not an authentication of the factory,
 * verifier, or creation code behind it. `selectProfile` validates shape and
 * fails closed on unknown profiles or chain conflicts; the binding itself
 * must come from a source the application trusts (pinned or operator-supplied).
 */

import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { concatHex, hexToBytes, keccak256, type Hex } from 'viem';

import {
  checkCommitAnnouncement, deriveCommitment, deriveOpener, encodeCommitMetaAddress, sendCommit,
  COMMIT_META_ADDRESS_VERSION, ML_KEM_768_EK_BYTES, PREIMAGE_DOMAINS, PREIMAGE_KEY_DOMAIN, SPHINCS_C13_DOMAINS,
  type CommitAnnouncementData, type CommitDomains, type CommitMetaAddress, type CommitPayment, type Deployment,
} from './commit-scheme.ts';

// ----------------------------------------------------------------------------
// ML-DSA-44 committed-key profile constants (exact bytes; UTF-8 == ASCII here)
// ----------------------------------------------------------------------------
export const ML_DSA_44_KEY_DOMAIN = 'pq-stealth/ml-dsa-44/key/v0';
export const ML_DSA_44_DOMAINS: CommitDomains = { open: 'pq-stealth/ml-dsa-44/open/v0', commit: 'pq-stealth/ml-dsa-44/commit/v0' };
export const ML_DSA_44_PK_BYTES = 1312;
export const ML_DSA_44_SIG_BYTES = 2420;
export const OPENER_BYTES = 32;
export const DIGEST_BYTES = 32;

/** An ML-DSA implementation from @noble/post-quantum (`ml_dsa44`, `ml_dsa65`, `ml_dsa87` share this shape). */
export type MlDsa = typeof ml_dsa44;

export interface Authorization {
  scheme: string;
  /** The signature implementation for signature profiles (mirrors Python's `dsa`); null otherwise. */
  dsa: MlDsa | null;
  /** spendKey = keccak256(keyDomain || pk); absent for the raw-key C13 profile. */
  keyDomain: string | null;
  pkBytes: number | null;
  sigBytes: number | null;
  /**
   * "pure/empty-ctx/digest32": FIPS 204 pure ML-DSA over the 32-byte account digest
   * with an empty context (M' = 0x00 || 0x00 || digest) — what the vendored ZKNOX
   * 3-argument `verify(bytes,bytes32,bytes)` hashes. No prehash, no double hashing.
   */
  messageConvention: string;
}

export interface AccountProfile {
  profileId: string;
  revision: number;
  metaAddressVersion: number;
  kem: 'ML-KEM-768';
  domains: CommitDomains;
  authorization: Authorization;
  bindingLayout: string;
  spendRouteStatus: string;
}

export const profileName = (p: AccountProfile): string => `${p.profileId}/v${p.revision}`;
export const payloadBytes = (p: AccountProfile): number | null =>
  p.authorization.pkBytes === null || p.authorization.sigBytes === null
    ? null : p.authorization.pkBytes + OPENER_BYTES + p.authorization.sigBytes;

const BINDING_LAYOUT_8141 =
  'CREATE2(factory, salt, keccak256(creation_code || commitment || leftpad32(verifier) || leftpad32(frame_ctx))) — Stealth8141ZkFactory shape';

export const SPHINCS_C13_COMMIT_V0: AccountProfile = {
  profileId: 'sphincs-c13-commit', revision: 0, metaAddressVersion: COMMIT_META_ADDRESS_VERSION, kem: 'ML-KEM-768',
  domains: SPHINCS_C13_DOMAINS,
  authorization: {
    scheme: 'SPHINCS- C13 (raw 32-byte key is the spend_key)', dsa: null, keyDomain: null, pkBytes: 32, sigBytes: 3688,
    messageConvention: 'C13 H_msg over the 32-byte digest, no envelope',
  },
  bindingLayout: BINDING_LAYOUT_8141,
  spendRouteStatus: 'deployed (D-018 commit signer, D-023 ZK circuit)',
};

export const PREIMAGE_V0: AccountProfile = {
  profileId: 'preimage', revision: 0, metaAddressVersion: COMMIT_META_ADDRESS_VERSION, kem: 'ML-KEM-768',
  domains: PREIMAGE_DOMAINS,
  authorization: {
    scheme: 'preimage ZK proof of (sk, opener); spend_key = keccak256(KEY || sk)', dsa: null, keyDomain: PREIMAGE_KEY_DOMAIN,
    pkBytes: null, sigBytes: null,
    messageConvention: 'UltraHonk public inputs [digest_hi, digest_lo, commitment_hi, commitment_lo]; backend not PQ-sound',
  },
  bindingLayout: BINDING_LAYOUT_8141,
  spendRouteStatus: 'deployed on the frames testnet (D-025 browser demo)',
};

/**
 * ML-DSA-44, not ML-DSA-65: the only ML-DSA verifier in this repository with an
 * executable on-chain path is the vendored ZKNOX `ZKNOX_dilithium` (df999ed,
 * NIST/SHAKE profile, fixed k = l = 4). The two parameter sets are not
 * interchangeable; a 65 profile needs its own verifier and its own name.
 */
export const ML_DSA_44_COMMIT_V0: AccountProfile = {
  profileId: 'ml-dsa-44-commit', revision: 0, metaAddressVersion: COMMIT_META_ADDRESS_VERSION, kem: 'ML-KEM-768',
  domains: ML_DSA_44_DOMAINS,
  authorization: {
    scheme: 'ML-DSA-44 (FIPS 204), canonical 1,312-byte public key', dsa: ml_dsa44, keyDomain: ML_DSA_44_KEY_DOMAIN,
    pkBytes: ML_DSA_44_PK_BYTES, sigBytes: ML_DSA_44_SIG_BYTES, messageConvention: 'pure/empty-ctx/digest32',
  },
  bindingLayout: BINDING_LAYOUT_8141,
  spendRouteStatus:
    'reference + local contract path (MlDsa44CommitSigner7913 over the vendored ZKNOX ML-DSA-44 verifier); key setup needs a trusted registrar — no trustless deployment, nothing live',
};

export const PROFILES: ReadonlyMap<string, AccountProfile> = new Map(
  [SPHINCS_C13_COMMIT_V0, PREIMAGE_V0, ML_DSA_44_COMMIT_V0].map((p) => [profileName(p), p]),
);

export class ProfileError extends Error {}

/** A selected profile bound to one chain and one deployment: trusted configuration. */
export interface ProfileBinding {
  profile: AccountProfile;
  chainId: number;
  deployment: Deployment;
}

const isAddress = (a: string): boolean => /^0x[0-9a-fA-F]{40}$/.test(a);
const isHex = (h: string): boolean => /^0x([0-9a-fA-F]{2})*$/.test(h);

/** Resolve an explicitly named profile and validate its deployment binding; fails closed. */
export function selectProfile(name: string, chainId: number, deployment: Deployment): ProfileBinding {
  const profile = PROFILES.get(name);
  if (!profile) throw new ProfileError(`unknown or unsupported profile ${JSON.stringify(name)}`);
  if (!Number.isInteger(chainId) || chainId <= 0) throw new ProfileError('chainId must be a positive integer');
  for (const [k, v] of [['factory', deployment.factory], ['verifier', deployment.verifier], ['frameCtx', deployment.frameCtx]] as const) {
    if (!isAddress(v)) throw new ProfileError(`deployment.${k} must be a 20-byte address`);
  }
  if (!isHex(deployment.creationCode) || deployment.creationCode.length <= 2) throw new ProfileError('deployment.creationCode must be non-empty hex');
  if (deployment.salt !== undefined && !/^0x[0-9a-fA-F]{64}$/.test(deployment.salt)) throw new ProfileError('deployment.salt must be 32 bytes');
  return { profile, chainId, deployment };
}

/** Fail closed when a binding is used on another chain than it was bound to. */
export function bindingForChain(binding: ProfileBinding, chainId: number): ProfileBinding {
  if (binding.chainId !== chainId) throw new ProfileError(`binding is for chain ${binding.chainId}, not chain ${chainId}`);
  return binding;
}

function checkMeta(meta: CommitMetaAddress, profile: AccountProfile): void {
  if (hexToBytes(meta.spendKey).length !== 32) throw new ProfileError('spendKey must be 32 bytes');
  if (meta.kemEk.length !== ML_KEM_768_EK_BYTES) throw new ProfileError(`meta-address KEM does not match profile ${profileName(profile)} (ML-KEM-768)`);
}

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
const concat = (...parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
};

// ----------------------------------------------------------------------------
// ML-DSA key commitment
// ----------------------------------------------------------------------------
/** spendKey = keccak256(keyDomain || pk) for the profile's exact parameter set (hashed once). */
export function spendKeyFromMlDsaPk(pk: Uint8Array, profile: AccountProfile = ML_DSA_44_COMMIT_V0): Hex {
  const { keyDomain, pkBytes, scheme } = profile.authorization;
  if (keyDomain === null || pkBytes === null) throw new ProfileError(`profile ${profileName(profile)} has no ML-DSA key commitment`);
  if (pk.length !== pkBytes) throw new ProfileError(`${scheme} public key must be ${pkBytes} bytes, got ${pk.length}`);
  return keccak256(concat(utf8(keyDomain), pk));
}

function signatureScheme(profile: AccountProfile): MlDsa {
  const { dsa } = profile.authorization;
  if (dsa === null) throw new ProfileError(`profile ${profileName(profile)} is not a signature profile`);
  return dsa;
}

/** Recipient: an ML-DSA keypair from a 32-byte seed (FIPS 204 keygen) under the profile's parameter set, and its spend key. */
export function mlDsaRecipient(zeta: Uint8Array, profile: AccountProfile = ML_DSA_44_COMMIT_V0): { publicKey: Uint8Array; secretKey: Uint8Array; spendKey: Hex } {
  if (zeta.length !== 32) throw new ProfileError('zeta must be 32 bytes');
  const { publicKey, secretKey } = signatureScheme(profile).keygen(zeta);
  return { publicKey, secretKey, spendKey: spendKeyFromMlDsaPk(publicKey, profile) };
}

/** @deprecated alias of `mlDsaRecipient(zeta, ML_DSA_44_COMMIT_V0)`. */
export const mlDsa44Recipient = (zeta: Uint8Array) => mlDsaRecipient(zeta, ML_DSA_44_COMMIT_V0);

export function encodeProfileMetaAddress(spendKey: Hex, kemEk: Uint8Array, profile: AccountProfile): Uint8Array {
  if (profile.metaAddressVersion !== COMMIT_META_ADDRESS_VERSION) throw new ProfileError('profile is not a 0x02 profile');
  return encodeCommitMetaAddress(spendKey, kemEk);
}

// ----------------------------------------------------------------------------
// Profile-aware send / scan (same bytes as commit-scheme.ts)
// ----------------------------------------------------------------------------
export function sendWithProfile(
  meta: CommitMetaAddress, binding: ProfileBinding, encaps?: { cipherText: Uint8Array; sharedSecret: Uint8Array },
): { announcement: CommitAnnouncementData; commitment: Hex; sharedSecret: Uint8Array } {
  checkMeta(meta, binding.profile);
  return sendCommit(meta, binding.deployment, encaps, binding.profile.domains);
}

/** Viewing key + public spend key + selected profile; accepts only after re-deriving the destination. */
export function checkWithProfile(
  meta: CommitMetaAddress, kemDk: Uint8Array, ann: CommitAnnouncementData, binding: ProfileBinding,
): CommitPayment | null {
  checkMeta(meta, binding.profile);
  return checkCommitAnnouncement(meta, kemDk, ann, binding.deployment, binding.profile.domains);
}

// ----------------------------------------------------------------------------
// Authorization payload:  pk || opener || signature
// ----------------------------------------------------------------------------
export interface AuthorizationParts { pk: Uint8Array; opener: Hex; sig: Uint8Array }

/**
 * Recipient: sign the account's canonical 32-byte operation digest (frame sig_hash,
 * userOpHash — it already binds chain, account, nonce, destination, value, calldata)
 * with pure ML-DSA-44 and an empty context, and open the commitment.
 */
export function buildAuthorization(
  secretKey: Uint8Array, publicKey: Uint8Array, opener: Hex, digest: Uint8Array,
  profile: AccountProfile = ML_DSA_44_COMMIT_V0, deterministic = false,
): Uint8Array {
  const dsa = signatureScheme(profile);
  const { pkBytes, sigBytes } = profile.authorization;
  if (pkBytes === null || sigBytes === null) throw new ProfileError(`profile ${profileName(profile)} is not a signature profile`);
  if (publicKey.length !== pkBytes) throw new ProfileError(`public key must be ${pkBytes} bytes`);
  const op = hexToBytes(opener);
  if (op.length !== OPENER_BYTES) throw new ProfileError('opener must be 32 bytes');
  if (digest.length !== DIGEST_BYTES) throw new ProfileError('digest must be 32 bytes');
  const sig = dsa.sign(digest, secretKey, deterministic ? { extraEntropy: false } : {});
  if (sig.length !== sigBytes) throw new ProfileError('unexpected signature length');
  return concat(publicKey, op, sig);
}

/** Split a payload into (pk, opener, sig); exact length only. */
export function parseAuthorization(payload: Uint8Array, profile: AccountProfile = ML_DSA_44_COMMIT_V0): AuthorizationParts {
  const total = payloadBytes(profile);
  const pkBytes = profile.authorization.pkBytes;
  if (total === null || pkBytes === null) throw new ProfileError(`profile ${profileName(profile)} has no signature payload`);
  if (payload.length !== total) throw new ProfileError(`payload must be ${total} bytes, got ${payload.length}`);
  const toHex = (b: Uint8Array): Hex => `0x${Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')}`;
  return { pk: payload.slice(0, pkBytes), opener: toHex(payload.slice(pkBytes, pkBytes + OPENER_BYTES)), sig: payload.slice(pkBytes + OPENER_BYTES) };
}

/**
 * Reference verifier — the steps the on-chain wrapper performs: parse and length-check,
 * spendKey = keccak256(keyDomain || pk), recompute the outer commitment and compare it to
 * the account's, then verify the signature under pk over the 32-byte digest (empty ctx).
 * Returns false, never throws, on any mismatch — like an ERC-7913 verifier's 0xffffffff.
 */
export function verifyAuthorization(
  commitment: Hex, digest: Uint8Array, payload: Uint8Array, profile: AccountProfile = ML_DSA_44_COMMIT_V0,
): boolean {
  const { dsa, keyDomain, pkBytes } = profile.authorization;
  if (dsa === null || keyDomain === null || pkBytes === null) return false;
  if (!/^0x[0-9a-fA-F]{64}$/.test(commitment) || digest.length !== DIGEST_BYTES) return false;
  let parts: AuthorizationParts;
  try { parts = parseAuthorization(payload, profile); } catch { return false; }
  const spendKey = spendKeyFromMlDsaPk(parts.pk, profile);
  if (deriveCommitment(spendKey, parts.opener, profile.domains).toLowerCase() !== commitment.toLowerCase()) return false;
  try { return dsa.verify(parts.sig, digest, parts.pk); } catch { return false; }
}

/** Opener under the selected profile's domain (sender- and scanner-known; not a credential). */
export function openerForPayment(ss: Uint8Array, profile: AccountProfile): Hex {
  return deriveOpener(ss, profile.domains);
}

/** ERC-7913 signer bytes for a committed ML-DSA-44 account: `verifier || commitment`. */
export function mlDsa44CommitSigner(verifier: Hex, commitment: Hex): Hex {
  return concatHex([verifier, commitment]);
}
