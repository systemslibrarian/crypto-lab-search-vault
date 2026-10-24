/**
 * Boneh-Di Crescenzo-Ostrovsky-Persiano public-key encryption with keyword
 * search (PEKS), adapted to the Type-3 BLS12-381 pairing exposed by noble.
 *
 * The 2004 construction is written for a symmetric bilinear group. Here the
 * keyword point and trapdoor live in G1, while the public key and randomized
 * tag component live in G2:
 *
 *   X = x P2
 *   PEKS(X, w; r) = (A = r P2, B = H2(e(H1(w), r X)))
 *   T_w = x H1(w)
 *   Test((A, B), T_w) := [B == H2(e(T_w, A))]
 *
 * Bilinearity gives e(x H1(w), r P2) = e(H1(w), x P2)^r. That proves
 * executable correctness. It does NOT transplant the original paper's
 * symmetric-pairing BDH reduction to this Type-3 adaptation; the UI and README
 * state that limitation explicitly.
 */
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { concat, ctEqual, frame, utf8 } from '../core/bytes';
import { sha256 } from '../core/prf';

export const PEKS_H1_DST =
  'CRYPTO-LAB-SEARCH-VAULT-PEKS-V1-BLS12381G1_XMD:SHA-256_SSWU_RO_';
export const PEKS_H2_DOMAIN = 'crypto-lab/search-vault/peks/v1/h2-gt';

export const PEKS_SIZES = {
  publicKey: 96,
  tagPoint: 96,
  trapdoor: 48,
  digest: 32,
} as const;

export interface PeksPublicKey {
  /** Canonical compressed non-identity G2 encoding of X = x P2. */
  readonly bytes: Uint8Array;
}

export interface PeksSecretKey {
  /** Recipient-only scalar x. It is never part of a tag, trapdoor, or server record. */
  readonly scalar: bigint;
}

export interface PeksKeyPair {
  readonly publicKey: PeksPublicKey;
  readonly secretKey: PeksSecretKey;
}

export interface PeksTrapdoor {
  /** Canonical compressed non-identity G1 encoding of T_w = x H1(w). */
  readonly bytes: Uint8Array;
}

export interface PeksTag {
  /** Canonical compressed G2 encoding of A = r P2. */
  readonly a: Uint8Array;
  /** H2 digest of the sender-side GT element. */
  readonly b: Uint8Array;
}

type G1Point = InstanceType<typeof bls.G1.Point>;
type G2Point = InstanceType<typeof bls.G2.Point>;
type GtElement = ReturnType<typeof bls.pairing>;

const ORDER = bls.fields.Fr.ORDER;
const G2_BASE = bls.G2.Point.BASE;

/** Exact-match normalization used by every PEKS role in this exhibit. */
export function normalizePeksKeyword(keyword: string): string {
  const normalized = keyword.normalize('NFKC').trim().toLowerCase();
  if (!normalized) throw new Error('PEKS keyword must not be empty');
  return normalized;
}

/**
 * Uniformly sample x in [1, r-1]. Masking to 255 bits and rejecting values at
 * or above the subgroup order avoids modulo bias.
 */
export function randomNonzeroScalar(): bigint {
  while (true) {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    bytes[0] &= 0x7f;
    const candidate = bytesToBigInt(bytes);
    if (candidate > 0n && candidate < ORDER) return candidate;
  }
}

export function generatePeksKeyPair(): PeksKeyPair {
  return derivePeksKeyPair(randomNonzeroScalar());
}

/**
 * Deterministic low-level helper for fixed-transcript and independent tests.
 * The learner/application path must call generatePeksKeyPair: reused or
 * caller-chosen secret scalars are not a safe key-generation interface.
 */
export function derivePeksKeyPair(secretScalar: bigint): PeksKeyPair {
  assertScalar(secretScalar, 'recipient secret');
  const point = G2_BASE.multiply(secretScalar);
  return {
    publicKey: { bytes: point.toBytes(true) },
    secretKey: { scalar: secretScalar },
  };
}

/** RFC 9380 random-oracle hash to BLS12-381 G1 under a PEKS-only DST. */
export function hashKeywordToG1(keyword: string): G1Point {
  const normalized = normalizePeksKeyword(keyword);
  return bls.G1.hashToCurve(utf8(normalized), { DST: PEKS_H1_DST });
}

/** Anyone holding only the recipient public key can produce a randomized tag. */
export async function encryptKeyword(
  publicKey: PeksPublicKey,
  keyword: string,
): Promise<PeksTag> {
  return encryptKeywordWithScalar(publicKey, keyword, randomNonzeroScalar());
}

/**
 * Deterministic low-level form used to verify the construction independently.
 * The learner/application path must call encryptKeyword: reusing r would make
 * randomized tags linkable and is deliberately not exposed by the UI.
 */
export async function encryptKeywordWithScalar(
  publicKey: PeksPublicKey,
  keyword: string,
  senderScalar: bigint,
): Promise<PeksTag> {
  assertScalar(senderScalar, 'sender randomness');
  const xPoint = decodeG2(publicKey.bytes, 'recipient public key');
  const keywordPoint = hashKeywordToG1(keyword);
  const aPoint = G2_BASE.multiply(senderScalar);
  // Original h^r route: compute rX with the curve's scalar multiplication,
  // then pair once. Avoid Fp12.pow(..., r): noble documents generic field pow
  // as variable-time, so it is the wrong operation for secret ephemeral r.
  const senderGt = bls.pairing(keywordPoint, xPoint.multiply(senderScalar));
  return {
    a: aPoint.toBytes(true),
    b: await hashGt(senderGt),
  };
}

/** Recipient-only operation T_w = x H1(w). */
export function issueTrapdoor(secretKey: PeksSecretKey, keyword: string): PeksTrapdoor {
  assertScalar(secretKey.scalar, 'recipient secret');
  return { bytes: hashKeywordToG1(keyword).multiply(secretKey.scalar).toBytes(true) };
}

/** Public Test algorithm. It returns false on a well-formed non-match. */
export async function testTag(tag: PeksTag, trapdoor: PeksTrapdoor): Promise<boolean> {
  if (tag.b.length !== PEKS_SIZES.digest) {
    throw new Error(`PEKS digest must be ${PEKS_SIZES.digest} bytes`);
  }
  const aPoint = decodeG2(tag.a, 'PEKS tag A');
  const trapdoorPoint = decodeG1(trapdoor.bytes, 'PEKS trapdoor');
  const recipientGt = bls.pairing(trapdoorPoint, aPoint);
  // ctEqual scans all 32 bytes, but JavaScript runtimes do not provide a hard
  // constant-time guarantee. This teaching implementation makes no
  // side-channel-hardening claim.
  return ctEqual(tag.b, await hashGt(recipientGt));
}

/** Copies a public tag across the sender/server boundary. */
export function cloneTag(tag: PeksTag): PeksTag {
  return { a: tag.a.slice(), b: tag.b.slice() };
}

function decodeG1(bytes: Uint8Array, label: string): G1Point {
  if (bytes.length !== PEKS_SIZES.trapdoor) {
    throw new Error(`${label} must be ${PEKS_SIZES.trapdoor} bytes`);
  }
  const point = bls.G1.Point.fromBytes(bytes);
  point.assertValidity();
  if (point.is0()) throw new Error(`${label} must not be the identity point`);
  if (!point.isTorsionFree()) throw new Error(`${label} is not in the prime-order subgroup`);
  if (!ctEqual(point.toBytes(true), bytes)) throw new Error(`${label} is not canonically encoded`);
  return point;
}

function decodeG2(bytes: Uint8Array, label: string): G2Point {
  if (bytes.length !== PEKS_SIZES.publicKey) {
    throw new Error(`${label} must be ${PEKS_SIZES.publicKey} bytes`);
  }
  const point = bls.G2.Point.fromBytes(bytes);
  point.assertValidity();
  if (point.is0()) throw new Error(`${label} must not be the identity point`);
  if (!point.isTorsionFree()) throw new Error(`${label} is not in the prime-order subgroup`);
  if (!ctEqual(point.toBytes(true), bytes)) throw new Error(`${label} is not canonically encoded`);
  return point;
}

async function hashGt(gt: GtElement): Promise<Uint8Array> {
  // noble's fixed 576-byte Fp12 coefficient encoding. RFC 9380 standardizes
  // hash-to-curve, not a wire format for arbitrary GT elements, so do not call
  // this an interoperable standardized GT encoding.
  const gtBytes = bls.fields.Fp12.toBytes(gt);
  return sha256(concat(frame(utf8(PEKS_H2_DOMAIN)), frame(gtBytes)));
}

function assertScalar(scalar: bigint, label: string): void {
  if (scalar <= 0n || scalar >= ORDER) {
    throw new Error(`${label} must be in [1, r-1]`);
  }
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let out = 0n;
  for (const byte of bytes) out = (out << 8n) | BigInt(byte);
  return out;
}
