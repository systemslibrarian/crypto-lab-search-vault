/**
 * Bounded OXT core for the two-keyword conjunction lesson.
 *
 * This is a static, single-owner teaching adapter of Cash et al.'s OXT
 * equations. It deliberately supports one shape only: s AND x. The server
 * receives a deterministic s-term lookup token plus one blinded group element
 * per tuple in that s-term's list. It never receives the x-term posting list.
 *
 * Additive ristretto255 notation used here:
 *
 *   xind       = F_I(id)
 *   xtag(w,id) = [F_X(w) * xind]B
 *   z(s,c)     = F_Z(s || c)
 *   y(s,c,id)  = xind / z(s,c) mod l
 *   xtoken     = [z(s,c) * F_X(x)]B
 *
 * The server computes [y]xtoken = [F_X(x) * xind]B and checks exact XSet
 * membership. XSet is a sorted set of canonical RFC 9496 encodings, not a
 * Bloom filter, so this bounded implementation introduces no probabilistic
 * membership false positives.
 */
import { ristretto255 } from '@noble/curves/ed25519.js';
import { open, seal } from '../core/aead';
import {
  frame,
  fromHex,
  fromUtf8,
  randomBytes,
  toHex,
  u32be,
  utf8,
} from '../core/bytes';
import { hmacSha256, hmacSha512 } from '../core/prf';
import { CORPUS, KEYWORDS, documentsFor } from '../sse/corpus';
import type { Document } from '../sse/types';

const Point = ristretto255.Point;
const Scalar = Point.Fn;

export const RISTRETTO_ORDER = Scalar.ORDER;

export const OXT_DOMAIN = {
  STAG: 'crypto-lab/search-vault/oxt/v1/stag',
  TSET_ADDRESS: 'crypto-lab/search-vault/oxt/v1/tset-address',
  ENCRYPTION_KEY: 'crypto-lab/search-vault/oxt/v1/encryption-key',
  XTERM: 'crypto-lab/search-vault/oxt/v1/xterm-scalar',
  DOCUMENT: 'crypto-lab/search-vault/oxt/v1/document-scalar',
  BLIND: 'crypto-lab/search-vault/oxt/v1/blind-scalar',
} as const;

export interface OxtKeys {
  readonly kStag: Uint8Array;
  readonly kEnc: Uint8Array;
  readonly kX: Uint8Array;
  readonly kId: Uint8Array;
  readonly kZ: Uint8Array;
}

/** One unlinkable TSet row as the server receives it at setup. */
export interface OxtTSetRow {
  readonly addressHex: string;
  readonly encryptedId: Uint8Array;
  /** Canonical 32-byte little-endian ristretto255 scalar encoding. */
  readonly y: Uint8Array;
}

/**
 * Flat TSet rows hide per-keyword list boundaries before a stag is queried.
 * The total row count and exact XSet size remain setup leakage.
 */
export interface OxtEncryptedIndex {
  readonly tsetRows: readonly OxtTSetRow[];
  readonly xset: readonly string[];
}

export interface OxtServerQuery {
  readonly stag: Uint8Array;
  readonly xtokens: readonly Uint8Array[];
}

/** Client-only labels stay outside OxtServerQuery. */
export interface OxtClientQuery {
  readonly canonical: string;
  readonly sTerm: string;
  readonly xTerm: string;
  readonly serverQuery: OxtServerQuery;
}

export interface OxtEncryptedMatch {
  readonly position: number;
  readonly addressHex: string;
  readonly encryptedId: Uint8Array;
}

export function generateOxtKeys(): OxtKeys {
  return {
    kStag: randomBytes(32),
    kEnc: randomBytes(32),
    kX: randomBytes(32),
    kId: randomBytes(32),
    kZ: randomBytes(32),
  };
}

export type WideMac = (key: Uint8Array, message: Uint8Array) => Promise<Uint8Array>;

/**
 * Deterministic nonzero scalar PRF. HMAC-SHA-512 supplies 512 uniform-looking
 * bits, interpreted little-endian and reduced modulo the ristretto255 scalar
 * order. A framed retry counter handles the negligible zero case.
 */
export async function scalarPrf(
  key: Uint8Array,
  domain: string,
  ...inputs: Uint8Array[]
): Promise<bigint> {
  return scalarPrfWithMac(key, domain, inputs, hmacSha512);
}

/** Exported so tests can force the zero-output retry without weakening the
 * production path or pretending that a practically impossible event ran. */
export async function scalarPrfWithMac(
  key: Uint8Array,
  domain: string,
  inputs: readonly Uint8Array[],
  mac: WideMac,
): Promise<bigint> {
  assertKey(key, 'scalar PRF key');
  if (domain.length === 0) throw new Error('scalar PRF domain must not be empty');
  for (let counter = 0; counter <= 0xffffffff; counter++) {
    const digest = await mac(
      key,
      frame(utf8(domain), ...inputs, u32be(counter)),
    );
    if (!(digest instanceof Uint8Array) || digest.length !== 64) {
      throw new Error('scalar PRF requires a 64-byte wide-MAC output');
    }
    const scalar = Scalar.create(bytesToBigIntLittleEndian(digest));
    if (Scalar.isValidNot0(scalar)) return scalar;
  }
  throw new Error('scalar derivation exhausted its counter');
}

export async function stagFor(keys: OxtKeys, keyword: string): Promise<Uint8Array> {
  assertOxtKeys(keys);
  return oxtPrf256(keys.kStag, OXT_DOMAIN.STAG, utf8(normalizeIndexedKeyword(keyword)));
}

export async function tsetAddressFor(stag: Uint8Array, position: number): Promise<Uint8Array> {
  assertKey(stag, 'stag');
  if (!Number.isSafeInteger(position) || position < 1 || position > 0xffffffff) {
    throw new Error('TSet position must be an integer from 1 through 2^32-1');
  }
  return oxtPrf256(stag, OXT_DOMAIN.TSET_ADDRESS, u32be(position));
}

/** OXT-only HMAC-SHA-256 with the domain and every input length-framed. */
export async function oxtPrf256(
  key: Uint8Array,
  domain: string,
  ...inputs: Uint8Array[]
): Promise<Uint8Array> {
  assertKey(key, 'OXT PRF key');
  if (domain.length === 0) throw new Error('OXT PRF domain must not be empty');
  return hmacSha256(key, frame(utf8(domain), ...inputs));
}

export async function xtermScalar(keys: OxtKeys, keyword: string): Promise<bigint> {
  return scalarPrf(keys.kX, OXT_DOMAIN.XTERM, utf8(normalizeIndexedKeyword(keyword)));
}

export async function documentScalar(keys: OxtKeys, documentId: string): Promise<bigint> {
  if (documentId.length === 0) throw new Error('document id must not be empty');
  return scalarPrf(keys.kId, OXT_DOMAIN.DOCUMENT, utf8(documentId));
}

export async function blindScalar(
  keys: OxtKeys,
  sTerm: string,
  position: number,
): Promise<bigint> {
  if (!Number.isSafeInteger(position) || position < 1 || position > 0xffffffff) {
    throw new Error('blind position must be an integer from 1 through 2^32-1');
  }
  return scalarPrf(
    keys.kZ,
    OXT_DOMAIN.BLIND,
    utf8(normalizeIndexedKeyword(sTerm)),
    u32be(position),
  );
}

export async function crossTagFor(
  keys: OxtKeys,
  keyword: string,
  documentId: string,
): Promise<Uint8Array> {
  const fx = await xtermScalar(keys, keyword);
  const xind = await documentScalar(keys, documentId);
  return Point.BASE.multiply(Scalar.mul(fx, xind)).toBytes();
}

/**
 * Strict server-side boundary: canonical RFC 9496 decoding, identity rejection,
 * and a nonzero canonical scalar before the blinded multiplication.
 */
export function evaluateCrossToken(xtoken: Uint8Array, y: bigint): Uint8Array {
  if (!(xtoken instanceof Uint8Array) || xtoken.length !== 32) {
    throw new Error('OXT cross-token must be a 32-byte ristretto255 encoding');
  }
  if (!Scalar.isValidNot0(y)) throw new Error('OXT y must be a canonical nonzero scalar');
  let point: InstanceType<typeof Point>;
  try {
    point = Point.fromBytes(xtoken);
  } catch {
    throw new Error('OXT cross-token is not a canonical ristretto255 encoding');
  }
  if (point.is0()) throw new Error('OXT cross-token must not be the identity');
  return point.multiply(y).toBytes();
}

/**
 * Build a flat addressed TSet and exact XSet. Each keyword's document list is
 * shuffled before positions c and their y values are assigned.
 */
export async function buildOxtIndex(
  keys: OxtKeys,
  corpus: readonly Document[] = CORPUS,
): Promise<OxtEncryptedIndex> {
  assertOxtKeys(keys);
  assertCorpus(corpus);
  const tsetRows: OxtTSetRow[] = [];

  for (const keyword of KEYWORDS) {
    const ids = shuffleWithCsprng(documentsFor(keyword, [...corpus]));
    const stag = await stagFor(keys, keyword);
    const encryptionKey = await oxtPrf256(
      keys.kEnc,
      OXT_DOMAIN.ENCRYPTION_KEY,
      utf8(keyword),
    );

    for (let offset = 0; offset < ids.length; offset++) {
      const position = offset + 1;
      const id = ids[offset]!;
      const address = await tsetAddressFor(stag, position);
      const addressHex = toHex(address);
      const xind = await documentScalar(keys, id);
      const z = await blindScalar(keys, keyword, position);
      const y = Scalar.div(xind, z);
      tsetRows.push({
        addressHex,
        encryptedId: await seal(encryptionKey, utf8(id), address),
        y: Scalar.toBytes(y),
      });
    }
  }

  if (new Set(tsetRows.map((row) => row.addressHex)).size !== tsetRows.length) {
    throw new Error('TSet address collision');
  }

  const xset = (
    await Promise.all(
      corpus.flatMap((document) =>
        document.keywords.map((keyword) => crossTagFor(keys, keyword, document.id)),
      ),
    )
  )
    .map(toHex)
    .sort();
  if (new Set(xset).size !== xset.length) throw new Error('XSet cross-tag collision');

  return {
    // A second, global shuffle removes the setup loop's keyword-grouped row
    // order. Positions c were already bound inside each list and are recovered
    // only by addressed lookup, so this shuffle cannot break their algebra.
    tsetRows: shuffleWithCsprng(tsetRows).map(cloneTSetRow),
    xset: [...xset],
  };
}

export async function createOxtQuery(
  keys: OxtKeys,
  left: string,
  right: string,
  corpus: readonly Document[] = CORPUS,
): Promise<OxtClientQuery> {
  assertCorpus(corpus);
  const first = normalizeIndexedKeyword(left);
  const second = normalizeIndexedKeyword(right);
  if (first === second) throw new Error('OXT conjunction requires two distinct keywords');
  const [sTerm, xTerm] = selectTerms(first, second, corpus);
  const count = documentsFor(sTerm, [...corpus]).length;
  const fx = await xtermScalar(keys, xTerm);
  const xtokens: Uint8Array[] = [];
  for (let position = 1; position <= count; position++) {
    const z = await blindScalar(keys, sTerm, position);
    xtokens.push(Point.BASE.multiply(Scalar.mul(z, fx)).toBytes());
  }
  return {
    canonical: `${first} AND ${second}`,
    sTerm,
    xTerm,
    serverQuery: { stag: await stagFor(keys, sTerm), xtokens },
  };
}

export async function decryptOxtMatches(
  keys: OxtKeys,
  query: OxtClientQuery,
  matches: readonly OxtEncryptedMatch[],
  corpus: readonly Document[] = CORPUS,
): Promise<string[]> {
  assertCorpus(corpus);
  const allowedIds = new Set(corpus.map((document) => document.id));
  const corpusOrder = new Map(corpus.map((document, index) => [document.id, index] as const));
  const encryptionKey = await oxtPrf256(
    keys.kEnc,
    OXT_DOMAIN.ENCRYPTION_KEY,
    utf8(query.sTerm),
  );
  const ids: string[] = [];
  for (const match of matches) {
    const id = fromUtf8(
      await open(encryptionKey, match.encryptedId, fromHex(match.addressHex)),
    );
    if (!allowedIds.has(id)) throw new Error('decrypted OXT document id is not in the client corpus');
    ids.push(id);
  }
  if (new Set(ids).size !== ids.length) throw new Error('OXT response repeated a document id');
  return ids.sort((left, right) => corpusOrder.get(left)! - corpusOrder.get(right)!);
}

export function selectTerms(
  left: string,
  right: string,
  corpus: readonly Document[] = CORPUS,
): readonly [sTerm: string, xTerm: string] {
  const a = normalizeIndexedKeyword(left);
  const b = normalizeIndexedKeyword(right);
  if (a === b) throw new Error('OXT conjunction requires two distinct keywords');
  const aCount = documentsFor(a, [...corpus]).length;
  const bCount = documentsFor(b, [...corpus]).length;
  if (aCount < bCount) return [a, b];
  if (bCount < aCount) return [b, a];
  // Indexed keywords are lowercase ASCII. Direct code-unit order is stable
  // across runtimes and locales; localeCompare is intentionally avoided.
  return a < b ? [a, b] : [b, a];
}

export function scalarToHex(value: bigint): string {
  if (!Scalar.isValid(value)) throw new Error('scalar is not canonical');
  return toHex(Scalar.toBytes(value));
}

export function scalarFromBytes(value: Uint8Array): bigint {
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    throw new Error('scalar encoding must be exactly 32 bytes');
  }
  try {
    return Scalar.fromBytes(value);
  } catch {
    throw new Error('scalar encoding is not canonical');
  }
}

/** Unbiased CSPRNG Fisher-Yates shuffle. */
export function shuffleWithCsprng<T>(items: readonly T[]): T[] {
  const out = [...items];
  for (let i = out.length - 1; i > 0; i--) {
    const j = randomIndex(i + 1);
    [out[i], out[j]] = [out[j]!, out[i]!];
  }
  return out;
}

/** Rejection sampling avoids the modulo bias of randomUint32 % upperBound. */
export function randomIndex(upperBound: number, draw: () => number = randomUint32): number {
  if (!Number.isSafeInteger(upperBound) || upperBound < 1 || upperBound > 0x100000000) {
    throw new Error('random-index upper bound must be between 1 and 2^32');
  }
  const range = 0x100000000;
  const limit = Math.floor(range / upperBound) * upperBound;
  for (;;) {
    const candidate = draw();
    if (!Number.isSafeInteger(candidate) || candidate < 0 || candidate > 0xffffffff) {
      throw new Error('random-index source returned a value outside uint32');
    }
    if (candidate < limit) return candidate % upperBound;
  }
}

function randomUint32(): number {
  return crypto.getRandomValues(new Uint32Array(1))[0]!;
}

export function bytesToBigIntLittleEndian(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index--) {
    value = (value << 8n) | BigInt(bytes[index]!);
  }
  return value;
}

function normalizeIndexedKeyword(keyword: string): string {
  const normalized = keyword.trim().toLowerCase();
  if (!(KEYWORDS as readonly string[]).includes(normalized)) {
    throw new Error(`keyword is not in the fixed indexed vocabulary: ${normalized || '(empty)'}`);
  }
  return normalized;
}

function assertKey(key: Uint8Array, label: string): void {
  if (!(key instanceof Uint8Array) || key.length !== 32) {
    throw new Error(`${label} must be exactly 32 bytes`);
  }
}

function assertOxtKeys(keys: OxtKeys): void {
  assertKey(keys.kStag, 'OXT stag key');
  assertKey(keys.kEnc, 'OXT encryption key');
  assertKey(keys.kX, 'OXT x-term key');
  assertKey(keys.kId, 'OXT document key');
  assertKey(keys.kZ, 'OXT blinding key');
}

function assertCorpus(corpus: readonly Document[]): void {
  const ids = corpus.map((document) => document.id);
  if (ids.length === 0 || new Set(ids).size !== ids.length) {
    throw new Error('OXT corpus must contain unique document ids');
  }
  const encodedIdLengths = new Set<number>();
  for (const document of corpus) {
    if (document.id.length === 0) throw new Error('OXT document id must not be empty');
    const encodedId = utf8(document.id);
    if (fromUtf8(encodedId) !== document.id) {
      throw new Error(`OXT document id is not well-formed Unicode: ${document.id}`);
    }
    encodedIdLengths.add(encodedId.length);
    if (new Set(document.keywords).size !== document.keywords.length) {
      throw new Error(`OXT document ${document.id} repeats a keyword`);
    }
    for (const keyword of document.keywords) {
      const normalized = normalizeIndexedKeyword(keyword);
      if (keyword !== normalized) {
        throw new Error(
          `OXT document ${document.id} keyword must already be normalized: ${keyword}`,
        );
      }
    }
  }
  if (encodedIdLengths.size !== 1) {
    throw new Error('OXT corpus document ids must have one fixed UTF-8 byte length');
  }
  for (const keyword of KEYWORDS) {
    if (documentsFor(keyword, [...corpus]).length === 0) {
      throw new Error(`OXT corpus is missing indexed keyword: ${keyword}`);
    }
  }
}

function cloneTSetRow(row: OxtTSetRow): OxtTSetRow {
  return {
    addressHex: row.addressHex,
    encryptedId: row.encryptedId.slice(),
    y: row.y.slice(),
  };
}
