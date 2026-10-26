/** Pairing roles and iterative-testing server for the L-R-08 MUSE lesson. */
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { ctEqual, frame, randomBytes, toHex, utf8 } from '../core/bytes';
import { sha256 } from '../core/prf';
import { modInverse } from './math';

export const MUSE_H1_DST =
  'CRYPTO-LAB-SEARCH-VAULT-MUSE-V1-BLS12381G1_XMD:SHA-256_SSWU_RO_';
export const MUSE_GT_DOMAIN = 'crypto-lab/search-vault/muse/v1/gt-search-element';

type G1Point = InstanceType<typeof bls.G1.Point>;
type G2Point = InstanceType<typeof bls.G2.Point>;
export type MuseGtElement = ReturnType<typeof bls.pairing>;

const ORDER = bls.fields.Fr.ORDER;
const G2_BASE = bls.G2.Point.BASE;
const GT_BYTES = bls.fields.Fp12.BYTES;

export interface MuseReaderPublicKey {
  readonly readerId: string;
  /** P2^(1/rho_r), canonical compressed BLS12-381 G2. */
  readonly bytes: Uint8Array;
}

export interface MuseAuthorization {
  readonly readerId: string;
  readonly writerId: string;
  /** Delta_r,w = publicReader^gamma_w. */
  readonly deltaBytes: Uint8Array;
}

export interface MuseEncryptedRow {
  readonly rowId: string;
  /** Canonical noble Fp12 coefficient encoding of e(H(x),P2^gamma_w). */
  readonly gtBytes: Uint8Array;
}

export interface MuseEncryptedIndex {
  readonly writerId: string;
  readonly rows: readonly MuseEncryptedRow[];
}

export interface MuseTrapdoor {
  readonly readerId: string;
  readonly bytes: Uint8Array;
}

export interface SingleServerMatch {
  readonly writerId: string;
  readonly rowId: string;
}

export interface SingleServerObservation {
  readonly queryId: string;
  readonly readerId: string;
  readonly requestedWriterIds: readonly string[];
  readonly trapdoorHex: string;
  readonly testedRows: number;
  readonly matches: readonly SingleServerMatch[];
}

export interface SingleServerResult {
  readonly queryId: string;
  readonly matchedWriterIds: readonly string[];
  readonly testedRows: number;
  readonly matches: readonly SingleServerMatch[];
}

export class MuseReader {
  readonly id: string;
  readonly publicKey: MuseReaderPublicKey;
  readonly #rho: bigint;
  readonly #resultKey: Uint8Array;

  constructor(id: string, rho = randomMuseScalar(), resultKey = randomBytes(32)) {
    assertPrincipalId(id, 'reader');
    assertScalar(rho, 'reader scalar');
    if (resultKey.length !== 32) throw new Error('reader result key must be 32 bytes');
    this.id = id;
    this.#rho = rho;
    this.#resultKey = resultKey.slice();
    const inverse = modInverse(rho, ORDER);
    this.publicKey = {
      readerId: id,
      bytes: G2_BASE.multiply(inverse).toBytes(true),
    };
  }

  /** Iterative-testing baseline: xi=1, so matching transformed values persist. */
  issueSingleServerTrapdoor(keyword: string): MuseTrapdoor {
    return {
      readerId: this.id,
      bytes: hashMuseKeyword(keyword).multiply(this.#rho).toBytes(true),
    };
  }

  /** SCC 2018 §5: fresh xi blinds this query before QM transforms it. */
  issueSplitTrustTrapdoor(keyword: string, xi = randomMuseScalar()): {
    readonly trapdoor: MuseTrapdoor;
    readonly dhBlinding: bigint;
  } {
    assertScalar(xi, 'query blinding scalar');
    return {
      trapdoor: {
        readerId: this.id,
        bytes: hashMuseKeyword(keyword).multiply((xi * this.#rho) % ORDER).toBytes(true),
      },
      dhBlinding: xi,
    };
  }

  /** Reader-only copy. Returned defensively for the DH handoff in this model. */
  resultKeyForDataHost(): Uint8Array {
    return this.#resultKey.slice();
  }

  resultKeyForOpen(): Uint8Array {
    return this.#resultKey.slice();
  }
}

export class MuseWriter {
  readonly id: string;
  readonly #gamma: bigint;
  readonly #keywords: readonly string[];

  constructor(id: string, keywords: readonly string[], gamma = randomMuseScalar()) {
    assertPrincipalId(id, 'writer');
    assertScalar(gamma, 'writer scalar');
    const normalized = [...new Set(keywords.map(normalizeMuseKeyword))];
    if (normalized.length === 0) throw new Error('writer index must contain at least one keyword');
    this.id = id;
    this.#gamma = gamma;
    this.#keywords = normalized;
  }

  encryptIndex(): MuseEncryptedIndex {
    const publicPoint = G2_BASE.multiply(this.#gamma);
    return {
      writerId: this.id,
      rows: this.#keywords.map((keyword, index) => ({
        rowId: `${this.id}:row-${index + 1}`,
        gtBytes: encodeGt(bls.pairing(hashMuseKeyword(keyword), publicPoint)),
      })),
    };
  }

  delegate(reader: MuseReaderPublicKey): MuseAuthorization {
    const readerPoint = decodeG2(reader.bytes, 'reader public key');
    return {
      readerId: reader.readerId,
      writerId: this.id,
      deltaBytes: readerPoint.multiply(this.#gamma).toBytes(true),
    };
  }
}

export class IterativeMuseServer {
  readonly #indices: Map<string, MuseEncryptedIndex>;
  readonly #authorizations: Map<string, MuseAuthorization>;
  readonly #observations: SingleServerObservation[] = [];

  constructor(indices: readonly MuseEncryptedIndex[], authorizations: readonly MuseAuthorization[]) {
    if (indices.length === 0) throw new Error('MUSE server requires at least one writer index');
    this.#indices = new Map();
    for (const index of indices) {
      if (this.#indices.has(index.writerId)) throw new Error('writer index ids must be unique');
      if (index.rows.length === 0) throw new Error('writer index must not be empty');
      const rowIds = index.rows.map((row) => row.rowId);
      if (new Set(rowIds).size !== rowIds.length) throw new Error('encrypted row ids must be unique');
      for (const row of index.rows) decodeGt(row.gtBytes, 'encrypted index token');
      this.#indices.set(index.writerId, cloneIndex(index));
    }
    this.#authorizations = new Map();
    for (const authorization of authorizations) {
      if (!this.#indices.has(authorization.writerId)) {
        throw new Error('authorization names an unknown writer');
      }
      decodeG2(authorization.deltaBytes, 'authorization delta');
      const key = authorizationKey(authorization.readerId, authorization.writerId);
      if (this.#authorizations.has(key)) throw new Error('duplicate reader/writer authorization');
      this.#authorizations.set(key, cloneAuthorization(authorization));
    }
  }

  search(trapdoor: MuseTrapdoor, requestedWriterIds: readonly string[]): SingleServerResult {
    const writerIds = validateRequestedWriters(requestedWriterIds);
    // Resolve every capability before decoding/testing anything or appending a
    // transcript: an unauthorized mixed request fails atomically.
    const work = writerIds.map((writerId) => {
      const index = this.#indices.get(writerId);
      if (!index) throw new Error(`unknown writer index: ${writerId}`);
      const authorization = this.#authorizations.get(authorizationKey(trapdoor.readerId, writerId));
      if (!authorization) throw new Error(`reader ${trapdoor.readerId} is not authorized for ${writerId}`);
      return { index, authorization };
    });
    const queryPoint = decodeG1(trapdoor.bytes, 'reader trapdoor');
    const matches: SingleServerMatch[] = [];
    let testedRows = 0;
    for (const { index, authorization } of work) {
      const transformed = bls.pairing(
        queryPoint,
        decodeG2(authorization.deltaBytes, 'authorization delta'),
      );
      for (const row of index.rows) {
        testedRows += 1;
        if (bls.fields.Fp12.eql(transformed, decodeGt(row.gtBytes, 'encrypted index token'))) {
          matches.push({ writerId: index.writerId, rowId: row.rowId });
        }
      }
    }
    const queryId = `query-${this.#observations.length + 1}`;
    this.#observations.push({
      queryId,
      readerId: trapdoor.readerId,
      requestedWriterIds: [...writerIds],
      trapdoorHex: toHex(trapdoor.bytes),
      testedRows,
      matches: matches.map((match) => ({ ...match })),
    });
    return {
      queryId,
      matchedWriterIds: [...new Set(matches.map((match) => match.writerId))],
      testedRows,
      matches: matches.map((match) => ({ ...match })),
    };
  }

  observations(): SingleServerObservation[] {
    return this.#observations.map((observation) => ({
      ...observation,
      requestedWriterIds: [...observation.requestedWriterIds],
      matches: observation.matches.map((match) => ({ ...match })),
    }));
  }
}

export function transformMuseTrapdoor(
  trapdoor: MuseTrapdoor,
  authorization: MuseAuthorization,
): MuseGtElement {
  if (trapdoor.readerId !== authorization.readerId) {
    throw new Error('authorization delta belongs to a different reader');
  }
  return bls.pairing(
    decodeG1(trapdoor.bytes, 'reader trapdoor'),
    decodeG2(authorization.deltaBytes, 'authorization delta'),
  );
}

export function blindEncryptedIndex(index: MuseEncryptedIndex, xi: bigint): MuseGtElement[] {
  assertScalar(xi, 'query blinding scalar');
  return index.rows.map((row) =>
    bls.fields.Fp12.pow(decodeGt(row.gtBytes, 'encrypted index token'), xi),
  );
}

export async function gtSearchElement(gt: MuseGtElement): Promise<Uint8Array> {
  return sha256(frame(utf8(MUSE_GT_DOMAIN), encodeGt(gt)));
}

export function encodeGt(gt: MuseGtElement): Uint8Array {
  return bls.fields.Fp12.toBytes(gt);
}

export function decodeGt(bytes: Uint8Array, label: string): MuseGtElement {
  if (bytes.length !== GT_BYTES) throw new Error(`${label} must be ${GT_BYTES} bytes`);
  const value = bls.fields.Fp12.fromBytes(bytes);
  if (!ctEqual(bls.fields.Fp12.toBytes(value), bytes)) {
    throw new Error(`${label} is not canonically encoded`);
  }
  return value;
}

export function hashMuseKeyword(keyword: string): G1Point {
  return bls.G1.hashToCurve(utf8(normalizeMuseKeyword(keyword)), { DST: MUSE_H1_DST });
}

export function normalizeMuseKeyword(keyword: string): string {
  const normalized = keyword.normalize('NFKC').trim().toLowerCase();
  if (!/^[a-z]{2,24}$/.test(normalized)) {
    throw new Error('MUSE keyword must contain 2–24 ASCII letters');
  }
  return normalized;
}

export function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return ctEqual(left, right);
}

function decodeG1(bytes: Uint8Array, label: string): G1Point {
  if (bytes.length !== 48) throw new Error(`${label} must be 48 bytes`);
  const point = bls.G1.Point.fromBytes(bytes);
  point.assertValidity();
  if (point.is0() || !point.isTorsionFree() || !ctEqual(point.toBytes(true), bytes)) {
    throw new Error(`${label} is not a canonical non-identity subgroup point`);
  }
  return point;
}

function decodeG2(bytes: Uint8Array, label: string): G2Point {
  if (bytes.length !== 96) throw new Error(`${label} must be 96 bytes`);
  const point = bls.G2.Point.fromBytes(bytes);
  point.assertValidity();
  if (point.is0() || !point.isTorsionFree() || !ctEqual(point.toBytes(true), bytes)) {
    throw new Error(`${label} is not a canonical non-identity subgroup point`);
  }
  return point;
}

function assertScalar(value: bigint, label: string): void {
  if (value <= 0n || value >= ORDER) throw new Error(`${label} must be in [1,r-1]`);
}

function randomMuseScalar(): bigint {
  while (true) {
    const bytes = randomBytes(32);
    bytes[0] &= 0x7f;
    let candidate = 0n;
    for (const byte of bytes) candidate = (candidate << 8n) | BigInt(byte);
    if (candidate > 0n && candidate < ORDER) return candidate;
  }
}

function assertPrincipalId(id: string, role: string): void {
  if (!/^[a-z][a-z0-9-]{1,31}$/.test(id)) throw new Error(`${role} id is invalid`);
}

function authorizationKey(readerId: string, writerId: string): string {
  return `${readerId}\u0000${writerId}`;
}

function validateRequestedWriters(writerIds: readonly string[]): string[] {
  if (writerIds.length === 0) throw new Error('a query must name at least one writer index');
  if (new Set(writerIds).size !== writerIds.length) throw new Error('requested writer ids must be unique');
  return [...writerIds];
}

function cloneAuthorization(authorization: MuseAuthorization): MuseAuthorization {
  return { ...authorization, deltaBytes: authorization.deltaBytes.slice() };
}

function cloneIndex(index: MuseEncryptedIndex): MuseEncryptedIndex {
  return {
    writerId: index.writerId,
    rows: index.rows.map((row) => ({ ...row, gtBytes: row.gtBytes.slice() })),
  };
}
