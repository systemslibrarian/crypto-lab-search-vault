/** Honest-but-curious server for the bounded OXT lesson. */
import { toHex } from '../core/bytes';
import {
  evaluateCrossToken,
  scalarFromBytes,
  tsetAddressFor,
  type OxtEncryptedIndex,
  type OxtEncryptedMatch,
  type OxtServerQuery,
  type OxtTSetRow,
} from './core';

export interface OxtMembershipRow {
  readonly position: number;
  readonly addressHex: string;
  readonly xtokenHex: string;
  readonly candidateTagHex: string;
  readonly matched: boolean;
}

export interface OxtSearchResponse {
  readonly seq: number;
  readonly sListSize: number;
  readonly membershipTests: number;
  readonly matches: readonly OxtEncryptedMatch[];
  readonly rows: readonly OxtMembershipRow[];
  readonly repeatedLookup: boolean;
  readonly repeatedCandidateTagHexes: readonly string[];
  readonly repeatedWithQueries: readonly number[];
}

export interface OxtObservation {
  readonly seq: number;
  readonly stagHex: string;
  readonly sListSize: number;
  readonly membershipTests: number;
  readonly candidateTagHexes: readonly string[];
  readonly matchedPositions: readonly number[];
  readonly resultSize: number;
  readonly fetchedDocumentIds: readonly string[];
}

export interface OxtServerSnapshot {
  readonly tsetRows: readonly {
    readonly addressHex: string;
    readonly encryptedIdHex: string;
    readonly yHex: string;
  }[];
  readonly xset: readonly string[];
}

export class OxtServer {
  readonly #tset = new Map<string, OxtTSetRow>();
  readonly #xsetSorted: string[];
  readonly #observations: Array<{
    seq: number;
    stagHex: string;
    sListSize: number;
    membershipTests: number;
    candidateTagHexes: string[];
    matchedPositions: number[];
    resultSize: number;
    fetchedDocumentIds: string[];
  }> = [];
  readonly #recordedFetches = new Set<number>();

  constructor(index: OxtEncryptedIndex) {
    if (index.tsetRows.length === 0) throw new Error('OXT TSet must not be empty');
    if (index.xset.length === 0) throw new Error('OXT XSet must not be empty');

    for (const row of index.tsetRows) {
      assertTSetRow(row);
      if (this.#tset.has(row.addressHex)) throw new Error('OXT TSet addresses must be unique');
      this.#tset.set(row.addressHex, cloneTSetRow(row));
    }

    if ([...index.xset].some((encoded, i, all) => i > 0 && encoded <= all[i - 1]!)) {
      throw new Error('OXT XSet must be strictly sorted and unique');
    }
    for (const encoded of index.xset) {
      if (!/^[0-9a-f]{64}$/.test(encoded)) throw new Error('OXT XSet entry is not canonical hex');
      try {
        // Reuse the strict point boundary while allowing neither malformed nor
        // identity cross-tags. Multiplication by 1 preserves the encoding.
        evaluateCrossToken(hexToBytes(encoded), 1n);
      } catch {
        throw new Error('OXT XSet entry is not a valid non-identity ristretto255 point');
      }
    }
    this.#xsetSorted = [...index.xset];
  }

  /**
   * Retrieve the flat TSet list exposed by stag, then evaluate every blinded
   * membership token against the exact XSet.
   */
  async search(query: OxtServerQuery): Promise<OxtSearchResponse> {
    if (!(query.stag instanceof Uint8Array) || query.stag.length !== 32) {
      throw new Error('OXT stag must be exactly 32 bytes');
    }

    const retrieved: Array<{ position: number; row: OxtTSetRow }> = [];
    for (let position = 1; position <= 0xffffffff; position++) {
      const addressHex = toHex(await tsetAddressFor(query.stag, position));
      const row = this.#tset.get(addressHex);
      if (!row) break;
      retrieved.push({ position, row });
    }
    if (query.xtokens.length !== retrieved.length) {
      throw new Error(
        `OXT query supplied ${query.xtokens.length} cross-tokens for ${retrieved.length} TSet rows`,
      );
    }

    const rows: OxtMembershipRow[] = [];
    const matches: OxtEncryptedMatch[] = [];
    for (let offset = 0; offset < retrieved.length; offset++) {
      const { position, row } = retrieved[offset]!;
      const xtoken = query.xtokens[offset]!;
      const candidateTagHex = toHex(evaluateCrossToken(xtoken, scalarFromBytes(row.y)));
      const matched = sortedIncludes(this.#xsetSorted, candidateTagHex);
      rows.push({
        position,
        addressHex: row.addressHex,
        xtokenHex: toHex(xtoken),
        candidateTagHex,
        matched,
      });
      if (matched) {
        matches.push({
          position,
          addressHex: row.addressHex,
          encryptedId: row.encryptedId.slice(),
        });
      }
    }

    const stagHex = toHex(query.stag);
    const previous = this.#observations;
    const repeatedLookup = previous.some((observation) => observation.stagHex === stagHex);
    const candidateTagHexes = rows.map((row) => row.candidateTagHex);
    const currentSet = new Set(candidateTagHexes);
    const repeatedCandidateTagHexes = [
      ...new Set(
        previous.flatMap((observation) =>
          observation.candidateTagHexes.filter((candidate) => currentSet.has(candidate)),
        ),
      ),
    ].sort();
    const repeatedWithQueries = previous
      .filter((observation) =>
        observation.candidateTagHexes.some((candidate) => currentSet.has(candidate)),
      )
      .map((observation) => observation.seq);

    const seq = previous.length;
    this.#observations.push({
      seq,
      stagHex,
      sListSize: retrieved.length,
      membershipTests: rows.length,
      candidateTagHexes,
      matchedPositions: rows.filter((row) => row.matched).map((row) => row.position),
      resultSize: matches.length,
      fetchedDocumentIds: [],
    });

    return {
      seq,
      sListSize: retrieved.length,
      membershipTests: rows.length,
      matches,
      rows,
      repeatedLookup,
      repeatedCandidateTagHexes,
      repeatedWithQueries,
    };
  }

  /** Record the client's final document-identifier access request. The bounded
   * lesson does not model a separate encrypted body store. */
  recordFetch(seq: number, documentIds: readonly string[]): void {
    const observation = this.#observations[seq];
    if (!observation) throw new Error('OXT observation does not exist');
    if (this.#recordedFetches.has(seq)) {
      throw new Error('OXT result fetch was already recorded');
    }
    if (documentIds.length !== observation.resultSize) {
      throw new Error('OXT fetched-document count does not match the result size');
    }
    if (new Set(documentIds).size !== documentIds.length) {
      throw new Error('OXT fetched-document ids must be distinct');
    }
    if (documentIds.some((id) => typeof id !== 'string' || id.length === 0)) {
      throw new Error('OXT fetched-document ids must be nonempty strings');
    }
    observation.fetchedDocumentIds = [...documentIds];
    this.#recordedFetches.add(seq);
  }

  observations(): OxtObservation[] {
    return this.#observations.map((observation) => ({
      ...observation,
      candidateTagHexes: [...observation.candidateTagHexes],
      matchedPositions: [...observation.matchedPositions],
      fetchedDocumentIds: [...observation.fetchedDocumentIds],
    }));
  }

  snapshot(): OxtServerSnapshot {
    return {
      tsetRows: [...this.#tset.values()]
        .map((row) => ({
          addressHex: row.addressHex,
          encryptedIdHex: toHex(row.encryptedId),
          yHex: toHex(row.y),
        })),
      xset: [...this.#xsetSorted],
    };
  }
}

function assertTSetRow(row: OxtTSetRow): void {
  if (!/^[0-9a-f]{64}$/.test(row.addressHex)) {
    throw new Error('OXT TSet address must be 32-byte canonical hex');
  }
  if (!(row.encryptedId instanceof Uint8Array) || row.encryptedId.length < 30) {
    throw new Error('OXT encrypted identifier is too short');
  }
  let y: bigint;
  try {
    y = scalarFromBytes(row.y);
  } catch {
    throw new Error('OXT TSet y is not a canonical 32-byte scalar encoding');
  }
  if (y === 0n) throw new Error('OXT TSet y must not be zero');
}

function cloneTSetRow(row: OxtTSetRow): OxtTSetRow {
  return {
    addressHex: row.addressHex,
    encryptedId: row.encryptedId.slice(),
    y: row.y.slice(),
  };
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function sortedIncludes(sorted: readonly string[], target: string): boolean {
  let low = 0;
  let high = sorted.length - 1;
  while (low <= high) {
    const middle = low + Math.floor((high - low) / 2);
    const value = sorted[middle]!;
    if (value === target) return true;
    if (value < target) low = middle + 1;
    else high = middle - 1;
  }
  return false;
}
