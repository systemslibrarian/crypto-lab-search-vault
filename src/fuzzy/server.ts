/** Honest-but-curious keyed-listing server for Exhibit 9. */

export interface FuzzyIndexRow {
  readonly trapdoorHex: string;
  readonly value: Uint8Array;
}

/** Server boundary: deliberately contains no query word or gram strings. */
export interface FuzzyServerQuery {
  readonly trapdoorHexes: readonly string[];
}

export interface FuzzyServerResponse {
  readonly queryTrapdoorHexes: readonly string[];
  readonly matchedTrapdoorHexes: readonly string[];
  readonly lookups: number;
  readonly rows: readonly FuzzyIndexRow[];
  readonly responseBytes: number;
}

export interface FuzzyStorageCost {
  readonly associations: number;
  readonly trapdoorBytes: number;
  readonly payloadBytes: number;
  readonly totalBytes: number;
}

export class FuzzySearchServer {
  readonly #byTrapdoor = new Map<string, FuzzyIndexRow[]>();
  readonly #rows: FuzzyIndexRow[] = [];
  readonly #queryBundles: string[][] = [];
  readonly #documentRequests: string[][] = [];
  #queryCount = 0;

  constructor(rows: readonly FuzzyIndexRow[]) {
    if (rows.length === 0) throw new Error('Fuzzy index must not be empty');
    for (const supplied of rows) {
      assertRow(supplied);
      const row = cloneRow(supplied);
      this.#rows.push(row);
      const bucket = this.#byTrapdoor.get(row.trapdoorHex) ?? [];
      bucket.push(row);
      this.#byTrapdoor.set(row.trapdoorHex, bucket);
    }
  }

  search(query: FuzzyServerQuery): FuzzyServerResponse {
    if (query.trapdoorHexes.length === 0) {
      throw new Error('Fuzzy query must contain at least one trapdoor');
    }
    const unique = new Set<string>();
    for (const token of query.trapdoorHexes) {
      assertTrapdoor(token, 'query trapdoor');
      if (unique.has(token)) throw new Error('Fuzzy query repeats a trapdoor');
      unique.add(token);
    }

    this.#queryCount += 1;
    this.#queryBundles.push([...query.trapdoorHexes]);

    const rows: FuzzyIndexRow[] = [];
    const matchedTrapdoorHexes: string[] = [];
    for (const token of query.trapdoorHexes) {
      const bucket = this.#byTrapdoor.get(token);
      if (!bucket) continue;
      matchedTrapdoorHexes.push(token);
      rows.push(...bucket.map(cloneRow));
    }
    return {
      queryTrapdoorHexes: [...query.trapdoorHexes],
      matchedTrapdoorHexes,
      lookups: query.trapdoorHexes.length,
      rows,
      responseBytes: rows.reduce((bytes, row) => bytes + 32 + row.value.length, 0),
    };
  }

  storageCost(): FuzzyStorageCost {
    const trapdoorBytes = this.#rows.length * 32;
    const payloadBytes = this.#rows.reduce((bytes, row) => bytes + row.value.length, 0);
    return {
      associations: this.#rows.length,
      trapdoorBytes,
      payloadBytes,
      totalBytes: trapdoorBytes + payloadBytes,
    };
  }

  /** Model the final access request as an actual server-bound message. */
  recordDocumentRequest(documentIds: readonly string[]): string[] {
    const unique = new Set<string>();
    for (const documentId of documentIds) {
      if (!/^d[0-9]{2}$/.test(documentId)) {
        throw new Error('Fuzzy document request contains an invalid identifier');
      }
      if (unique.has(documentId)) {
        throw new Error('Fuzzy document request repeats an identifier');
      }
      unique.add(documentId);
    }
    const observed = [...documentIds];
    this.#documentRequests.push(observed);
    return [...observed];
  }

  documentRequests(): string[][] {
    return this.#documentRequests.map((request) => [...request]);
  }

  queryBundles(): string[][] {
    return this.#queryBundles.map((bundle) => [...bundle]);
  }

  snapshot(): FuzzyIndexRow[] {
    return this.#rows.map(cloneRow);
  }

  get queryCount(): number {
    return this.#queryCount;
  }
}

function assertRow(row: FuzzyIndexRow): void {
  assertTrapdoor(row.trapdoorHex, 'fuzzy index trapdoor');
  if (!(row.value instanceof Uint8Array) || row.value.length < 29) {
    throw new Error('Fuzzy index payload is too short for AES-GCM');
  }
}

function assertTrapdoor(token: string, label: string): void {
  if (!/^[0-9a-f]{64}$/.test(token)) throw new Error(`${label} must be lowercase 32-byte hex`);
}

function cloneRow(row: FuzzyIndexRow): FuzzyIndexRow {
  return { trapdoorHex: row.trapdoorHex, value: row.value.slice() };
}
