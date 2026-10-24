/** Server-side PEKS store. No record contains a keyword, scalar, or body. */
import { toHex } from '../core/bytes';
import { cloneTag, testTag, type PeksTag, type PeksTrapdoor } from './core';

export interface PeksStoredRecord {
  readonly opaqueRecordId: string;
  readonly tag: PeksTag;
}

export interface PeksTestRow {
  readonly opaqueRecordId: string;
  readonly matched: boolean;
}

export interface PeksSearchResult {
  readonly tests: number;
  readonly matchedRecordIds: readonly string[];
  readonly rows: readonly PeksTestRow[];
}

export interface PeksObservation {
  readonly seq: number;
  readonly trapdoorHex: string;
  readonly tests: number;
  readonly resultSize: number;
  readonly matchedRecordIds: readonly string[];
}

export class PeksServer {
  readonly #records: PeksStoredRecord[];
  readonly #observations: PeksObservation[] = [];

  constructor(records: readonly PeksStoredRecord[]) {
    if (records.length === 0) throw new Error('PEKS server requires at least one tag');
    const ids = records.map((record) => record.opaqueRecordId);
    if (ids.some((id) => id.length === 0)) throw new Error('opaque record ids must not be empty');
    if (new Set(ids).size !== ids.length) throw new Error('opaque record ids must be unique');
    this.#records = records.map((record) => ({
      opaqueRecordId: record.opaqueRecordId,
      tag: cloneTag(record.tag),
    }));
  }

  /** Public PEKS Test; useful to the legitimate server and to a guesser. */
  async test(tag: PeksTag, trapdoor: PeksTrapdoor): Promise<boolean> {
    return testTag(tag, trapdoor);
  }

  /** Basic BDOP PEKS scans every stored tag for each trapdoor. */
  async search(trapdoor: PeksTrapdoor): Promise<PeksSearchResult> {
    const rows: PeksTestRow[] = [];
    for (const record of this.#records) {
      rows.push({
        opaqueRecordId: record.opaqueRecordId,
        matched: await this.test(record.tag, trapdoor),
      });
    }
    const matchedRecordIds = rows.filter((row) => row.matched).map((row) => row.opaqueRecordId);
    this.#observations.push({
      seq: this.#observations.length,
      trapdoorHex: toHex(trapdoor.bytes),
      tests: rows.length,
      resultSize: matchedRecordIds.length,
      matchedRecordIds: [...matchedRecordIds],
    });
    return { tests: rows.length, matchedRecordIds, rows };
  }

  records(): PeksStoredRecord[] {
    return this.#records.map((record) => ({
      opaqueRecordId: record.opaqueRecordId,
      tag: cloneTag(record.tag),
    }));
  }

  observations(): PeksObservation[] {
    return this.#observations.map((observation) => ({
      ...observation,
      matchedRecordIds: [...observation.matchedRecordIds],
    }));
  }
}
