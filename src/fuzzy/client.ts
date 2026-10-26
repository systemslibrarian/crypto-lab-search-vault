/** Client-side setup, query generation, and candidate filtering for Exhibit 9. */
import { open, seal } from '../core/aead';
import { fromHex, fromUtf8, randomBytes, toHex, utf8 } from '../core/bytes';
import { prf } from '../core/prf';
import type { Document } from '../sse/types';
import {
  deletionGramSet,
  levenshteinDistance,
  normalizeFuzzyWord,
  type FuzzyThreshold,
} from './core';
import type { FuzzyIndexRow, FuzzyServerQuery, FuzzyServerResponse } from './server';

export const FUZZY_DOMAIN = {
  GRAM_TRAPDOOR: 'crypto-lab/search-vault/fuzzy/v1/gram-trapdoor',
} as const;

export interface FuzzyKeys {
  readonly kTrapdoor: Uint8Array;
  readonly kPayload: Uint8Array;
}

export interface FuzzyIndexVault {
  readonly threshold: FuzzyThreshold;
  readonly rows: readonly FuzzyIndexRow[];
}

export interface FuzzyClientQuery {
  /** Client-only normalized text. Never part of FuzzyServerQuery. */
  readonly normalizedWord: string;
  /** Client/narrator-only grams. The server sees their PRF values only. */
  readonly grams: readonly string[];
  readonly serverQuery: FuzzyServerQuery;
}

export interface DecryptedCandidate {
  readonly keyword: string;
  readonly documentIds: readonly string[];
  readonly matchingRows: number;
  readonly distance: number;
  readonly accepted: boolean;
}

interface CandidatePayload {
  readonly keyword: string;
  readonly documentIds: readonly string[];
}

export function generateFuzzyKeys(): FuzzyKeys {
  return { kTrapdoor: randomBytes(32), kPayload: randomBytes(32) };
}

export async function gramTrapdoor(keys: FuzzyKeys, gram: string): Promise<Uint8Array> {
  assertFuzzyKeys(keys);
  if (!/^[a-z]+$/.test(gram)) throw new Error('A gram must contain ASCII letters only.');
  return prf(keys.kTrapdoor, FUZZY_DOMAIN.GRAM_TRAPDOOR, utf8(gram));
}

/** Build the paper's gram-set listing shape with modern primitives.
 * Each association gets an independently randomized, trapdoor-bound payload. */
export async function buildFuzzyIndex(
  keys: FuzzyKeys,
  corpus: readonly Document[],
  threshold: FuzzyThreshold,
): Promise<FuzzyIndexVault> {
  assertFuzzyKeys(keys);
  assertCorpus(corpus);
  const keywords = [...new Set(corpus.flatMap((document) => document.keywords))].sort();

  const perKeyword = await Promise.all(
    keywords.map(async (keyword): Promise<FuzzyIndexRow[]> => {
      const normalized = normalizeFuzzyWord(keyword);
      if (normalized !== keyword) throw new Error('Indexed keywords must already be normalized.');
      const documentIds = corpus
        .filter((document) => document.keywords.includes(keyword))
        .map((document) => document.id);
      const plaintext = utf8(JSON.stringify({ keyword, documentIds } satisfies CandidatePayload));
      return Promise.all(
        deletionGramSet(keyword, threshold).map(async (gram): Promise<FuzzyIndexRow> => {
          const trapdoor = await gramTrapdoor(keys, gram);
          return {
            trapdoorHex: toHex(trapdoor),
            value: await seal(keys.kPayload, plaintext, trapdoor),
          };
        }),
      );
    }),
  );

  const rows = shuffleWithCsprng(perKeyword.flat());
  if (new Set(rows.map((row) => toHex(row.value))).size !== rows.length) {
    throw new Error('Fuzzy index ciphertext collision');
  }
  return { threshold, rows };
}

export async function createFuzzyQuery(
  keys: FuzzyKeys,
  input: string,
  threshold: FuzzyThreshold,
): Promise<FuzzyClientQuery> {
  const normalizedWord = normalizeFuzzyWord(input);
  const grams = deletionGramSet(normalizedWord, threshold);
  const trapdoorHexes = await Promise.all(
    grams.map(async (gram) => toHex(await gramTrapdoor(keys, gram))),
  );
  return {
    normalizedWord,
    grams,
    serverQuery: { trapdoorHexes },
  };
}

/** Decrypt, deduplicate, and apply the real edit-distance predicate. */
export async function decryptAndFilterCandidates(
  keys: FuzzyKeys,
  queryWord: string,
  threshold: FuzzyThreshold,
  response: FuzzyServerResponse,
): Promise<DecryptedCandidate[]> {
  assertFuzzyKeys(keys);
  const normalizedQuery = normalizeFuzzyWord(queryWord);
  const byKeyword = new Map<
    string,
    { documentIds: string[]; matchingRows: number }
  >();

  for (const row of response.rows) {
    const trapdoor = fromHex(row.trapdoorHex);
    const plaintext = await open(keys.kPayload, row.value, trapdoor);
    const payload = parseCandidatePayload(fromUtf8(plaintext));
    const existing = byKeyword.get(payload.keyword);
    if (existing) {
      if (JSON.stringify(existing.documentIds) !== JSON.stringify(payload.documentIds)) {
        throw new Error('Conflicting fuzzy payloads for one keyword');
      }
      existing.matchingRows += 1;
    } else {
      byKeyword.set(payload.keyword, {
        documentIds: [...payload.documentIds],
        matchingRows: 1,
      });
    }
  }

  return [...byKeyword.entries()]
    .map(([keyword, candidate]): DecryptedCandidate => {
      const distance = levenshteinDistance(normalizedQuery, keyword);
      return {
        keyword,
        documentIds: candidate.documentIds,
        matchingRows: candidate.matchingRows,
        distance,
        accepted: distance <= threshold,
      };
    })
    .sort((left, right) => left.distance - right.distance || left.keyword.localeCompare(right.keyword));
}

function parseCandidatePayload(serialized: string): CandidatePayload {
  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized);
  } catch {
    throw new Error('Fuzzy candidate payload is not valid JSON');
  }
  if (!isRecord(parsed) || typeof parsed.keyword !== 'string') {
    throw new Error('Fuzzy candidate payload has no keyword');
  }
  const keyword = normalizeFuzzyWord(parsed.keyword);
  if (keyword !== parsed.keyword) throw new Error('Fuzzy payload keyword is not canonical');
  if (!Array.isArray(parsed.documentIds) || parsed.documentIds.length === 0) {
    throw new Error('Fuzzy candidate payload has no document identifiers');
  }
  const documentIds = parsed.documentIds.map((id) => {
    if (typeof id !== 'string' || !/^d[0-9]{2}$/.test(id)) {
      throw new Error('Fuzzy candidate payload has an invalid document identifier');
    }
    return id;
  });
  if (new Set(documentIds).size !== documentIds.length) {
    throw new Error('Fuzzy candidate payload repeats a document identifier');
  }
  return { keyword, documentIds };
}

function assertFuzzyKeys(keys: FuzzyKeys): void {
  for (const [label, key] of Object.entries(keys)) {
    if (!(key instanceof Uint8Array) || key.length !== 32) {
      throw new Error(`${label} must be a 32-byte key`);
    }
  }
}

function assertCorpus(corpus: readonly Document[]): void {
  if (corpus.length === 0) throw new Error('Fuzzy index corpus must not be empty');
  const ids = new Set<string>();
  for (const document of corpus) {
    if (!/^d[0-9]{2}$/.test(document.id) || ids.has(document.id)) {
      throw new Error('Fuzzy index document identifiers must be unique dNN values');
    }
    ids.add(document.id);
    if (document.keywords.length === 0) throw new Error('Every fuzzy-indexed document needs a keyword');
  }
}

function shuffleWithCsprng<T>(input: readonly T[]): T[] {
  const output = [...input];
  for (let index = output.length - 1; index > 0; index--) {
    const upperBound = index + 1;
    const range = 0x100000000;
    const limit = Math.floor(range / upperBound) * upperBound;
    let draw: number;
    do {
      draw = crypto.getRandomValues(new Uint32Array(1))[0]!;
    } while (draw >= limit);
    const chosen = draw % upperBound;
    [output[index], output[chosen]] = [output[chosen]!, output[index]!];
  }
  return output;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
