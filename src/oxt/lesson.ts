/** End-to-end comparison harness for the bounded Boolean-search lesson. */
import { toHex } from '../core/bytes';
import { buildVault, generateKeys, openPostings, searchToken } from '../sse/client';
import { CORPUS, KEYWORDS, documentsFor } from '../sse/corpus';
import { SearchServer } from '../sse/server';
import type { Document, VaultKeys } from '../sse/types';
import {
  buildOxtIndex,
  createOxtQuery,
  crossTagFor,
  decryptOxtMatches,
  generateOxtKeys,
  type OxtClientQuery,
  type OxtEncryptedIndex,
  type OxtKeys,
} from './core';
import { OxtServer, type OxtMembershipRow, type OxtSearchResponse } from './server';

export type QueryErrorCode =
  | 'empty'
  | 'parentheses'
  | 'or'
  | 'not'
  | 'arity'
  | 'syntax'
  | 'unknown-keyword'
  | 'duplicate-keyword';

export class ConjunctiveQueryError extends Error {
  constructor(
    readonly code: QueryErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'ConjunctiveQueryError';
  }
}

export interface ParsedConjunctiveQuery {
  readonly left: string;
  readonly right: string;
  readonly canonical: string;
}

export interface NaiveTermTrace {
  readonly keyword: string;
  readonly tokenHex: string;
  readonly resultIds: readonly string[];
  readonly resultSize: number;
  readonly repeatedToken: boolean;
}

export interface NaiveConjunctionTrace {
  readonly queryVolume: 2;
  readonly terms: readonly [NaiveTermTrace, NaiveTermTrace];
  readonly finalResultIds: readonly string[];
}

export interface OxtConjunctionTrace {
  readonly queryVolume: 1;
  readonly sTerm: string;
  readonly xTerm: string;
  readonly stagHex: string;
  readonly sListSize: number;
  readonly membershipTests: number;
  readonly rows: readonly OxtMembershipRow[];
  readonly finalResultIds: readonly string[];
  readonly repeatedLookup: boolean;
  readonly repeatedCandidateTagHexes: readonly string[];
  readonly repeatedWithQueries: readonly number[];
  readonly xTermPostingListRetrieved: false;
}

export interface ConjunctiveComparison {
  readonly input: ParsedConjunctiveQuery;
  readonly naive: NaiveConjunctionTrace;
  readonly oxt: OxtConjunctionTrace;
}

export type ControlKind =
  | 'shared-x-overlapping-s'
  | 'shared-x-disjoint-s'
  | 'different-x-overlapping-s'
  | 'repeated-s-different-x'
  | 'identical-query';

export interface OxtControlPair {
  readonly kind: ControlKind;
  readonly firstQuery: string;
  readonly secondQuery: string;
  readonly firstSTerm: string;
  readonly secondSTerm: string;
  readonly firstXTerm: string;
  readonly secondXTerm: string;
  readonly sharedSTermDocumentIds: readonly string[];
  readonly repeatedCandidateTagHexes: readonly string[];
  readonly repeatedDocumentIdsForNarrator: readonly string[];
  readonly repeatedLookup: boolean;
}

export interface PathOramPaddingCase {
  readonly realResults: number;
  readonly dummyFetches: number;
  readonly logicalFetches: number;
  readonly blockTransfers: number;
}

export interface PathOramCost {
  readonly documentCount: number;
  readonly treeDepth: number;
  readonly leaves: number;
  readonly bucketSize: number;
  readonly bucketsPerPath: number;
  readonly readsPerFetch: number;
  readonly writesPerFetch: number;
  readonly transfersPerFetch: number;
  readonly maxPairIntersection: number;
  readonly maxPairs: readonly string[];
  readonly paddedTransfers: number;
  readonly paddingCases: readonly PathOramPaddingCase[];
}

export class ConjunctiveLesson {
  readonly #corpus: readonly Document[];
  readonly #naiveKeys: VaultKeys;
  readonly #naiveServer: SearchServer;
  readonly #oxtKeys: OxtKeys;
  readonly #oxtIndex: OxtEncryptedIndex;
  readonly #oxtServer: OxtServer;
  readonly oram: PathOramCost;

  private constructor(args: {
    corpus: readonly Document[];
    naiveKeys: VaultKeys;
    naiveServer: SearchServer;
    oxtKeys: OxtKeys;
    oxtIndex: OxtEncryptedIndex;
  }) {
    this.#corpus = args.corpus;
    this.#naiveKeys = args.naiveKeys;
    this.#naiveServer = args.naiveServer;
    this.#oxtKeys = args.oxtKeys;
    this.#oxtIndex = args.oxtIndex;
    this.#oxtServer = new OxtServer(args.oxtIndex);
    this.oram = derivePathOramCost(args.corpus, 4);
  }

  static async create(corpus: readonly Document[] = CORPUS): Promise<ConjunctiveLesson> {
    const isolatedCorpus = corpus.map((document) => ({
      ...document,
      keywords: [...document.keywords],
    }));
    const naiveKeys = generateKeys();
    const { vault } = await buildVault(naiveKeys, isolatedCorpus);
    const oxtKeys = generateOxtKeys();
    const oxtIndex = await buildOxtIndex(oxtKeys, isolatedCorpus);
    return new ConjunctiveLesson({
      corpus: isolatedCorpus,
      naiveKeys,
      naiveServer: new SearchServer(vault),
      oxtKeys,
      oxtIndex,
    });
  }

  /** Invalid grammar is rejected before either isolated server sees a byte. */
  async run(input: string): Promise<ConjunctiveComparison> {
    const parsed = parseConjunctiveQuery(input);
    const naive = await this.#runNaive(parsed);
    const oxt = await this.#runOxt(this.#oxtServer, parsed);
    if (!sameSet(naive.finalResultIds, oxt.finalResultIds)) {
      throw new Error('naive SSE and OXT returned different conjunction results');
    }
    return { input: parsed, naive, oxt };
  }

  transcriptCounts(): { naiveQueries: number; oxtQueries: number } {
    return {
      naiveQueries: this.#naiveServer.observations().length,
      oxtQueries: this.#oxtServer.observations().length,
    };
  }

  /** Three required leakage controls plus repeated-s and identical-query checks. */
  async runControlPairs(): Promise<OxtControlPair[]> {
    const cases: ReadonlyArray<
      readonly [ControlKind, first: string, second: string]
    > = [
      ['shared-x-overlapping-s', 'breach AND audit', 'subpoena AND audit'],
      ['shared-x-disjoint-s', 'patent AND audit', 'harassment AND audit'],
      ['different-x-overlapping-s', 'breach AND audit', 'subpoena AND lawsuit'],
      ['repeated-s-different-x', 'breach AND audit', 'breach AND lawsuit'],
      ['identical-query', 'breach AND audit', 'breach AND audit'],
    ];
    const out: OxtControlPair[] = [];
    for (const [kind, firstInput, secondInput] of cases) {
      const server = new OxtServer(this.#oxtIndex);
      const firstParsed = parseConjunctiveQuery(firstInput);
      const secondParsed = parseConjunctiveQuery(secondInput);
      const first = await this.#runOxt(server, firstParsed);
      const second = await this.#runOxt(server, secondParsed);
      const sharedSTermDocumentIds = intersection(
        documentsFor(first.sTerm, [...this.#corpus]),
        documentsFor(second.sTerm, [...this.#corpus]),
      );
      const repeatedDocumentIdsForNarrator: string[] = [];
      if (first.xTerm === second.xTerm) {
        for (const id of sharedSTermDocumentIds) {
          const encoded = toHex(await crossTagFor(this.#oxtKeys, first.xTerm, id));
          if (second.repeatedCandidateTagHexes.includes(encoded)) {
            repeatedDocumentIdsForNarrator.push(id);
          }
        }
      }
      out.push({
        kind,
        firstQuery: firstInput,
        secondQuery: secondInput,
        firstSTerm: first.sTerm,
        secondSTerm: second.sTerm,
        firstXTerm: first.xTerm,
        secondXTerm: second.xTerm,
        sharedSTermDocumentIds,
        repeatedCandidateTagHexes: second.repeatedCandidateTagHexes,
        repeatedDocumentIdsForNarrator,
        repeatedLookup: second.repeatedLookup,
      });
    }
    return out;
  }

  async #runNaive(parsed: ParsedConjunctiveQuery): Promise<NaiveConjunctionTrace> {
    const seenBefore = new Set(
      this.#naiveServer.observations().map((observation) => observation.tokenHex),
    );
    const traces: NaiveTermTrace[] = [];
    for (const keyword of [parsed.left, parsed.right]) {
      const token = await searchToken(this.#naiveKeys, keyword);
      const tokenHex = toHex(token);
      const postings = await this.#naiveServer.search(token);
      const ids = await openPostings(this.#naiveKeys, keyword, postings);
      this.#naiveServer.fetchDocuments(token, ids);
      traces.push({
        keyword,
        tokenHex,
        resultIds: [...ids],
        resultSize: ids.length,
        repeatedToken: seenBefore.has(tokenHex),
      });
      seenBefore.add(tokenHex);
    }
    if (traces[0]!.tokenHex === traces[1]!.tokenHex) {
      throw new Error('distinct naive SSE keywords produced the same token');
    }
    return {
      queryVolume: 2,
      terms: [traces[0]!, traces[1]!],
      finalResultIds: intersection(traces[0]!.resultIds, traces[1]!.resultIds),
    };
  }

  async #runOxt(
    server: OxtServer,
    parsed: ParsedConjunctiveQuery,
  ): Promise<OxtConjunctionTrace> {
    const query = await createOxtQuery(
      this.#oxtKeys,
      parsed.left,
      parsed.right,
      this.#corpus,
    );
    const response = await server.search(query.serverQuery);
    const ids = await decryptOxtMatches(this.#oxtKeys, query, response.matches, this.#corpus);
    server.recordFetch(response.seq, ids);
    return toOxtTrace(query, response, ids);
  }
}

export function parseConjunctiveQuery(input: string): ParsedConjunctiveQuery {
  const trimmed = input.trim();
  if (trimmed.length === 0) {
    throw new ConjunctiveQueryError('empty', 'Enter exactly “keyword AND keyword”.');
  }
  if (/[()]/.test(trimmed)) {
    throw new ConjunctiveQueryError(
      'parentheses',
      'Parentheses are not supported by this two-term lesson.',
    );
  }
  if (/\bOR\b/i.test(trimmed)) {
    throw new ConjunctiveQueryError('or', 'OR is not supported; use exactly one AND.');
  }
  if (/\bNOT\b/i.test(trimmed)) {
    throw new ConjunctiveQueryError('not', 'NOT is not supported; use exactly one AND.');
  }
  const tokens = trimmed.split(/\s+/);
  const andCount = tokens.filter((token) => token.toUpperCase() === 'AND').length;
  if (tokens.length > 3 || andCount > 1) {
    throw new ConjunctiveQueryError(
      'arity',
      'This bounded lesson accepts exactly two terms, not three or more.',
    );
  }
  if (tokens.length !== 3 || tokens[1]!.toUpperCase() !== 'AND') {
    throw new ConjunctiveQueryError('syntax', 'Use exactly “keyword AND keyword”.');
  }
  const left = tokens[0]!.toLowerCase();
  const right = tokens[2]!.toLowerCase();
  const vocabulary = KEYWORDS as readonly string[];
  if (!vocabulary.includes(left) || !vocabulary.includes(right)) {
    const unknown = [left, right].filter((term) => !vocabulary.includes(term));
    throw new ConjunctiveQueryError(
      'unknown-keyword',
      `Not in this fixed index: ${unknown.join(', ')}.`,
    );
  }
  if (left === right) {
    throw new ConjunctiveQueryError(
      'duplicate-keyword',
      'The two normalized keywords must be distinct.',
    );
  }
  return { left, right, canonical: `${left} AND ${right}` };
}

export function derivePathOramCost(
  corpus: readonly Document[] = CORPUS,
  bucketSize = 4,
): PathOramCost {
  if (corpus.length < 1) throw new Error('Path ORAM illustration needs at least one document');
  if (!Number.isSafeInteger(bucketSize) || bucketSize < 1) {
    throw new Error('Path ORAM bucket size must be a positive safe integer');
  }
  const ids = corpus.map((document) => document.id);
  if (new Set(ids).size !== ids.length) throw new Error('Path ORAM document ids must be unique');
  const treeDepth = Math.ceil(Math.log2(corpus.length));
  const leaves = 2 ** treeDepth;
  const bucketsPerPath = treeDepth + 1;
  const readsPerFetch = bucketSize * bucketsPerPath;
  const writesPerFetch = readsPerFetch;
  const transfersPerFetch = readsPerFetch + writesPerFetch;

  let maxPairIntersection = -1;
  const maxPairs: string[] = [];
  for (let i = 0; i < KEYWORDS.length; i++) {
    for (let j = i + 1; j < KEYWORDS.length; j++) {
      const left = KEYWORDS[i]!;
      const right = KEYWORDS[j]!;
      const count = intersection(
        documentsFor(left, [...corpus]),
        documentsFor(right, [...corpus]),
      ).length;
      if (count > maxPairIntersection) {
        maxPairIntersection = count;
        maxPairs.length = 0;
        maxPairs.push(`${left} AND ${right}`);
      } else if (count === maxPairIntersection) {
        maxPairs.push(`${left} AND ${right}`);
      }
    }
  }
  if (maxPairIntersection < 0) throw new Error('Path ORAM illustration needs two keywords');
  const paddingCases = Array.from({ length: maxPairIntersection + 1 }, (_, realResults) => ({
    realResults,
    dummyFetches: maxPairIntersection - realResults,
    logicalFetches: maxPairIntersection,
    blockTransfers: maxPairIntersection * transfersPerFetch,
  }));
  return {
    documentCount: corpus.length,
    treeDepth,
    leaves,
    bucketSize,
    bucketsPerPath,
    readsPerFetch,
    writesPerFetch,
    transfersPerFetch,
    maxPairIntersection,
    maxPairs,
    paddedTransfers: maxPairIntersection * transfersPerFetch,
    paddingCases,
  };
}

function toOxtTrace(
  query: OxtClientQuery,
  response: OxtSearchResponse,
  ids: readonly string[],
): OxtConjunctionTrace {
  return {
    queryVolume: 1,
    sTerm: query.sTerm,
    xTerm: query.xTerm,
    stagHex: toHex(query.serverQuery.stag),
    sListSize: response.sListSize,
    membershipTests: response.membershipTests,
    rows: response.rows,
    finalResultIds: [...ids],
    repeatedLookup: response.repeatedLookup,
    repeatedCandidateTagHexes: [...response.repeatedCandidateTagHexes],
    repeatedWithQueries: [...response.repeatedWithQueries],
    xTermPostingListRetrieved: false,
  };
}

function intersection(left: readonly string[], right: readonly string[]): string[] {
  const rightSet = new Set(right);
  // Both posting lists are already in corpus order; retain that client-visible
  // order rather than accidentally substituting lexical identifier order.
  return [...new Set(left.filter((value) => rightSet.has(value)))];
}

function sameSet(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}
