/** End-to-end exact-SSE versus gram-based fuzzy-search lesson. */
import { toHex } from '../core/bytes';
import { buildVault, generateKeys, openPostings, searchToken } from '../sse/client';
import { CORPUS } from '../sse/corpus';
import { SearchServer } from '../sse/server';
import type { Document, VaultKeys } from '../sse/types';
import {
  FUZZY_THRESHOLDS,
  assertFuzzyThreshold,
  inferObservedNeighborhood,
  normalizeFuzzyWord,
  type AnchorOverlap,
  type FuzzyThreshold,
} from './core';
import {
  buildFuzzyIndex,
  createFuzzyQuery,
  decryptAndFilterCandidates,
  generateFuzzyKeys,
  type DecryptedCandidate,
  type FuzzyKeys,
} from './client';
import { FuzzySearchServer, type FuzzyStorageCost } from './server';
import { oracleLevenshteinDistance } from './oracle';

export const KNOWN_QUERY_ANCHORS = ['audit', 'lawsuit', 'breach'] as const;

export interface ExactBaselineTrace {
  readonly tokenHex: string;
  readonly resultIds: readonly string[];
  readonly resultSize: number;
}

export interface ClassificationCount {
  readonly numerator: number;
  readonly denominator: number;
}

export interface ThresholdTrace {
  readonly threshold: FuzzyThreshold;
  readonly queryGrams: readonly string[];
  readonly queryTrapdoorHexes: readonly string[];
  readonly matchedTrapdoorHexes: readonly string[];
  readonly storage: FuzzyStorageCost;
  readonly queryTrapdoorBytes: number;
  readonly serverLookups: number;
  readonly responseRows: number;
  readonly responseBytes: number;
  readonly candidates: readonly DecryptedCandidate[];
  readonly groundTruthKeywords: readonly string[];
  readonly finalKeywords: readonly string[];
  readonly finalDocumentIds: readonly string[];
  readonly candidateTruePositives: number;
  readonly candidateFalsePositives: number;
  readonly candidateFalseNegatives: number;
  readonly candidateFalsePositiveRate: ClassificationCount;
  readonly candidateFalseNegativeRate: ClassificationCount;
  readonly finalFalsePositiveDocuments: number;
  readonly finalFalseNegativeDocuments: number;
  readonly finalFalsePositiveRate: ClassificationCount;
  readonly finalFalseNegativeRate: ClassificationCount;
}

export interface FuzzyInferenceTrace {
  readonly anchors: readonly AnchorOverlap[];
  readonly inferredAnchor: string | null;
  readonly ambiguous: boolean;
  readonly assumption: 'three-prior-query-labels-known-out-of-band';
}

export interface FuzzyLessonRun {
  readonly query: string;
  readonly selectedThreshold: FuzzyThreshold;
  readonly exact: ExactBaselineTrace;
  readonly thresholds: readonly ThresholdTrace[];
  readonly selected: ThresholdTrace;
  readonly inference: FuzzyInferenceTrace;
}

export class FuzzySearchLesson {
  readonly #corpus: readonly Document[];
  readonly #keywords: readonly string[];
  readonly #exactKeys: VaultKeys;
  readonly #exactServer: SearchServer;
  readonly #fuzzyKeys: FuzzyKeys;
  readonly #fuzzyServers: ReadonlyMap<FuzzyThreshold, FuzzySearchServer>;
  readonly #knownAnchors: ReadonlyMap<FuzzyThreshold, readonly {
    readonly label: string;
    readonly exactTokenHex: string;
    readonly fuzzyTokenHexes: readonly string[];
  }[]>;

  private constructor(args: {
    corpus: readonly Document[];
    exactKeys: VaultKeys;
    exactServer: SearchServer;
    fuzzyKeys: FuzzyKeys;
    fuzzyServers: ReadonlyMap<FuzzyThreshold, FuzzySearchServer>;
    knownAnchors: ReadonlyMap<FuzzyThreshold, readonly {
      readonly label: string;
      readonly exactTokenHex: string;
      readonly fuzzyTokenHexes: readonly string[];
    }[]>;
  }) {
    this.#corpus = args.corpus;
    this.#keywords = [...new Set(args.corpus.flatMap((document) => document.keywords))].sort();
    this.#exactKeys = args.exactKeys;
    this.#exactServer = args.exactServer;
    this.#fuzzyKeys = args.fuzzyKeys;
    this.#fuzzyServers = args.fuzzyServers;
    this.#knownAnchors = args.knownAnchors;
  }

  static async create(corpus: readonly Document[] = CORPUS): Promise<FuzzySearchLesson> {
    const isolatedCorpus = corpus.map((document) => ({
      ...document,
      keywords: [...document.keywords],
    }));
    const exactKeys = generateKeys();
    const fuzzyKeys = generateFuzzyKeys();
    const [{ vault }, fuzzyVaults] = await Promise.all([
      buildVault(exactKeys, isolatedCorpus),
      Promise.all(
        FUZZY_THRESHOLDS.map((threshold) =>
          buildFuzzyIndex(fuzzyKeys, isolatedCorpus, threshold),
        ),
      ),
    ]);
    const exactServer = new SearchServer(vault);
    const fuzzyServers = new Map(
      fuzzyVaults.map((fuzzyVault) => [
        fuzzyVault.threshold,
        new FuzzySearchServer(fuzzyVault.rows),
      ]),
    );

    // These are real prior server observations. The labels model outside
    // context learned later; no label or plaintext gram crosses either query
    // boundary.
    const exactAnchorTokens = new Map<string, string>();
    for (const label of KNOWN_QUERY_ANCHORS) {
      const token = await searchToken(exactKeys, label);
      const postings = await exactServer.search(token);
      const ids = await openPostings(exactKeys, label, postings);
      exactServer.fetchDocuments(token, ids);
      const retainedObservation = exactServer.observations().at(-1);
      if (!retainedObservation) throw new Error('Exact server did not retain an anchor query');
      exactAnchorTokens.set(label, retainedObservation.tokenHex);
    }
    const knownAnchors = new Map<FuzzyThreshold, {
      label: string;
      exactTokenHex: string;
      fuzzyTokenHexes: readonly string[];
    }[]>();
    for (const threshold of FUZZY_THRESHOLDS) {
      const server = fuzzyServers.get(threshold);
      if (!server) throw new Error(`No fuzzy server exists for threshold ${threshold}`);
      const observations = [];
      for (const label of KNOWN_QUERY_ANCHORS) {
        const query = await createFuzzyQuery(fuzzyKeys, label, threshold);
        server.search(query.serverQuery);
        const retainedBundle = server.queryBundles().at(-1);
        if (!retainedBundle) throw new Error('Fuzzy server did not retain an anchor query');
        observations.push({
          label,
          exactTokenHex: exactAnchorTokens.get(label)!,
          fuzzyTokenHexes: retainedBundle,
        });
      }
      knownAnchors.set(threshold, observations);
    }

    return new FuzzySearchLesson({
      corpus: isolatedCorpus,
      exactKeys,
      exactServer,
      fuzzyKeys,
      fuzzyServers,
      knownAnchors,
    });
  }

  /** Invalid input is completely resolved before either comparison server sees a byte. */
  async run(input: string, thresholdValue: number): Promise<FuzzyLessonRun> {
    const query = normalizeFuzzyWord(input);
    assertFuzzyThreshold(thresholdValue);

    const exactToken = await searchToken(this.#exactKeys, query);
    const exactPostings = await this.#exactServer.search(exactToken);
    const exactIds = await openPostings(this.#exactKeys, query, exactPostings);
    this.#exactServer.fetchDocuments(exactToken, exactIds);
    const exact: ExactBaselineTrace = {
      tokenHex: toHex(exactToken),
      resultIds: exactIds,
      resultSize: exactIds.length,
    };

    const thresholds: ThresholdTrace[] = [];
    for (const candidateThreshold of FUZZY_THRESHOLDS) {
      thresholds.push(await this.#runThreshold(query, candidateThreshold));
    }
    const selected = thresholds.find((trace) => trace.threshold === thresholdValue);
    if (!selected) throw new Error('Selected fuzzy threshold trace is missing');

    const anchors = this.#knownAnchors.get(thresholdValue);
    if (!anchors) throw new Error('Known-query anchor observations are missing');
    const inference = inferObservedNeighborhood(
      exact.tokenHex,
      selected.queryTrapdoorHexes,
      anchors,
    );

    return {
      query,
      selectedThreshold: thresholdValue,
      exact,
      thresholds,
      selected,
      inference: {
        anchors: inference.overlaps,
        inferredAnchor: inference.inferredAnchor,
        ambiguous: inference.ambiguous,
        assumption: 'three-prior-query-labels-known-out-of-band',
      },
    };
  }

  transcriptCounts(): {
    readonly exactQueries: number;
    readonly fuzzyQueries: Readonly<Record<FuzzyThreshold, number>>;
  } {
    return {
      exactQueries: this.#exactServer.observations().length,
      fuzzyQueries: {
        0: this.#server(0).queryCount,
        1: this.#server(1).queryCount,
        2: this.#server(2).queryCount,
      },
    };
  }

  async #runThreshold(query: string, threshold: FuzzyThreshold): Promise<ThresholdTrace> {
    const clientQuery = await createFuzzyQuery(this.#fuzzyKeys, query, threshold);
    const server = this.#server(threshold);
    const response = server.search(clientQuery.serverQuery);
    const candidates = await decryptAndFilterCandidates(
      this.#fuzzyKeys,
      query,
      threshold,
      response,
    );

    const candidateKeywords = new Set(candidates.map((candidate) => candidate.keyword));
    const groundTruthKeywords = this.#keywords.filter(
      (keyword) => oracleLevenshteinDistance(query, keyword) <= threshold,
    );
    const groundTruth = new Set(groundTruthKeywords);
    const finalKeywords = candidates
      .filter((candidate) => candidate.accepted)
      .map((candidate) => candidate.keyword)
      .sort();
    const expectedFinal = [...groundTruth].sort();
    if (JSON.stringify(finalKeywords) !== JSON.stringify(expectedFinal)) {
      throw new Error('Client-filtered fuzzy result disagrees with the plaintext edit-distance oracle');
    }

    const candidateTruePositives = [...candidateKeywords]
      .filter((keyword) => groundTruth.has(keyword)).length;
    const candidateFalsePositives = [...candidateKeywords]
      .filter((keyword) => !groundTruth.has(keyword)).length;
    const candidateFalseNegatives = [...groundTruth]
      .filter((keyword) => !candidateKeywords.has(keyword)).length;
    const finalDocumentIds = [
      ...new Set(
        candidates
          .filter((candidate) => candidate.accepted)
          .flatMap((candidate) => candidate.documentIds),
      ),
    ].sort();
    const expectedDocumentIds = this.#corpus
      .filter((document) => document.keywords.some((keyword) => groundTruth.has(keyword)))
      .map((document) => document.id)
      .sort();
    if (JSON.stringify(finalDocumentIds) !== JSON.stringify(expectedDocumentIds)) {
      throw new Error('Client-filtered document result disagrees with the corpus oracle');
    }
    const serverObservedDocumentIds = server.recordDocumentRequest(finalDocumentIds);
    const finalDocuments = new Set(serverObservedDocumentIds);
    const expectedDocuments = new Set(expectedDocumentIds);
    const finalFalsePositiveDocuments = [...finalDocuments]
      .filter((documentId) => !expectedDocuments.has(documentId)).length;
    const finalFalseNegativeDocuments = [...expectedDocuments]
      .filter((documentId) => !finalDocuments.has(documentId)).length;

    return {
      threshold,
      queryGrams: clientQuery.grams,
      queryTrapdoorHexes: response.queryTrapdoorHexes,
      matchedTrapdoorHexes: response.matchedTrapdoorHexes,
      storage: server.storageCost(),
      queryTrapdoorBytes: response.queryTrapdoorHexes.length * 32,
      serverLookups: response.lookups,
      responseRows: response.rows.length,
      responseBytes: response.responseBytes,
      candidates,
      groundTruthKeywords,
      finalKeywords,
      finalDocumentIds: serverObservedDocumentIds,
      candidateTruePositives,
      candidateFalsePositives,
      candidateFalseNegatives,
      candidateFalsePositiveRate: {
        numerator: candidateFalsePositives,
        denominator: this.#keywords.length - groundTruth.size,
      },
      candidateFalseNegativeRate: {
        numerator: candidateFalseNegatives,
        denominator: groundTruth.size,
      },
      finalFalsePositiveDocuments,
      finalFalseNegativeDocuments,
      finalFalsePositiveRate: {
        numerator: finalFalsePositiveDocuments,
        denominator: this.#corpus.length - expectedDocuments.size,
      },
      finalFalseNegativeRate: {
        numerator: finalFalseNegativeDocuments,
        denominator: expectedDocuments.size,
      },
    };
  }

  #server(threshold: FuzzyThreshold): FuzzySearchServer {
    const server = this.#fuzzyServers.get(threshold);
    if (!server) throw new Error(`No fuzzy server exists for threshold ${threshold}`);
    return server;
  }
}
