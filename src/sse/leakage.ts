/**
 * The leakage profile, computed from the server's ledger alone.
 *
 * Nothing in this file may touch the keys, the corpus keywords, or the
 * plaintext — it takes only what server.ts genuinely observed. That constraint
 * is the honesty of the whole exhibit: if a chart can be drawn from here, a
 * real server could draw it too.
 */
import type { QueryObservation } from './types';
import type { Document } from './types';

/** One distinct token the server has seen, with everything it knows about it. */
export interface TokenProfile {
  tokenHex: string;
  /** search-pattern leakage: how often this exact token came back */
  queryCount: number;
  /** volume leakage: how many documents it matches */
  resultSize: number;
  resultIds: string[];
  firstSeenSeq: number;
}

export function tokenProfiles(observations: QueryObservation[]): TokenProfile[] {
  const byToken = new Map<string, TokenProfile>();
  for (const o of observations) {
    const existing = byToken.get(o.tokenHex);
    if (existing) {
      existing.queryCount += 1;
      continue;
    }
    byToken.set(o.tokenHex, {
      tokenHex: o.tokenHex,
      queryCount: 1,
      resultSize: o.resultSize,
      resultIds: o.resultIds.slice(),
      firstSeenSeq: o.seq,
    });
  }
  return [...byToken.values()].sort((a, b) => a.firstSeenSeq - b.firstSeenSeq);
}

/**
 * Observed co-occurrence: M[i][j] = |R_i ∩ R_j| / N, the fraction of the
 * database that answers both token i and token j. This matrix is the whole
 * input to the Islam–Kuzu–Kantarcioglu attack, and the server assembles it
 * from returned document identifiers — no keyword knowledge required.
 */
export function observedCooccurrence(profiles: TokenProfile[], totalDocs: number): number[][] {
  const sets = profiles.map((p) => new Set(p.resultIds));
  return sets.map((a) => sets.map((b) => intersectionSize(a, b) / totalDocs));
}

/**
 * The adversary's background knowledge: the same statistic computed over a
 * corpus it already knows (a public mirror, an earlier leak, a similar
 * organisation). IKK's assumption — and the reason the attack is realistic —
 * is that this is obtainable without breaking any cryptography.
 */
export function knownCooccurrence(
  keywords: readonly string[],
  corpus: Document[],
): number[][] {
  const sets = keywords.map((w) => new Set(corpus.filter((d) => d.keywords.includes(w)).map((d) => d.id)));
  const n = corpus.length;
  return sets.map((a) => sets.map((b) => intersectionSize(a, b) / n));
}

export function knownCounts(keywords: readonly string[], corpus: Document[]): number[] {
  return keywords.map((w) => corpus.filter((d) => d.keywords.includes(w)).length);
}

/**
 * Document-level co-occurrence: how often a pair of documents was returned by
 * the same query. Even with every keyword hidden, this clusters the database
 * into topics — the shape a server sees emerge after a few dozen queries.
 */
export function documentCooccurrence(
  observations: QueryObservation[],
  docIds: string[],
): number[][] {
  const idx = new Map(docIds.map((id, i) => [id, i]));
  const m = docIds.map(() => docIds.map(() => 0));
  for (const o of observations) {
    for (const a of o.resultIds) {
      const i = idx.get(a);
      if (i === undefined) continue;
      for (const b of o.resultIds) {
        const j = idx.get(b);
        if (j === undefined) continue;
        m[i]![j]! += 1;
      }
    }
  }
  return m;
}

/** How many documents the server has seen returned at least once — the share
 *  of the database whose membership in *some* result set is now public. */
export function touchedDocuments(observations: QueryObservation[]): Set<string> {
  const seen = new Set<string>();
  for (const o of observations) for (const id of o.resultIds) seen.add(id);
  return seen;
}

function intersectionSize(a: Set<string>, b: Set<string>): number {
  let n = 0;
  for (const x of a) if (b.has(x)) n++;
  return n;
}

/** Deterministic short label for a token, so the UI can name it without ever
 *  implying the server knows more than 32 opaque bytes. */
export function tokenLabel(tokenHex: string): string {
  return `t·${tokenHex.slice(0, 6)}`;
}
