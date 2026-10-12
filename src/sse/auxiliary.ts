/** Independent synthetic corpora; no target documents, token truth or keys. */
import { xorshift32 } from './attack';
import { knownCooccurrence, knownCounts } from './leakage';
import type { Document } from './types';

export type AuxiliaryMode = 'independent' | 'small' | 'shifted';
// Public teaching model, declared independently of the handwritten target.
const CLUSTERS = [
  ['salary', 'bonus', 'layoff'], ['lawsuit', 'subpoena', 'harassment'],
  ['merger', 'acquisition', 'contract'], ['audit', 'breach', 'invoice'],
  ['patent', 'research'],
];
export function auxiliaryCorpus(mode: AuxiliaryMode, seed = 0xa17): Document[] {
  const rng = xorshift32(seed);
  const size = mode === 'small' ? 12 : 64;
  return Array.from({ length: size }, (_, i) => {
    // Shifted mode favors payroll and independently drops half its keywords.
    const cluster = mode === 'shifted' && rng() < 0.65 ? CLUSTERS[0]! : CLUSTERS[Math.floor(rng() * CLUSTERS.length)]!;
    let keywords = cluster.filter(() => rng() < (mode === 'shifted' ? 0.45 : 0.75));
    if (keywords.length === 0) keywords = [cluster[Math.floor(rng() * cluster.length)]!];
    return { id: `aux-${seed}-${i}`, title: 'Independent modeled document', body: '', keywords };
  });
}
export function auxiliaryStatistics(keywords: readonly string[], corpus: Document[]) {
  if (corpus.length === 0) throw new Error('Auxiliary corpus must not be empty');
  return { sampleSize: corpus.length, counts: knownCounts(keywords, corpus), matrix: knownCooccurrence(keywords, corpus) };
}
/** Root mean squared difference over all aligned keyword-matrix cells. Evaluation only. */
export function matrixDistance(a: number[][], b: number[][]): number {
  if (a.length !== b.length || a.some((row, i) => row.length !== b[i]?.length)) throw new Error('Matrix shapes differ');
  const cells = a.reduce((n, row) => n + row.length, 0);
  if (!cells) return 0;
  return Math.sqrt(a.reduce((sum, row, i) => sum + row.reduce((s, v, j) => s + (v - b[i]![j]!) ** 2, 0), 0) / cells);
}
