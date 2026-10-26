import { beforeAll, describe, expect, it } from 'vitest';
import { CORPUS, documentsFor } from '../sse/corpus';
import { FuzzySearchLesson } from './lesson';

let lesson: FuzzySearchLesson;

beforeAll(async () => {
  lesson = await FuzzySearchLesson.create();
});

describe('exact versus fuzzy execution', () => {
  it('recovers a one-edit neighbor that exact SSE misses', async () => {
    const run = await lesson.run('asudit', 1);
    expect(run.exact.resultIds).toEqual([]);
    expect(run.selected.groundTruthKeywords).toEqual(['audit']);
    expect(run.selected.finalKeywords).toEqual(['audit']);
    expect(run.selected.finalDocumentIds).toEqual(documentsFor('audit'));
    expect(run.selected.candidateTruePositives).toBe(1);
    expect(run.selected.candidateFalsePositives).toBe(0);
    expect(run.selected.candidateFalseNegatives).toBe(0);
    expect(run.selected.finalFalsePositiveDocuments).toBe(0);
    expect(run.selected.finalFalseNegativeDocuments).toBe(0);
  });

  it('reports a gram collision separately from the filtered final answer', async () => {
    const run = await lesson.run('asudit', 2);
    expect(run.selected.candidates.map((candidate) => candidate.keyword)).toEqual([
      'audit',
      'lawsuit',
    ]);
    expect(run.selected.candidates.find((candidate) => candidate.keyword === 'lawsuit')).toMatchObject({
      distance: 3,
      accepted: false,
    });
    expect(run.selected.finalKeywords).toEqual(['audit']);
    expect(run.selected.candidateFalsePositives).toBe(1);
    expect(run.selected.candidateFalsePositiveRate).toEqual({ numerator: 1, denominator: 13 });
    expect(run.selected.candidateFalseNegatives).toBe(0);
    expect(run.selected.finalFalsePositiveRate).toEqual({ numerator: 0, denominator: 18 });
    expect(run.selected.finalFalseNegativeRate).toEqual({ numerator: 0, denominator: 6 });
  });

  it('keeps threshold zero exact and returns no typo candidate', async () => {
    const run = await lesson.run('asudit', 0);
    expect(run.selected.queryGrams).toEqual(['asudit']);
    expect(run.selected.candidates).toEqual([]);
    expect(run.selected.finalDocumentIds).toEqual([]);
  });

  it('runs the existing exact SSE route rather than a scenario label', async () => {
    const run = await lesson.run('audit', 1);
    expect(run.exact.resultIds).toEqual(documentsFor('audit'));
    expect(run.exact.resultSize).toBe(documentsFor('audit').length);
    expect(run.selected.finalDocumentIds).toEqual(run.exact.resultIds);
  });
});

describe('threshold cost and accuracy ledger', () => {
  it('derives every alternative from its real index, query, and response', async () => {
    const run = await lesson.run('asudit', 1);
    expect(run.thresholds.map((trace) => trace.storage.associations)).toEqual([14, 109, 401]);
    expect(run.thresholds.map((trace) => trace.serverLookups)).toEqual([1, 7, 22]);
    expect(run.thresholds.map((trace) => trace.queryTrapdoorBytes)).toEqual([32, 224, 704]);
    for (const trace of run.thresholds) {
      expect(trace.queryTrapdoorBytes).toBe(trace.queryTrapdoorHexes.length * 32);
      expect(trace.serverLookups).toBe(trace.queryTrapdoorHexes.length);
      expect(trace.candidateFalseNegatives).toBe(0);
      expect(trace.candidateFalsePositiveRate.denominator)
        .toBe(14 - trace.groundTruthKeywords.length);
      expect(trace.candidateFalseNegativeRate.denominator)
        .toBe(trace.groundTruthKeywords.length);
      expect(trace.finalFalsePositiveDocuments).toBe(0);
      expect(trace.finalFalseNegativeDocuments).toBe(0);
    }
  });

  it('makes the selected threshold point to the corresponding computed row', async () => {
    for (const threshold of [0, 1, 2] as const) {
      const run = await lesson.run('asudit', threshold);
      expect(run.selected).toBe(run.thresholds[threshold]);
      expect(run.selected.threshold).toBe(threshold);
    }
  });
});

describe('declared known-query-anchor inference', () => {
  it('learns an audit-neighborhood relation unavailable from exact-token equality', async () => {
    const run = await lesson.run('asudit', 1);
    expect(run.inference.anchors.map((anchor) => anchor.exactTokenEqual)).toEqual([
      false,
      false,
      false,
    ]);
    expect(run.inference.anchors.map((anchor) => [
      anchor.label,
      anchor.fuzzyIntersection,
      anchor.fuzzyUnion,
    ])).toEqual([
      ['audit', 1, 12],
      ['lawsuit', 0, 15],
      ['breach', 0, 14],
    ]);
    expect(run.inference.inferredAnchor).toBe('audit');
    expect(run.inference.assumption).toBe('three-prior-query-labels-known-out-of-band');
  });

  it('makes no neighborhood inference at threshold zero', async () => {
    const run = await lesson.run('asudit', 0);
    expect(run.inference.inferredAnchor).toBeNull();
    expect(run.inference.ambiguous).toBe(false);
    expect(run.inference.anchors.every((anchor) => anchor.fuzzyIntersection === 0)).toBe(true);
  });
});

describe('failure and isolation boundaries', () => {
  it('rejects invalid input before either isolated server receives a query', async () => {
    const before = lesson.transcriptCounts();
    await expect(lesson.run('au*dit', 1)).rejects.toThrow(/ASCII letters/);
    await expect(lesson.run('audit', 3)).rejects.toThrow(/0, 1, or 2/);
    expect(lesson.transcriptCounts()).toEqual(before);
  });

  it('keeps three declared anchors and learner queries inside its isolated servers', async () => {
    const isolated = await FuzzySearchLesson.create(CORPUS);
    expect(isolated.transcriptCounts()).toEqual({
      exactQueries: 3,
      fuzzyQueries: { 0: 3, 1: 3, 2: 3 },
    });
    await isolated.run('asudit', 1);
    expect(isolated.transcriptCounts()).toEqual({
      exactQueries: 4,
      fuzzyQueries: { 0: 4, 1: 4, 2: 4 },
    });
  });
});
