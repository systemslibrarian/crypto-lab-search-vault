import { describe, expect, it } from 'vitest';
import { auxiliaryCorpus, auxiliaryStatistics, matrixDistance } from './auxiliary';
import { KEYWORDS } from './corpus';

describe('independent auxiliary corpora', () => {
  for (const mode of ['independent', 'small', 'shifted'] as const) {
    it(`${mode} derives consistent counts and joint overlaps from actual documents`, () => {
      const corpus = auxiliaryCorpus(mode);
      const stats = auxiliaryStatistics(KEYWORDS, corpus);
      expect(corpus).toEqual(auxiliaryCorpus(mode));
      expect(corpus).not.toEqual(auxiliaryCorpus(mode, 17));
      expect(stats.sampleSize).toBe(mode === 'small' ? 12 : 64);
      for (let i = 0; i < KEYWORDS.length; i++) {
        expect(stats.matrix[i]![i]).toBe(stats.counts[i]! / stats.sampleSize);
        for (let j = 0; j < KEYWORDS.length; j++) {
          expect(stats.matrix[i]![j]).toBe(stats.matrix[j]![i]);
          expect(stats.matrix[i]![j]).toBeLessThanOrEqual(Math.min(stats.counts[i]!, stats.counts[j]!) / stats.sampleSize);
        }
      }
    });
  }
  it('measures matrix distance without receiving token ground truth', () => {
    expect(matrixDistance([[0, 1], [1, 0]], [[0, 0], [0, 0]])).toBeCloseTo(Math.sqrt(0.5));
    expect(() => matrixDistance([[1]], [[1, 0]])).toThrow();
    expect(() => auxiliaryStatistics(KEYWORDS, [])).toThrow();
  });
});
