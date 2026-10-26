import { describe, expect, it } from 'vitest';
import {
  deletionGramSet,
  inferObservedNeighborhood,
  levenshteinDistance,
  normalizeFuzzyWord,
} from './core';
import { oracleLevenshteinDistance } from './oracle';

describe('Li et al. deletion-gram construction', () => {
  it('reproduces the paper’s CASTLE threshold-1 gram example', () => {
    expect(deletionGramSet('CASTLE', 1)).toEqual(
      ['astle', 'castle', 'caste', 'castl', 'casle', 'catle', 'cstle'].sort(),
    );
  });

  it('includes all 0-, 1-, and 2-deletion grams once', () => {
    expect(deletionGramSet('asudit', 0)).toHaveLength(1);
    expect(deletionGramSet('asudit', 1)).toHaveLength(7);
    expect(deletionGramSet('asudit', 2)).toHaveLength(22);
    expect(deletionGramSet('letter', 2)).toEqual([
      ...new Set(deletionGramSet('letter', 2)),
    ].sort());
  });

  it('normalizes only case and outer whitespace, and rejects unsupported text', () => {
    expect(normalizeFuzzyWord('  AsUdIt ')).toBe('asudit');
    expect(() => normalizeFuzzyWord('au*dit')).toThrow(/ASCII letters/);
    expect(() => normalizeFuzzyWord('')).toThrow(/Enter a word/);
    expect(() => normalizeFuzzyWord('ab')).toThrow(/3 through 12/);
    expect(() => normalizeFuzzyWord('abcdefghijklmnop')).toThrow(/3 through 12/);
  });
});

describe('independent edit-distance oracle', () => {
  it('uses insertion, deletion, and substitution with no transposition shortcut', () => {
    expect(levenshteinDistance('kitten', 'sitting')).toBe(3);
    expect(levenshteinDistance('asudit', 'audit')).toBe(1);
    expect(levenshteinDistance('aduit', 'audit')).toBe(2);
    expect(levenshteinDistance('asudit', 'lawsuit')).toBe(3);
  });

  it('agrees with an independent full-matrix oracle over a bounded exhaustive space', () => {
    const words = enumerateWords('abc', 3, 4);
    for (const left of words) {
      for (const right of words) {
        expect(levenshteinDistance(left, right), `${left}/${right}`)
          .toBe(oracleLevenshteinDistance(left, right));
      }
    }
  });

  it('observes the gram construction’s completeness over a bounded exhaustive space', () => {
    const words = enumerateWords('abc', 3, 4);
    for (const left of words) {
      for (const right of words) {
        for (const threshold of [0, 1, 2] as const) {
          if (oracleLevenshteinDistance(left, right) > threshold) continue;
          const leftGrams = new Set(deletionGramSet(left, threshold));
          expect(
            deletionGramSet(right, threshold).some((gram) => leftGrams.has(gram)),
            `${left}/${right} at d=${threshold}`,
          ).toBe(true);
        }
      }
    }
  });
});

describe('server-visible query-bundle overlap', () => {
  const token = (value: number): string => value.toString(16).padStart(64, '0');

  it('infers one uniquely overlapping known anchor when exact tokens are unrelated', () => {
    const result = inferObservedNeighborhood(
      token(90),
      [token(1), token(2), token(3)],
      [
        { label: 'audit', exactTokenHex: token(91), fuzzyTokenHexes: [token(2), token(4)] },
        { label: 'lawsuit', exactTokenHex: token(92), fuzzyTokenHexes: [token(5)] },
        { label: 'breach', exactTokenHex: token(93), fuzzyTokenHexes: [token(6)] },
      ],
    );
    expect(result.inferredAnchor).toBe('audit');
    expect(result.ambiguous).toBe(false);
    expect(result.overlaps.map((row) => row.exactTokenEqual)).toEqual([false, false, false]);
    expect(result.overlaps.map((row) => row.fuzzyIntersection)).toEqual([1, 0, 0]);
  });

  it('reports ties and zero-overlap cases rather than inventing a label', () => {
    const tied = inferObservedNeighborhood(token(1), [token(2)], [
      { label: 'a', exactTokenHex: token(3), fuzzyTokenHexes: [token(2)] },
      { label: 'b', exactTokenHex: token(4), fuzzyTokenHexes: [token(2)] },
    ]);
    expect(tied.inferredAnchor).toBeNull();
    expect(tied.ambiguous).toBe(true);

    const none = inferObservedNeighborhood(token(1), [token(2)], [
      { label: 'a', exactTokenHex: token(3), fuzzyTokenHexes: [token(4)] },
    ]);
    expect(none.inferredAnchor).toBeNull();
    expect(none.ambiguous).toBe(false);
  });

  it('rejects malformed or repeated observed tokens', () => {
    expect(() => inferObservedNeighborhood('00', [token(1)], [])).toThrow(/32-byte/);
    expect(() =>
      inferObservedNeighborhood(token(1), [token(2), token(2)], []),
    ).toThrow(/must not repeat/);
  });
});

function enumerateWords(alphabet: string, minLength: number, maxLength: number): string[] {
  const output: string[] = [];
  const visit = (prefix: string, remaining: number): void => {
    if (remaining === 0) {
      output.push(prefix);
      return;
    }
    for (const character of alphabet) visit(prefix + character, remaining - 1);
  };
  for (let length = minLength; length <= maxLength; length++) visit('', length);
  return output;
}
