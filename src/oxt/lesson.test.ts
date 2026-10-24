import { beforeAll, describe, expect, it } from 'vitest';
import { toHex } from '../core/bytes';
import { CORPUS, KEYWORDS, documentsFor } from '../sse/corpus';
import { getState, initState } from '../ui/state';
import {
  ConjunctiveLesson,
  ConjunctiveQueryError,
  derivePathOramCost,
  parseConjunctiveQuery,
} from './lesson';

let lesson: ConjunctiveLesson;

beforeAll(async () => {
  lesson = await ConjunctiveLesson.create();
});

describe('bounded two-term query grammar', () => {
  it('normalizes case and whitespace around exactly one AND', () => {
    expect(parseConjunctiveQuery('  Breach   aNd   AUDIT ')).toEqual({
      left: 'breach',
      right: 'audit',
      canonical: 'breach AND audit',
    });
  });

  it.each([
    ['', 'empty'],
    ['audit', 'syntax'],
    ['audit breach', 'syntax'],
    ['audit AND', 'syntax'],
    ['AND audit', 'syntax'],
    ['audit OR breach', 'or'],
    ['audit NOT breach', 'not'],
    ['(audit) AND breach', 'parentheses'],
    ['audit AND breach AND salary', 'arity'],
    ['audit AND unicorn', 'unknown-keyword'],
    ['AUDIT AND audit', 'duplicate-keyword'],
  ])('rejects %j as %s before creating a transcript', async (input, code) => {
    const before = lesson.transcriptCounts();
    try {
      parseConjunctiveQuery(input);
      throw new Error('query unexpectedly parsed');
    } catch (error) {
      expect(error).toBeInstanceOf(ConjunctiveQueryError);
      expect((error as ConjunctiveQueryError).code).toBe(code);
    }
    await expect(lesson.run(input)).rejects.toMatchObject({ code });
    expect(lesson.transcriptCounts()).toEqual(before);
  });
});

describe('naive SSE versus bounded OXT semantics', () => {
  it('pins corpus facts independently of either encrypted implementation', () => {
    expect(KEYWORDS).toHaveLength(14);
    expect(CORPUS).toHaveLength(24);
    expect(CORPUS.reduce((total, document) => total + document.keywords.length, 0)).toBe(55);
    expect(documentsFor('breach')).toEqual(['d02', 'd13', 'd15', 'd22']);
    expect(documentsFor('subpoena')).toEqual(['d03', 'd13', 'd15', 'd22']);
    expect(plainIntersection('breach', 'subpoena')).toEqual(['d13', 'd15', 'd22']);
  });

  it('matches an independent plaintext oracle for all 91 pairs in both orders', async () => {
    let unorderedPairs = 0;
    for (let i = 0; i < KEYWORDS.length; i++) {
      for (let j = i + 1; j < KEYWORDS.length; j++) {
        unorderedPairs += 1;
        const left = KEYWORDS[i]!;
        const right = KEYWORDS[j]!;
        const expected = plainIntersection(left, right);
        const forward = await lesson.run(`${left} AND ${right}`);
        const reverse = await lesson.run(`${right} AND ${left}`);

        for (const trace of [forward, reverse]) {
          expect(trace.naive.finalResultIds).toEqual(expected);
          expect(trace.oxt.finalResultIds).toEqual(expected);
          expect(trace.naive.queryVolume).toBe(2);
          expect(trace.oxt.queryVolume).toBe(1);
          expect(trace.naive.terms.map((term) => term.keyword)).toEqual([
            trace.input.left,
            trace.input.right,
          ]);
          expect(trace.naive.terms[0].tokenHex).not.toBe(trace.naive.terms[1].tokenHex);
          expect(trace.oxt.sListSize).toBe(documentsFor(trace.oxt.sTerm).length);
          expect(trace.oxt.membershipTests).toBe(trace.oxt.sListSize);
          expect(trace.oxt.rows).toHaveLength(trace.oxt.sListSize);
          expect(trace.oxt.xTermPostingListRetrieved).toBe(false);
        }

        // Operand order is syntax, not leakage: stable (frequency, ASCII)
        // selection produces byte-identical OXT requests and outcomes.
        expect(reverse.oxt.sTerm).toBe(forward.oxt.sTerm);
        expect(reverse.oxt.xTerm).toBe(forward.oxt.xTerm);
        expect(reverse.oxt.stagHex).toBe(forward.oxt.stagHex);
        expect(reverse.oxt.rows.map((row) => row.xtokenHex)).toEqual(
          forward.oxt.rows.map((row) => row.xtokenHex),
        );
        expect(reverse.oxt.rows.map((row) => row.candidateTagHex)).toEqual(
          forward.oxt.rows.map((row) => row.candidateTagHex),
        );
      }
    }
    expect(unorderedPairs).toBe(91);
  }, 30_000);

  it('uses the lower-frequency term, with stable ASCII order for a tie', async () => {
    const lower = await lesson.run('audit AND harassment');
    expect(lower.oxt.sTerm).toBe('harassment');
    expect(documentsFor('harassment').length).toBeLessThan(documentsFor('audit').length);

    const tie = await lesson.run('breach AND subpoena');
    expect(documentsFor('breach')).toHaveLength(4);
    expect(documentsFor('subpoena')).toHaveLength(4);
    expect(tie.oxt.sTerm).toBe('breach');
    expect(tie.oxt.xTerm).toBe('subpoena');
  });

  it('uses fresh isolated SSE state and never feeds the app ledger or IKK evidence', async () => {
    await initState();
    const globalBefore = getState().server.observations();
    const isolated = await ConjunctiveLesson.create();
    expect(isolated.transcriptCounts()).toEqual({ naiveQueries: 0, oxtQueries: 0 });
    const result = await isolated.run('breach AND audit');
    expect(result.naive.terms.map((term) => term.resultIds)).toEqual([
      documentsFor('breach'),
      documentsFor('audit'),
    ]);
    expect(result.naive.terms.map((term) => term.repeatedToken)).toEqual([false, false]);

    const reversed = await isolated.run('audit AND breach');
    expect(reversed.naive.terms.map((term) => term.repeatedToken)).toEqual([true, true]);
    expect(reversed.naive.terms.map((term) => term.tokenHex)).toEqual([
      result.naive.terms[1].tokenHex,
      result.naive.terms[0].tokenHex,
    ]);
    expect(isolated.transcriptCounts()).toEqual({ naiveQueries: 4, oxtQueries: 2 });
    expect(getState().server.observations()).toEqual(globalBefore);
  });
});

describe('measured equality and intersection leakage controls', () => {
  it('distinguishes repeated stag from repeated candidate-point evidence', async () => {
    const controls = new Map((await lesson.runControlPairs()).map((row) => [row.kind, row]));

    const shared = controls.get('shared-x-overlapping-s')!;
    expect(shared.firstXTerm).toBe('audit');
    expect(shared.secondXTerm).toBe('audit');
    expect(shared.sharedSTermDocumentIds).toEqual(['d13', 'd15', 'd22']);
    expect(shared.repeatedDocumentIdsForNarrator).toEqual(['d13', 'd15', 'd22']);
    expect(shared.repeatedCandidateTagHexes).toHaveLength(3);
    expect(shared.repeatedLookup).toBe(false);

    const disjoint = controls.get('shared-x-disjoint-s')!;
    expect(disjoint.firstXTerm).toBe('audit');
    expect(disjoint.secondXTerm).toBe('audit');
    expect(disjoint.sharedSTermDocumentIds).toEqual([]);
    expect(disjoint.repeatedCandidateTagHexes).toEqual([]);
    // This zero is deliberately not evidence that the x terms differ.
    expect(disjoint.repeatedDocumentIdsForNarrator).toEqual([]);

    const differentX = controls.get('different-x-overlapping-s')!;
    expect(differentX.firstXTerm).toBe('audit');
    expect(differentX.secondXTerm).toBe('lawsuit');
    expect(differentX.sharedSTermDocumentIds).toEqual(['d13', 'd15', 'd22']);
    expect(differentX.repeatedCandidateTagHexes).toEqual([]);

    const repeatedS = controls.get('repeated-s-different-x')!;
    expect(repeatedS.firstSTerm).toBe('breach');
    expect(repeatedS.secondSTerm).toBe('breach');
    expect(repeatedS.repeatedLookup).toBe(true);
    expect(repeatedS.repeatedCandidateTagHexes).toEqual([]);

    const identical = controls.get('identical-query')!;
    expect(identical.repeatedLookup).toBe(true);
    expect(identical.repeatedCandidateTagHexes).toHaveLength(documentsFor('breach').length);
    expect(new Set(identical.repeatedCandidateTagHexes.map((point) => toHex(hex(point)))).size).toBe(
      documentsFor('breach').length,
    );
  });
});

describe('bounded Path ORAM comparison arithmetic', () => {
  it('derives every displayed number from N=24, Z=4, and a three-result cap', () => {
    const cost = derivePathOramCost();
    expect(cost).toMatchObject({
      documentCount: 24,
      treeDepth: 5,
      leaves: 32,
      bucketSize: 4,
      bucketsPerPath: 6,
      readsPerFetch: 24,
      writesPerFetch: 24,
      transfersPerFetch: 48,
      maxPairIntersection: 3,
      paddedTransfers: 144,
    });
    expect(cost.maxPairs).toContain('breach AND subpoena');
    expect(cost.paddingCases).toEqual([
      { realResults: 0, dummyFetches: 3, logicalFetches: 3, blockTransfers: 144 },
      { realResults: 1, dummyFetches: 2, logicalFetches: 3, blockTransfers: 144 },
      { realResults: 2, dummyFetches: 1, logicalFetches: 3, blockTransfers: 144 },
      { realResults: 3, dummyFetches: 0, logicalFetches: 3, blockTransfers: 144 },
    ]);
  });

  it('rejects invalid parameters instead of emitting plausible-looking costs', () => {
    expect(() => derivePathOramCost([])).toThrow(/at least one document/);
    expect(() => derivePathOramCost(CORPUS, 0)).toThrow(/positive safe integer/);
    expect(() => derivePathOramCost(CORPUS, 1.5)).toThrow(/positive safe integer/);
    expect(() => derivePathOramCost([...CORPUS, CORPUS[0]!])).toThrow(/ids must be unique/);
  });
});

function plainIntersection(left: string, right: string): string[] {
  return CORPUS.filter(
    (document) =>
      (document.keywords as readonly string[]).includes(left) &&
      (document.keywords as readonly string[]).includes(right),
  )
    .map((document) => document.id)
    .sort();
}

function hex(value: string): Uint8Array {
  return Uint8Array.from(value.match(/../g)!.map((byte) => Number.parseInt(byte, 16)));
}
