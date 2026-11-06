import { describe, expect, it } from 'vitest';
import { DRAW_RANGE, randomBelow, rejectionLimit, type Uint32Source } from './uniform';
import { shuffle } from './client';

/**
 * A source that hands out exactly the values it was given, counts how many it was asked
 * for, and THROWS when it runs dry. Repeating its last value would make a bound mutation
 * spin forever instead of failing, which is how a boundary test stops being one.
 */
function scripted(values: readonly number[]): { source: Uint32Source; draws: () => number } {
  let index = 0;
  return {
    source: (out) => {
      if (index >= values.length) throw new Error(`the scripted source ran dry after ${index} draws`);
      out[0] = values[index]!;
      if (out[0] !== values[index]) throw new Error(`${values[index]} does not fit a 32-bit draw`);
      index += 1;
    },
    draws: () => index,
  };
}

/** The limit, derived here by a different route than the code's: floor division, not remainder. */
function expectedLimit(bound: number): number {
  return Math.floor(DRAW_RANGE / bound) * bound;
}

describe('uniform draws below a bound', () => {
  it('rejects exactly the tail no multiple of the bound can reach', () => {
    for (const bound of [1, 2, 3, 7, 10, 255, 256, 1000, 40_001, 0xffff_ffff, DRAW_RANGE]) {
      const limit = rejectionLimit(bound);
      expect(limit).toBe(expectedLimit(bound));
      expect(limit % bound).toBe(0);
      expect(DRAW_RANGE - limit).toBeLessThan(bound);
    }
  });

  it('spends a draw on every value in the rejected tail, then returns the next one below it', () => {
    // bound 10 leaves a tail of six: 2^32 mod 10 === 6, so the limit is 4_294_967_290
    // and the draws 4_294_967_290..4_294_967_295 must each be discarded. bound 3 would
    // not do: its tail is one value wide, so limit + 1 is 2^32 and does not fit a draw.
    const bound = 10;
    const limit = expectedLimit(bound);
    expect(limit).toBe(4_294_967_290);
    expect(DRAW_RANGE - limit).toBe(6);
    const { source, draws } = scripted([limit, limit + 1, limit + 5, limit - 1]);
    expect(randomBelow(bound, source)).toBe((limit - 1) % bound);
    expect(draws()).toBe(4);
  });

  it('accepts the value one below the limit and rejects the limit itself', () => {
    const bound = 7;
    const limit = expectedLimit(bound);
    const below = scripted([limit - 1]);
    expect(randomBelow(bound, below.source)).toBe((limit - 1) % bound);
    expect(below.draws()).toBe(1);

    // +1 and -1 around the boundary, each on its own: the limit must cost a draw.
    const at = scripted([limit, 0]);
    expect(randomBelow(bound, at.source)).toBe(0);
    expect(at.draws()).toBe(2);
  });

  it('refuses a bound that is not a positive integer in range', () => {
    for (const bound of [0, -1, 1.5, Number.NaN, DRAW_RANGE + 1]) {
      expect(() => randomBelow(bound, scripted([0]).source)).toThrow(RangeError);
    }
  });

  it('still costs exactly one draw for bound 1, and returns 0 whatever it drew', () => {
    // bound 1 has limit === DRAW_RANGE, so no draw is ever rejected -- but one is still
    // taken. Pinned because a tempting "shortcut for bound 1" would change the number of
    // draws the shuffle makes, and the shuffle's draw count is what the tail test reads.
    const { source, draws } = scripted([0xffff_ffff]);
    expect(randomBelow(1, source)).toBe(0);
    expect(draws()).toBe(1);
    expect(() => randomBelow(1, scripted([]).source)).toThrow(/ran dry/);
  });
});

/**
 * The shuffle itself, with the draws scripted. This is the guard on the change: with the
 * old `% (i + 1)` restored, the rejected draw below is accepted instead and both the
 * permutation and the draw count come out different.
 */
describe('the index shuffle draws without modulo bias', () => {
  it('discards a draw in the rejected tail rather than folding it into a low index', () => {
    // Four rows, so Fisher-Yates asks for bounds 4, 3 and 2.
    // bound 4 divides 2^32, so its limit is 2^32 and nothing is rejected: draw 2 -> j=2.
    // bound 3 has limit 4_294_967_295, so that exact value is the whole tail: it must be
    // discarded and redrawn. Under `% 3` it would be accepted as j = 4294967295 % 3 = 0.
    // bound 2 divides 2^32: draw 1 -> j=1.
    const script = [2, 4_294_967_295, 1, 1];
    let index = 0;
    const source: Uint32Source = (out) => {
      if (index >= script.length) throw new Error(`the scripted source ran dry after ${index} draws`);
      out[0] = script[index]!;
      index += 1;
    };
    const out = shuffle(['a', 'b', 'c', 'd'], source);
    expect(index).toBe(4);
    expect(out).toEqual(['a', 'd', 'b', 'c']);
    expect([...out].sort()).toEqual(['a', 'b', 'c', 'd']);
  });
});
