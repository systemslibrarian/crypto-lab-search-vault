import { describe, expect, it } from 'vitest';
import { builtPostings } from './build';

/** The stepper's sequencing: a row must not appear in the server's store
 *  before the step that actually seals it. */
describe('index build stepper', () => {
  const COUNT = 4;

  it('stores nothing during the three key-derivation steps', () => {
    for (const cursor of [0, 1, 2, 3]) {
      const s = builtPostings(cursor, COUNT);
      expect(s.stored).toBe(0);
      expect(s.pending).toBeNull();
    }
  });

  it('reveals a posting’s address one step before its sealed value', () => {
    // cursor 4: address of posting 0, nothing stored yet
    expect(builtPostings(4, COUNT)).toEqual({ stored: 0, pending: 0, valueShown: false });
    // cursor 5: value of posting 0 revealed, and that row is now stored
    expect(builtPostings(5, COUNT)).toEqual({ stored: 1, pending: 0, valueShown: true });
    // cursor 6: address of posting 1, still one row stored
    expect(builtPostings(6, COUNT)).toEqual({ stored: 1, pending: 1, valueShown: false });
    expect(builtPostings(7, COUNT)).toEqual({ stored: 2, pending: 1, valueShown: true });
  });

  it('ends with every posting stored and the last one still displayed', () => {
    const last = builtPostings(3 + COUNT * 2, COUNT);
    expect(last.stored).toBe(COUNT);
    expect(last.pending).toBe(COUNT - 1);
    expect(last.valueShown).toBe(true);
  });

  it('handles a keyword with no postings', () => {
    expect(builtPostings(9, 0)).toEqual({ stored: 0, pending: null, valueShown: false });
  });
});
