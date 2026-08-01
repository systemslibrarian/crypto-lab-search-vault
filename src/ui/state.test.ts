import { beforeAll, describe, expect, it } from 'vitest';
import { KEYWORDS } from '../sse/corpus';
import { tokenProfiles } from '../sse/leakage';
import { QUERY_MIX, getState, initState, resetLedger, runRealisticRound, runSearch } from './state';

beforeAll(async () => {
  await initState();
});

describe('the demo query mix', () => {
  it('covers every keyword in the corpus', () => {
    expect(QUERY_MIX.map(([w]) => w).sort()).toEqual([...KEYWORDS].sort());
  });

  it('is skewed — otherwise the frequency chart would teach nothing', () => {
    const counts = QUERY_MIX.map(([, n]) => n);
    expect(Math.max(...counts)).toBeGreaterThan(Math.min(...counts));
  });
});

describe('a realistic round', () => {
  it('produces one profile per keyword, with the intended query counts', async () => {
    resetLedger();
    await runRealisticRound();
    const profiles = tokenProfiles(getState().server.observations());
    expect(profiles).toHaveLength(KEYWORDS.length);

    const truth = getState().truth;
    const observed = new Map(profiles.map((p) => [truth.get(p.tokenHex)!, p.queryCount]));
    for (const [keyword, n] of QUERY_MIX) expect(observed.get(keyword)).toBe(n);
  });

  it('interleaves the queries rather than grouping them by keyword', async () => {
    resetLedger();
    await runRealisticRound();
    const seq = getState().server.observations().map((o) => o.tokenHex);
    const firstRepeatGap = seq.findIndex((t, i) => i > 0 && t === seq[0]);
    // A keyword-grouped log would repeat the first token at position 1.
    expect(firstRepeatGap).toBeGreaterThan(1);
  });
});

describe('a single search', () => {
  it('records exactly one observation and returns the sealed bodies', async () => {
    resetLedger();
    const { ids, documents } = await runSearch('patent');
    expect(documents.map((d) => d.id)).toEqual(ids);
    expect(getState().server.observations()).toHaveLength(1);
  });
});
