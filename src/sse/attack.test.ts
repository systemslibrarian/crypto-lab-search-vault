import { beforeAll, describe, expect, it } from 'vitest';
import { toHex } from '../core/bytes';
import { buildVault, generateKeys, openPostings, searchToken } from './client';
import { SearchServer } from './server';
import { CORPUS, KEYWORDS } from './corpus';
import {
  knownCooccurrence,
  knownCounts,
  observedCooccurrence,
  tokenProfiles,
  type TokenProfile,
} from './leakage';
import { DEFAULT_ATTACK, recoveryRate, runAttack, xorshift32, type AttackInput } from './attack';
import type { VaultKeys } from './types';

let keys: VaultKeys;
let server: SearchServer;
const truth = new Map<string, string>();

/** Issue `queried` real searches and hand the adversary only the ledger. */
async function observe(queried: readonly string[]): Promise<TokenProfile[]> {
  server.clearLedger();
  for (const w of queried) {
    const token = await searchToken(keys, w);
    server.fetchDocuments(token, await openPostings(keys, w, await server.search(token)));
  }
  return tokenProfiles(server.observations());
}

function attackInput(profiles: TokenProfile[]): AttackInput {
  return {
    profiles,
    candidates: KEYWORDS,
    observed: observedCooccurrence(profiles, CORPUS.length),
    known: knownCooccurrence(KEYWORDS, CORPUS),
    counts: knownCounts(KEYWORDS, CORPUS),
    totalDocs: CORPUS.length,
  };
}

beforeAll(async () => {
  keys = generateKeys();
  const { vault } = await buildVault(keys);
  server = new SearchServer(vault);
  for (const w of KEYWORDS) truth.set(toHex(await searchToken(keys, w)), w);
});

describe('count attack (Cash–Grubbs–Perry–Ristenpart 2015)', () => {
  it('pins every token whose result size is unique in the keyword universe', async () => {
    const profiles = await observe(KEYWORDS);
    const result = runAttack(attackInput(profiles));
    // "audit" (6 documents) and "harassment" (2) have counts no other keyword
    // shares — volume alone identifies them, before any co-occurrence work.
    expect(result.pinnedByCount).toBe(2);
    const byCount = result.recoveries.filter((r) => r.method === 'count');
    expect(byCount.map((r) => r.keyword).sort()).toEqual(['audit', 'harassment']);
    for (const r of byCount) expect(truth.get(r.tokenHex)).toBe(r.keyword);
  });
});

describe('IKK attack (Islam–Kuzu–Kantarcioglu 2012)', () => {
  it('recovers every keyword from the access pattern with exact background knowledge', async () => {
    const profiles = await observe(KEYWORDS);
    const result = runAttack(attackInput(profiles));
    const { rate, correct, total } = recoveryRate(result.recoveries, truth);
    expect(total).toBe(KEYWORDS.length);
    expect(correct).toBe(KEYWORDS.length);
    expect(rate).toBe(1);
    // A perfect assignment leaves no residual between the two matrices.
    expect(result.cost).toBeLessThan(1e-12);
  });

  it('is deterministic for a given seed', async () => {
    const profiles = await observe(KEYWORDS);
    const input = attackInput(profiles);
    const a = runAttack(input, { ...DEFAULT_ATTACK, noise: 0.5, seed: 12345 });
    const b = runAttack(input, { ...DEFAULT_ATTACK, noise: 0.5, seed: 12345 });
    expect(a.recoveries).toEqual(b.recoveries);
  });

  it('still recovers most keywords when only part of the vocabulary was queried', async () => {
    const subset = ['salary', 'lawsuit', 'merger', 'audit', 'breach', 'layoff', 'contract'];
    const profiles = await observe(subset);
    const result = runAttack(attackInput(profiles));
    const { rate } = recoveryRate(result.recoveries, truth);
    // Fewer observed tokens means a smaller matrix to match against, so the
    // adversary does worse — but far from randomly (1/14 ≈ 0.07).
    expect(rate).toBeGreaterThanOrEqual(0.5);
  });

  it('degrades as the adversary background knowledge gets noisier', async () => {
    const profiles = await observe(KEYWORDS);
    const input = attackInput(profiles);
    const clean = recoveryRate(runAttack(input, { ...DEFAULT_ATTACK, noise: 0 }).recoveries, truth);
    const noisy = recoveryRate(
      runAttack(input, { ...DEFAULT_ATTACK, noise: 1.5, seed: 99 }).recoveries,
      truth,
    );
    expect(clean.rate).toBe(1);
    expect(noisy.rate).toBeLessThan(clean.rate);
  });

  it('reports lower confidence where the restarts disagree', async () => {
    // Confidence is the share of independent restarts that reached the same
    // answer. Annealing is a heuristic, so even the exact-knowledge case has
    // restarts that stall in a local optimum — the reported answer is still
    // the best one found, and it is still correct.
    const profiles = await observe(KEYWORDS);
    const input = attackInput(profiles);
    const clean = runAttack(input, { ...DEFAULT_ATTACK, noise: 0 });
    const cleanMean = mean(clean.recoveries.map((r) => r.confidence));
    expect(cleanMean).toBeGreaterThan(0.8);
    const noisy = runAttack(input, { ...DEFAULT_ATTACK, noise: 2, seed: 7 });
    expect(mean(noisy.recoveries.map((r) => r.confidence))).toBeLessThan(cleanMean);
    for (const r of clean.recoveries) {
      expect(r.confidence).toBeGreaterThan(0);
      expect(r.confidence).toBeLessThanOrEqual(1);
    }
  });

  it('assigns each keyword to at most one token', async () => {
    const profiles = await observe(KEYWORDS);
    const result = runAttack(attackInput(profiles), { ...DEFAULT_ATTACK, noise: 0.8, seed: 4 });
    const guessed = result.recoveries.map((r) => r.keyword);
    expect(new Set(guessed).size).toBe(guessed.length);
  });

  it('does nothing when the server has observed nothing', () => {
    const result = runAttack({ ...attackInput([]), profiles: [] });
    expect(result.recoveries).toEqual([]);
    expect(result.pinnedByCount).toBe(0);
  });

  it('refuses to run when more tokens were seen than candidate keywords exist', async () => {
    const profiles = await observe(KEYWORDS);
    expect(() => runAttack({ ...attackInput(profiles), candidates: ['salary'] })).toThrow(
      /more distinct tokens/,
    );
  });
});

function mean(xs: number[]): number {
  return xs.reduce((a, b) => a + b, 0) / xs.length;
}

describe('seeded generator', () => {
  it('produces a reproducible stream in [0,1)', () => {
    const a = xorshift32(42);
    const b = xorshift32(42);
    for (let i = 0; i < 100; i++) {
      const v = a();
      expect(v).toBe(b());
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThan(1);
    }
  });
});
