import { beforeAll, describe, expect, it } from 'vitest';
import { toHex } from '../core/bytes';
import { buildVault, generateKeys, openPostings, searchToken } from './client';
import { SearchServer } from './server';
import { CORPUS, KEYWORDS, documentsFor } from './corpus';
import {
  documentCooccurrence,
  knownCooccurrence,
  knownCounts,
  observedCooccurrence,
  tokenLabel,
  tokenProfiles,
  touchedDocuments,
} from './leakage';
import type { VaultKeys } from './types';

let keys: VaultKeys;
let server: SearchServer;
/** truth table the *demo* keeps; the leakage code never receives it */
const truth = new Map<string, string>();

beforeAll(async () => {
  keys = generateKeys();
  const { vault } = await buildVault(keys);
  server = new SearchServer(vault);
  for (const w of KEYWORDS) {
    const token = await searchToken(keys, w);
    truth.set(toHex(token), w);
    server.fetchDocuments(token, await openPostings(keys, w, await server.search(token)));
  }
});

describe('token profiles', () => {
  it('has one profile per distinct token, in first-seen order', () => {
    const profiles = tokenProfiles(server.observations());
    expect(profiles).toHaveLength(KEYWORDS.length);
    expect(profiles.map((p) => p.firstSeenSeq)).toEqual(
      [...profiles].map((_, i) => i),
    );
  });

  it('counts repeat queries of the same token rather than duplicating it', async () => {
    const token = await searchToken(keys, 'audit');
    server.fetchDocuments(token, await openPostings(keys, 'audit', await server.search(token)));
    const profiles = tokenProfiles(server.observations());
    expect(profiles).toHaveLength(KEYWORDS.length);
    expect(profiles.find((p) => p.tokenHex === toHex(token))!.queryCount).toBe(2);
  });

  it('exposes result size — volume leakage — matching the true keyword', () => {
    for (const p of tokenProfiles(server.observations())) {
      expect(p.resultSize).toBe(documentsFor(truth.get(p.tokenHex)!).length);
    }
  });

  it('labels a token from its bytes alone', () => {
    expect(tokenLabel('abcdef0123456789')).toBe('t·abcdef');
  });
});

describe('co-occurrence leakage', () => {
  /**
   * The load-bearing fact of this whole demo: the matrix a curious server can
   * build from returned document identifiers is *identical* to the matrix an
   * adversary can compute from a corpus it already knows. Encryption does not
   * change it at all — which is precisely why IKK works.
   */
  it('reproduces the plaintext co-occurrence matrix exactly', () => {
    const profiles = tokenProfiles(server.observations());
    const observed = observedCooccurrence(profiles, CORPUS.length);
    const known = knownCooccurrence(KEYWORDS, CORPUS);
    const order = profiles.map((p) => KEYWORDS.indexOf(truth.get(p.tokenHex)! as never));
    for (let i = 0; i < profiles.length; i++) {
      for (let j = 0; j < profiles.length; j++) {
        expect(observed[i]![j]).toBeCloseTo(known[order[i]!]![order[j]!]!, 12);
      }
    }
  });

  it('is symmetric with the normalised result size on the diagonal', () => {
    const profiles = tokenProfiles(server.observations());
    const m = observedCooccurrence(profiles, CORPUS.length);
    for (let i = 0; i < m.length; i++) {
      expect(m[i]![i]).toBeCloseTo(profiles[i]!.resultSize / CORPUS.length, 12);
      for (let j = 0; j < m.length; j++) expect(m[i]![j]).toBeCloseTo(m[j]![i]!, 12);
    }
  });

  it('counts documents per keyword in the adversary corpus', () => {
    expect(knownCounts(KEYWORDS, CORPUS)).toEqual(
      KEYWORDS.map((w) => documentsFor(w).length),
    );
  });

  it('leaves no two keywords with an identical leakage fingerprint', () => {
    // Two keywords are information-theoretically interchangeable only if the
    // weighted co-occurrence graph has an automorphism swapping them — no
    // attack, however clever, could then separate them. Colour refinement
    // (1-WL) discharges that: if every keyword ends in its own colour class,
    // the automorphism group is trivial and the true assignment is unique.
    const m = knownCooccurrence(KEYWORDS, CORPUS);
    let colours = knownCounts(KEYWORDS, CORPUS).map(String);
    for (let round = 0; round < KEYWORDS.length; round++) {
      const next = colours.map((c, i) => {
        const nbrs = colours
          .map((cj, j) => (i === j ? null : `${m[i]![j]!.toFixed(6)}:${cj}`))
          .filter((x): x is string => x !== null)
          .sort();
        return `${c}|${nbrs.join(';')}`;
      });
      // Re-index to short labels so the strings do not grow exponentially.
      const seen = new Map<string, string>();
      colours = next.map((c) => {
        if (!seen.has(c)) seen.set(c, String(seen.size));
        return seen.get(c)!;
      });
      if (new Set(colours).size === KEYWORDS.length) break;
    }
    expect(new Set(colours).size).toBe(KEYWORDS.length);
  });
});

describe('document-level leakage', () => {
  it('clusters documents that keep coming back together', () => {
    const ids = CORPUS.map((d) => d.id);
    const m = documentCooccurrence(server.observations(), ids);
    const i = ids.indexOf('d13');
    const j = ids.indexOf('d15');
    // d13 and d15 share breach+subpoena, so they co-occur more than a pair
    // sharing nothing at all.
    expect(m[i]![j]!).toBeGreaterThan(m[i]![ids.indexOf('d07')]!);
  });

  it('reports how much of the database has been exposed to some result set', () => {
    const touched = touchedDocuments(server.observations());
    expect(touched.size).toBe(CORPUS.length);
    expect(touchedDocuments([]).size).toBe(0);
  });
});
