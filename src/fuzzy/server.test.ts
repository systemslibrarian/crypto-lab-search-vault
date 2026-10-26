import { beforeAll, describe, expect, it } from 'vitest';
import { toHex } from '../core/bytes';
import { CORPUS } from '../sse/corpus';
import {
  buildFuzzyIndex,
  createFuzzyQuery,
  decryptAndFilterCandidates,
  type FuzzyIndexVault,
  type FuzzyKeys,
} from './client';
import { FuzzySearchServer } from './server';

const keys: FuzzyKeys = {
  kTrapdoor: new Uint8Array(32).fill(0x11),
  kPayload: new Uint8Array(32).fill(0x22),
};

let indexes: FuzzyIndexVault[];

beforeAll(async () => {
  indexes = await Promise.all(
    ([0, 1, 2] as const).map((threshold) => buildFuzzyIndex(keys, CORPUS, threshold)),
  );
});

describe('encrypted gram indexes', () => {
  it('derives the bounded corpus association counts from actual rows', () => {
    expect(indexes.map((index) => index.rows.length)).toEqual([14, 109, 401]);
  });

  it('stores only keyed trapdoors and independently randomized ciphertexts', () => {
    const rows = indexes[2]!.rows;
    expect(rows.every((row) => /^[0-9a-f]{64}$/.test(row.trapdoorHex))).toBe(true);
    expect(new Set(rows.map((row) => toHex(row.value))).size).toBe(rows.length);
    expect(Object.keys(rows[0]!).sort()).toEqual(['trapdoorHex', 'value']);
    expect(JSON.stringify(rows[0])).not.toContain('audit');
  });

  it('accounts for every stored byte from the rows the server actually holds', () => {
    for (const index of indexes) {
      const server = new FuzzySearchServer(index.rows);
      const cost = server.storageCost();
      expect(cost.associations).toBe(index.rows.length);
      expect(cost.trapdoorBytes).toBe(index.rows.length * 32);
      expect(cost.payloadBytes).toBe(index.rows.reduce((sum, row) => sum + row.value.length, 0));
      expect(cost.totalBytes).toBe(cost.trapdoorBytes + cost.payloadBytes);
    }
  });
});

describe('query, candidate, and filter boundaries', () => {
  it('sends only opaque trapdoors and finds the one-edit audit candidate', async () => {
    const query = await createFuzzyQuery(keys, 'asudit', 1);
    expect(query.grams).toHaveLength(7);
    expect(Object.keys(query.serverQuery)).toEqual(['trapdoorHexes']);
    expect(JSON.stringify(query.serverQuery)).not.toContain('asudit');

    const server = new FuzzySearchServer(indexes[1]!.rows);
    const response = server.search(query.serverQuery);
    const candidates = await decryptAndFilterCandidates(keys, 'asudit', 1, response);
    expect(response.lookups).toBe(7);
    expect(response.rows).toHaveLength(1);
    expect(response.matchedTrapdoorHexes).toEqual([response.rows[0]!.trapdoorHex]);
    expect(response.responseBytes).toBe(32 + response.rows[0]!.value.length);
    expect(candidates).toEqual([
      {
        keyword: 'audit',
        documentIds: ['d02', 'd06', 'd14', 'd19', 'd21', 'd22'],
        matchingRows: 1,
        distance: 1,
        accepted: true,
      },
    ]);
    expect(server.recordDocumentRequest(candidates[0]!.documentIds)).toEqual(
      candidates[0]!.documentIds,
    );
    expect(server.documentRequests()).toEqual([candidates[0]!.documentIds]);
  });

  it('exposes and then filters the threshold-2 lawsuit false positive', async () => {
    const query = await createFuzzyQuery(keys, 'asudit', 2);
    const server = new FuzzySearchServer(indexes[2]!.rows);
    const response = server.search(query.serverQuery);
    const candidates = await decryptAndFilterCandidates(keys, 'asudit', 2, response);
    expect(query.grams).toHaveLength(22);
    expect(response.rows).toHaveLength(7);
    expect(candidates.map((candidate) => [candidate.keyword, candidate.matchingRows, candidate.distance, candidate.accepted]))
      .toEqual([
        ['audit', 6, 1, true],
        ['lawsuit', 1, 3, false],
      ]);
  });

  it('rejects repeated or malformed server trapdoors', async () => {
    const query = await createFuzzyQuery(keys, 'asudit', 1);
    const server = new FuzzySearchServer(indexes[1]!.rows);
    const one = query.serverQuery.trapdoorHexes[0]!;
    expect(() => server.search({ trapdoorHexes: [one, one] })).toThrow(/repeats/);
    expect(() => server.search({ trapdoorHexes: ['00'] })).toThrow(/32-byte/);
    expect(server.queryCount).toBe(0);
    expect(server.queryBundles()).toEqual([]);
  });

  it('records only validated opaque query bundles and returns defensive copies', async () => {
    const query = await createFuzzyQuery(keys, 'asudit', 1);
    const server = new FuzzySearchServer(indexes[1]!.rows);
    server.search(query.serverQuery);
    const observed = server.queryBundles();
    expect(observed).toEqual([query.serverQuery.trapdoorHexes]);
    observed[0]![0] = '00'.repeat(32);
    expect(server.queryBundles()).toEqual([query.serverQuery.trapdoorHexes]);
  });

  it('reports stored associations rather than distinct trapdoor buckets', () => {
    const server = new FuzzySearchServer(indexes[2]!.rows);
    expect(server.storageCost().associations).toBe(indexes[2]!.rows.length);
    expect(server.storageCost().associations).toBe(401);
  });

  it('validates and defensively copies the final document access request', () => {
    const server = new FuzzySearchServer(indexes[1]!.rows);
    const supplied = ['d02', 'd06'];
    const observed = server.recordDocumentRequest(supplied);
    supplied[0] = 'd99';
    observed[1] = 'd98';
    expect(server.documentRequests()).toEqual([['d02', 'd06']]);
    expect(() => server.recordDocumentRequest(['d02', 'd02'])).toThrow(/repeats/);
    expect(() => server.recordDocumentRequest(['document-2'])).toThrow(/invalid/);
    expect(server.documentRequests()).toEqual([['d02', 'd06']]);
  });

  it('fails closed when a matching ciphertext is changed or rebound', async () => {
    const query = await createFuzzyQuery(keys, 'asudit', 1);
    const server = new FuzzySearchServer(indexes[1]!.rows);
    const response = server.search(query.serverQuery);
    const changedValue = response.rows[0]!.value.slice();
    changedValue[changedValue.length - 1] ^= 0x01;
    await expect(
      decryptAndFilterCandidates(keys, 'asudit', 1, {
        ...response,
        rows: [{ ...response.rows[0]!, value: changedValue }],
      }),
    ).rejects.toBeTruthy();

    const differentTrapdoor = query.serverQuery.trapdoorHexes.find(
      (token) => token !== response.rows[0]!.trapdoorHex,
    )!;
    await expect(
      decryptAndFilterCandidates(keys, 'asudit', 1, {
        ...response,
        rows: [{ ...response.rows[0]!, trapdoorHex: differentTrapdoor }],
      }),
    ).rejects.toBeTruthy();
  });
});
