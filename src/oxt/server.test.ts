import { beforeAll, describe, expect, it } from 'vitest';
import { fromHex, toHex } from '../core/bytes';
import { CORPUS, KEYWORDS, documentsFor } from '../sse/corpus';
import {
  RISTRETTO_ORDER,
  buildOxtIndex,
  createOxtQuery,
  decryptOxtMatches,
  generateOxtKeys,
  type OxtEncryptedIndex,
  type OxtKeys,
} from './core';
import { OxtServer } from './server';

let keys: OxtKeys;
let index: OxtEncryptedIndex;

beforeAll(async () => {
  keys = generateOxtKeys();
  index = await buildOxtIndex(keys);
});

describe('flat addressed TSet server boundary', () => {
  it('holds only globally shuffled opaque rows and a sorted exact XSet', () => {
    const server = new OxtServer(index);
    const snapshot = server.snapshot();
    expect(snapshot.tsetRows).toHaveLength(55);
    expect(snapshot.xset).toHaveLength(55);
    expect(new Set(snapshot.tsetRows.map((row) => row.addressHex)).size).toBe(55);
    expect(snapshot.xset).toEqual([...snapshot.xset].sort());
    expect(new Set(snapshot.xset).size).toBe(55);

    const serialized = JSON.stringify(snapshot);
    for (const keyword of KEYWORDS) expect(serialized).not.toContain(keyword);
    for (const document of CORPUS) expect(serialized).not.toContain(`\"${document.id}\"`);
    for (const key of Object.values(keys)) expect(serialized).not.toContain(toHex(key));
    expect(serialized).not.toContain('stag');
    expect(serialized).not.toContain('posting');
  });

  it('returns exactly the conjunction while traversing only the s list', async () => {
    const server = new OxtServer(index);
    const query = await createOxtQuery(keys, 'breach', 'audit');
    const response = await server.search(query.serverQuery);
    const ids = await decryptOxtMatches(keys, query, response.matches);
    server.recordFetch(response.seq, ids);

    expect(query.sTerm).toBe('breach');
    expect(query.xTerm).toBe('audit');
    expect(response.sListSize).toBe(documentsFor('breach').length);
    expect(response.membershipTests).toBe(documentsFor('breach').length);
    expect(ids).toEqual(['d02', 'd22']);
    expect(server.observations()[0]).toMatchObject({
      resultSize: 2,
      fetchedDocumentIds: ['d02', 'd22'],
    });
  });

  it('returns defensive copies of ciphertexts, snapshots, and observations', async () => {
    const server = new OxtServer(index);
    const query = await createOxtQuery(keys, 'breach', 'audit');
    const first = await server.search(query.serverQuery);
    const originalByte = first.matches[0]?.encryptedId[0];
    if (first.matches[0]) first.matches[0].encryptedId[0] ^= 0xff;
    const second = await server.search(query.serverQuery);
    expect(second.matches[0]?.encryptedId[0]).toBe(originalByte);

    const snapshot = server.snapshot();
    (snapshot.tsetRows[0] as { encryptedIdHex: string }).encryptedIdHex = 'not mutable';
    expect(server.snapshot().tsetRows[0]!.encryptedIdHex).not.toBe('not mutable');

    server.recordFetch(first.seq, await decryptOxtMatches(keys, query, second.matches));
    const observations = server.observations();
    (observations[0]!.candidateTagHexes as string[]).splice(0);
    (observations[0]!.fetchedDocumentIds as string[]).splice(0);
    expect(server.observations()[0]!.candidateTagHexes).toHaveLength(
      documentsFor('breach').length,
    );
  });

  it('records even an empty fetch exactly once', async () => {
    const server = new OxtServer(index);
    const query = await createOxtQuery(keys, 'patent', 'harassment');
    const response = await server.search(query.serverQuery);
    expect(response.matches).toHaveLength(0);
    server.recordFetch(response.seq, []);
    expect(() => server.recordFetch(response.seq, [])).toThrow(/already recorded/);
  });

  it('rejects malformed query and setup values without recording an observation', async () => {
    const server = new OxtServer(index);
    await expect(server.search({ stag: new Uint8Array(31), xtokens: [] })).rejects.toThrow(
      /stag must be exactly 32 bytes/,
    );

    const query = await createOxtQuery(keys, 'breach', 'audit');
    await expect(
      server.search({ ...query.serverQuery, xtokens: query.serverQuery.xtokens.slice(1) }),
    ).rejects.toThrow(/cross-tokens/);
    const malformed = query.serverQuery.xtokens.map((token) => token.slice());
    malformed[0] = new Uint8Array(32);
    await expect(server.search({ ...query.serverQuery, xtokens: malformed })).rejects.toThrow(
      /canonical|identity/,
    );
    expect(server.observations()).toEqual([]);
  });

  it('rejects duplicate addresses, unsorted XSet, identity points, and invalid y', () => {
    expect(
      () => new OxtServer({ ...index, tsetRows: [index.tsetRows[0]!, index.tsetRows[0]!] }),
    ).toThrow(/addresses must be unique/);
    expect(() => new OxtServer({ ...index, xset: [...index.xset].reverse() })).toThrow(
      /strictly sorted/,
    );
    expect(() => new OxtServer({ ...index, xset: [toHex(new Uint8Array(32))] })).toThrow(
      /non-identity ristretto255 point/,
    );
    expect(
      () =>
        new OxtServer({
          ...index,
          tsetRows: [{ ...index.tsetRows[0]!, y: new Uint8Array(32) }],
        }),
    ).toThrow(/must not be zero/);
    expect(
      () =>
        new OxtServer({
          ...index,
          tsetRows: [{ ...index.tsetRows[0]!, y: new Uint8Array(31) }],
        }),
    ).toThrow(/canonical 32-byte scalar/);
    expect(
      () =>
        new OxtServer({
          ...index,
          tsetRows: [{ ...index.tsetRows[0]!, y: littleEndian32(RISTRETTO_ORDER) }],
        }),
    ).toThrow(/canonical 32-byte scalar/);
  });

  it('binds encrypted identifiers to their addressed row with AES-GCM AAD', async () => {
    const server = new OxtServer(index);
    const query = await createOxtQuery(keys, 'breach', 'audit');
    const response = await server.search(query.serverQuery);
    const changed = response.matches.map((match, index) => ({
      ...match,
      addressHex: index === 0 ? toHex(fromHex(response.matches[1]!.addressHex)) : match.addressHex,
      encryptedId: match.encryptedId.slice(),
    }));
    await expect(decryptOxtMatches(keys, query, changed)).rejects.toBeTruthy();
  });
});

function littleEndian32(value: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let remaining = value;
  for (let index = 0; index < out.length; index++) {
    out[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  if (remaining !== 0n) throw new Error('test scalar does not fit 32 bytes');
  return out;
}
