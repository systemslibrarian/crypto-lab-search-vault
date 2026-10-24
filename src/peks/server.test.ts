import { beforeAll, describe, expect, it } from 'vitest';
import { toHex } from '../core/bytes';
import { derivePeksKeyPair, encryptKeyword, issueTrapdoor, type PeksKeyPair } from './core';
import { PeksServer, type PeksStoredRecord } from './server';

let keys: PeksKeyPair;
let records: PeksStoredRecord[];

beforeAll(async () => {
  keys = derivePeksKeyPair(53n);
  records = await Promise.all(
    [
      ['record-7f', 'audit'],
      ['record-2a', 'merger'],
      ['record-91', 'audit'],
      ['record-b4', 'breach'],
    ].map(async ([opaqueRecordId, keyword]) => ({
      opaqueRecordId: opaqueRecordId!,
      tag: await encryptKeyword(keys.publicKey, keyword!),
    })),
  );
});

describe('PEKS server role and leakage', () => {
  it('tests every tag and returns exactly the matching opaque ids', async () => {
    const server = new PeksServer(records);
    const result = await server.search(issueTrapdoor(keys.secretKey, 'audit'));
    expect(result.tests).toBe(records.length);
    expect(result.rows).toHaveLength(records.length);
    expect(result.rows.filter((row) => row.matched).map((row) => row.opaqueRecordId)).toEqual([
      'record-7f',
      'record-91',
    ]);
    expect(result.matchedRecordIds).toEqual(['record-7f', 'record-91']);
  });

  it('stores no keyword, private scalar, sender randomness, or demo GT value', () => {
    const stored = new PeksServer(records).records();
    expect(Object.keys(stored[0]!).sort()).toEqual(['opaqueRecordId', 'tag']);
    expect(Object.keys(stored[0]!.tag).sort()).toEqual(['a', 'b']);
    const serialized = JSON.stringify(stored);
    for (const forbidden of ['audit', 'merger', 'breach', 'body', 'secret', 'scalar', 'randomness', 'gt']) {
      expect(serialized.toLowerCase()).not.toContain(forbidden);
    }
  });

  it('records deterministic trapdoor linkage separately from access and volume', async () => {
    const server = new PeksServer(records);
    const firstTrapdoor = issueTrapdoor(keys.secretKey, 'audit');
    const secondTrapdoor = issueTrapdoor(keys.secretKey, 'audit');
    await server.search(firstTrapdoor);
    await server.search(secondTrapdoor);
    const [first, second] = server.observations();
    expect(first!.trapdoorHex).toBe(toHex(firstTrapdoor.bytes));
    expect(second!.trapdoorHex).toBe(first!.trapdoorHex);
    expect(first!.tests).toBe(records.length);
    expect(first!.resultSize).toBe(2);
    expect(first!.matchedRecordIds).toEqual(['record-7f', 'record-91']);
    expect(Object.keys(first!).sort()).toEqual([
      'matchedRecordIds',
      'resultSize',
      'seq',
      'tests',
      'trapdoorHex',
    ]);
  });

  it('does not link a different keyword trapdoor by bytes', async () => {
    const server = new PeksServer(records);
    await server.search(issueTrapdoor(keys.secretKey, 'audit'));
    await server.search(issueTrapdoor(keys.secretKey, 'merger'));
    const observations = server.observations();
    expect(observations[0]!.trapdoorHex).not.toBe(observations[1]!.trapdoorHex);
    expect(observations[1]!.matchedRecordIds).toEqual(['record-2a']);
  });

  it('defensively copies tags and observations at the server boundary', async () => {
    const server = new PeksServer(records);
    const copy = server.records();
    copy[0]!.tag.a[0] ^= 0xff;
    expect(toHex(server.records()[0]!.tag.a)).not.toBe(toHex(copy[0]!.tag.a));

    await server.search(issueTrapdoor(keys.secretKey, 'audit'));
    const observations = server.observations();
    (observations[0]!.matchedRecordIds as string[]).push('invented');
    expect(server.observations()[0]!.matchedRecordIds).not.toContain('invented');
  });

  it('rejects empty stores, duplicate ids, and empty ids', () => {
    expect(() => new PeksServer([])).toThrow(/at least one tag/);
    expect(() => new PeksServer([{ ...records[0]!, opaqueRecordId: '' }])).toThrow(/must not be empty/);
    expect(() => new PeksServer([records[0]!, records[0]!])).toThrow(/must be unique/);
  });
});
