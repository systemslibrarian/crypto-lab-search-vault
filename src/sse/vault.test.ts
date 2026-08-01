import { beforeAll, describe, expect, it } from 'vitest';
import { toHex, utf8 } from '../core/bytes';
import { seal } from '../core/aead';
import {
  addressFor,
  buildVault,
  generateKeys,
  normalize,
  openDocument,
  openPostings,
  postingKey,
  searchToken,
} from './client';
import { SearchServer } from './server';
import { CORPUS, KEYWORDS, documentsFor } from './corpus';
import type { EncryptedVault, VaultKeys } from './types';

let keys: VaultKeys;
let vault: EncryptedVault;
let server: SearchServer;

beforeAll(async () => {
  keys = generateKeys();
  ({ vault } = await buildVault(keys));
  server = new SearchServer(vault);
});

async function search(keyword: string): Promise<string[]> {
  const token = await searchToken(keys, keyword);
  const postings = await server.search(token);
  const ids = await openPostings(keys, keyword, postings);
  server.fetchDocuments(token, ids);
  return ids;
}

describe('encrypted index construction', () => {
  it('stores exactly one posting per (keyword, document) pair', () => {
    const expected = CORPUS.reduce((n, d) => n + d.keywords.length, 0);
    expect(vault.index.length).toBe(expected);
    expect(server.indexSize).toBe(expected);
  });

  it('gives every posting a distinct pseudorandom address', () => {
    const addresses = new Set(vault.index.map((r) => r.address));
    expect(addresses.size).toBe(vault.index.length);
    for (const r of vault.index) expect(r.address).toMatch(/^[0-9a-f]{64}$/);
  });

  it('never stores two identical posting ciphertexts, even for the same doc id', () => {
    const values = new Set(vault.index.map((r) => toHex(r.value)));
    expect(values.size).toBe(vault.index.length);
  });

  it('encrypts every document body', () => {
    expect(server.documentCount).toBe(CORPUS.length);
    for (const d of vault.documents) {
      // A sealed body must not contain its own plaintext title.
      expect(toHex(d.blob)).not.toContain(toHex(utf8('Q3 payroll')));
    }
  });
});

describe('search correctness', () => {
  it('returns exactly the matching documents for every keyword in the corpus', async () => {
    for (const w of KEYWORDS) {
      expect(await search(w)).toEqual(documentsFor(w));
    }
  });

  it('is deterministic — the same keyword yields the same token every time', async () => {
    const a = await searchToken(keys, 'merger');
    const b = await searchToken(keys, 'merger');
    expect(toHex(a)).toBe(toHex(b));
  });

  it('normalises case and surrounding whitespace to one token', async () => {
    const a = await searchToken(keys, '  SALARY ');
    const b = await searchToken(keys, 'salary');
    expect(toHex(a)).toBe(toHex(b));
    expect(normalize('  SALARY ')).toBe('salary');
  });

  it('returns nothing for a keyword that is not in the corpus', async () => {
    const token = await searchToken(keys, 'unicorn');
    expect(await server.search(token)).toEqual([]);
  });

  it('returns nothing for a random 32-byte token — no key, no results', async () => {
    const fake = crypto.getRandomValues(new Uint8Array(32));
    expect(await server.search(fake)).toEqual([]);
  });

  it('decrypts document bodies only under the right document key', async () => {
    const ids = await search('patent');
    const stored = vault.documents.find((d) => d.id === ids[0]);
    const doc = await openDocument(keys, ids[0]!, stored!.blob);
    expect(doc.title).toBe(CORPUS.find((d) => d.id === ids[0])!.title);
    await expect(openDocument(keys, 'd01', stored!.blob)).rejects.toBeTruthy();
  });
});

describe('fail-closed behaviour', () => {
  it('rejects a posting whose ciphertext was flipped', async () => {
    const token = await searchToken(keys, 'lawsuit');
    const postings = await server.search(token);
    postings[0]!.value[postings[0]!.value.length - 1] ^= 0x01;
    await expect(openPostings(keys, 'lawsuit', postings)).rejects.toBeTruthy();
  });

  it('rejects a posting relocated to a different address', async () => {
    // Associated data binds each posting to its own label, so a server that
    // shuffles rows between labels is caught rather than silently obeyed.
    const token = await searchToken(keys, 'lawsuit');
    const postings = await server.search(token);
    const moved = [{ address: await addressFor(token, 99), value: postings[0]!.value }];
    await expect(openPostings(keys, 'lawsuit', moved)).rejects.toBeTruthy();
  });

  it('rejects a posting forged under a different keyword key', async () => {
    const token = await searchToken(keys, 'lawsuit');
    const address = await addressFor(token, 0);
    const wrongKey = await postingKey(keys, 'merger');
    const forged = [{ address, value: await seal(wrongKey, utf8('d99'), address) }];
    await expect(openPostings(keys, 'lawsuit', forged)).rejects.toBeTruthy();
  });

  it('rejects the whole result rather than returning a partial answer', async () => {
    const token = await searchToken(keys, 'audit');
    const postings = await server.search(token);
    postings[2]!.value[13] ^= 0xff;
    await expect(openPostings(keys, 'audit', postings)).rejects.toBeTruthy();
  });

  it('gives a fresh vault under fresh keys entirely different addresses', async () => {
    const other = await buildVault(generateKeys());
    const overlap = new Set(vault.index.map((r) => r.address));
    expect(other.vault.index.some((r) => overlap.has(r.address))).toBe(false);
  });
});

describe('what the server records', () => {
  it('logs one observation per query, with the result set it returned', async () => {
    const fresh = new SearchServer(vault);
    const token = await searchToken(keys, 'breach');
    const ids = await openPostings(keys, 'breach', await fresh.search(token));
    fresh.fetchDocuments(token, ids);
    const [obs] = fresh.observations();
    expect(obs!.tokenHex).toBe(toHex(token));
    expect(obs!.resultSize).toBe(documentsFor('breach').length);
    expect(obs!.resultIds).toEqual(documentsFor('breach'));
  });

  it('links repeated searches for the same keyword — search-pattern leakage', async () => {
    const fresh = new SearchServer(vault);
    const token = await searchToken(keys, 'merger');
    for (let i = 0; i < 3; i++) {
      fresh.fetchDocuments(token, await openPostings(keys, 'merger', await fresh.search(token)));
    }
    const tokens = new Set(fresh.observations().map((o) => o.tokenHex));
    expect(fresh.observations()).toHaveLength(3);
    expect(tokens.size).toBe(1);
  });

  it('records no keyword anywhere in the ledger', async () => {
    const fresh = new SearchServer(vault);
    const token = await searchToken(keys, 'harassment');
    fresh.fetchDocuments(token, await openPostings(keys, 'harassment', await fresh.search(token)));
    expect(JSON.stringify(fresh.observations())).not.toContain('harassment');
  });
});
