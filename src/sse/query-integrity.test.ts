import { beforeAll, describe, expect, it } from 'vitest';
import { randomBytes, toHex } from '../core/bytes';
import { buildVault, generateKeys, openPostings, searchToken } from './client';
import { CORPUS, KEYWORDS, documentsFor } from './corpus';
import {
  buildQueryCheckpoints,
  makeIntegrityTrialReply,
  verifyQueryReply,
} from './query-integrity';
import { SearchServer } from './server';
import type { EncryptedVault, VaultKeys } from './types';
import type { QueryCheckpoint } from './query-integrity';

let keys: VaultKeys;
let vault: EncryptedVault;
let server: SearchServer;
let snapshotId: string;
let checkpoints: Map<string, QueryCheckpoint>;

beforeAll(async () => {
  keys = generateKeys();
  ({ vault } = await buildVault(keys, CORPUS));
  server = new SearchServer(vault);
  snapshotId = toHex(randomBytes(16));
  checkpoints = await buildQueryCheckpoints(keys, vault, KEYWORDS, snapshotId);
});

async function caseFor(keyword: string, mode: 'honest' | 'omit' | 'fabricate' | 'stale') {
  const token = await searchToken(keys, keyword);
  const checkpoint = checkpoints.get(toHex(token));
  if (!checkpoint) throw new Error(`missing checkpoint for ${keyword}`);
  const postings = await server.search(token);
  const reply = makeIntegrityTrialReply(postings, snapshotId, mode);
  return { token, checkpoint, reply, verification: await verifyQueryReply(checkpoint, reply) };
}

describe('query-result completeness and freshness checkpoint', () => {
  it('records the complete answer size for every indexed keyword', async () => {
    expect(checkpoints.size).toBe(KEYWORDS.length);
    for (const keyword of KEYWORDS) {
      const token = await searchToken(keys, keyword);
      const checkpoint = checkpoints.get(toHex(token));
      expect(checkpoint?.expectedCount).toBe(documentsFor(keyword).length);
      expect(checkpoint?.snapshotId).toBe(snapshotId);
      expect(checkpoint?.digestHex).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it('accepts the honest answer from the current snapshot', async () => {
    const { verification } = await caseFor('breach', 'honest');
    expect(verification).toMatchObject({ ok: true, reason: 'verified' });
  });

  it('detects an omitted authentic posting even though every returned posting still authenticates', async () => {
    const { reply, verification } = await caseFor('breach', 'omit');
    expect(await openPostings(keys, 'breach', reply.postings)).toHaveLength(
      documentsFor('breach').length - 1,
    );
    expect(verification).toMatchObject({
      ok: false,
      reason: 'count-mismatch',
      expectedCount: documentsFor('breach').length,
      actualCount: documentsFor('breach').length - 1,
    });
  });

  it('detects a same-size fabricated answer and AES-GCM independently rejects the forged posting', async () => {
    const { reply, verification } = await caseFor('breach', 'fabricate');
    expect(verification).toMatchObject({ ok: false, reason: 'digest-mismatch' });
    await expect(openPostings(keys, 'breach', reply.postings)).rejects.toBeTruthy();
  });

  it('rejects a cryptographically authentic answer labelled as an older snapshot', async () => {
    const { reply, verification } = await caseFor('breach', 'stale');
    expect(await openPostings(keys, 'breach', reply.postings)).toEqual(documentsFor('breach'));
    expect(verification).toMatchObject({ ok: false, reason: 'stale-snapshot' });
    expect(verification.actualSnapshotId).not.toBe(snapshotId);
  });
});
