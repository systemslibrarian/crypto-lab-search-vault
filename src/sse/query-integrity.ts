import { toHex, utf8 } from '../core/bytes';
import { sha256 } from '../core/prf';
import { addressFor, searchToken } from './client';
import type { EncryptedVault, VaultKeys } from './types';

export type QueryReplyMode = 'honest' | 'omit' | 'fabricate' | 'stale';

export interface QueryCheckpoint {
  tokenHex: string;
  snapshotId: string;
  expectedCount: number;
  digestHex: string;
}

export interface QueryVerification {
  ok: boolean;
  reason: 'verified' | 'stale-snapshot' | 'count-mismatch' | 'digest-mismatch';
  expectedCount: number;
  actualCount: number;
  expectedSnapshotId: string;
  actualSnapshotId: string;
}

export interface QueryReply {
  snapshotId: string;
  postings: Array<{ address: Uint8Array; value: Uint8Array }>;
}

/**
 * Hash the exact ordered answer the client expects: each derived address plus
 * the authenticated ciphertext stored there. This is a teaching checkpoint,
 * not a claim of a general verifiable-SSE construction.
 */
export async function digestQueryAnswer(
  postings: Array<{ address: Uint8Array; value: Uint8Array }>,
): Promise<string> {
  const canonical = postings
    .map((p) => `${toHex(p.address)}:${toHex(p.value)}`)
    .join('\n');
  return toHex(await sha256(utf8(canonical)));
}

/**
 * Build client-side checkpoints from the encrypted snapshot that was actually
 * produced. A checkpoint binds one opaque search token to a snapshot id, the
 * full answer length, and a digest of the complete ordered encrypted answer.
 */
export async function buildQueryCheckpoints(
  keys: VaultKeys,
  vault: EncryptedVault,
  keywords: readonly string[],
  snapshotId: string,
): Promise<Map<string, QueryCheckpoint>> {
  const store = new Map(vault.index.map((row) => [row.address, row.value] as const));
  const out = new Map<string, QueryCheckpoint>();

  for (const keyword of keywords) {
    const token = await searchToken(keys, keyword);
    const postings: Array<{ address: Uint8Array; value: Uint8Array }> = [];
    for (let i = 0; ; i++) {
      const address = await addressFor(token, i);
      const value = store.get(toHex(address));
      if (!value) break;
      postings.push({ address, value });
    }

    const tokenHex = toHex(token);
    out.set(tokenHex, {
      tokenHex,
      snapshotId,
      expectedCount: postings.length,
      digestHex: await digestQueryAnswer(postings),
    });
  }

  return out;
}

/** Verify completeness and freshness against a client-retained checkpoint. */
export async function verifyQueryReply(
  checkpoint: QueryCheckpoint,
  reply: QueryReply,
): Promise<QueryVerification> {
  if (reply.snapshotId !== checkpoint.snapshotId) {
    return {
      ok: false,
      reason: 'stale-snapshot',
      expectedCount: checkpoint.expectedCount,
      actualCount: reply.postings.length,
      expectedSnapshotId: checkpoint.snapshotId,
      actualSnapshotId: reply.snapshotId,
    };
  }

  if (reply.postings.length !== checkpoint.expectedCount) {
    return {
      ok: false,
      reason: 'count-mismatch',
      expectedCount: checkpoint.expectedCount,
      actualCount: reply.postings.length,
      expectedSnapshotId: checkpoint.snapshotId,
      actualSnapshotId: reply.snapshotId,
    };
  }

  const digestHex = await digestQueryAnswer(reply.postings);
  return {
    ok: digestHex === checkpoint.digestHex,
    reason: digestHex === checkpoint.digestHex ? 'verified' : 'digest-mismatch',
    expectedCount: checkpoint.expectedCount,
    actualCount: reply.postings.length,
    expectedSnapshotId: checkpoint.snapshotId,
    actualSnapshotId: reply.snapshotId,
  };
}

/**
 * Produce explicit dishonest-server cases for the learner exercise. The normal
 * SearchServer remains honest-but-curious; only this function alters a copy of
 * its answer so the integrity guarantees can be compared side by side.
 */
export function makeIntegrityTrialReply(
  postings: Array<{ address: Uint8Array; value: Uint8Array }>,
  snapshotId: string,
  mode: QueryReplyMode,
): QueryReply {
  const copied = postings.map((p) => ({
    address: p.address.slice(),
    value: p.value.slice(),
  }));

  if (mode === 'omit' && copied.length > 0) {
    copied.pop();
  } else if (mode === 'fabricate' && copied.length > 0) {
    const forged = copied[0]!;
    forged.value[forged.value.length - 1] ^= 0x01;
  }

  return {
    snapshotId: mode === 'stale' ? `previous:${snapshotId}` : snapshotId,
    postings: copied,
  };
}
