import { describe, expect, it } from 'vitest';
import { open } from '../core/aead';
import { frame, fromHex, fromUtf8, utf8 } from '../core/bytes';
import { MuseReader, MuseWriter } from './core';
import { derivePaillierKeyPair } from './math';
import { combineSplitTrustViews, runSplitTrustSearch } from './split';

const P = BigInt('0xCF1ADEE9E745BD6B91DD865E6249024150C52438BC314F4135E12C56B122EDED');
const Q = BigInt('0xEEBFFF9F6C78D07EF708918FC946C930B1DA87D2848B86C7A951E779BFC3AA27');

function fixture() {
  const writers = [
    new MuseWriter('writer-a', ['audit', 'budget'], 7n),
    new MuseWriter('writer-b', ['audit', 'lawsuit'], 13n),
    new MuseWriter('writer-c', ['breach', 'forensic'], 17n),
  ];
  const target = new MuseReader('reader-target', 19n, new Uint8Array(32).fill(0x33));
  return {
    writers,
    target,
    indices: writers.map((writer) => writer.encryptIndex()),
    authorizations: writers.map((writer) => writer.delegate(target.publicKey)),
    paillier: derivePaillierKeyPair(P, Q),
  };
}

describe('split-trust MUSE adaptation', () => {
  it('returns the independently expected writers while separating QM and DH views', async () => {
    const state = fixture();
    const trace = await runSplitTrustSearch({
      reader: state.target,
      keyword: 'audit',
      requestedWriterIds: ['writer-a', 'writer-b', 'writer-c'],
      indices: state.indices,
      authorizations: state.authorizations,
      paillier: state.paillier,
      options: {
        zgbf: { slots: 32, hashCount: 3, shareBytes: 4 },
        blindingScalar: 23n,
        mapNonce: 7,
      },
    });

    expect([...trace.reader.writerIds].sort()).toEqual(['writer-a', 'writer-b']);
    expect(trace.queryManager.resultLength).toBe(2);
    expect(trace.queryManager.messages).toHaveLength(3);
    expect(trace.dataHost.incoming).toHaveLength(3);
    expect(trace.queryManager.shuffledResponses).toHaveLength(3);
    expect(trace.parameters.sanitizedResponses).toBe(true);
    expect(trace.parameters.shuffledResponses).toBe(true);
    expect(trace.queryManager.trapdoorHex).not.toContain('audit');
    expect(JSON.stringify(trace.queryManager)).not.toContain('responseRouting');
    expect(JSON.stringify(trace.dataHost)).not.toContain('"positive"');
    expect(JSON.stringify(trace.dataHost)).not.toContain('resultLength');

    const combined = combineSplitTrustViews(trace);
    expect(combined.filter((row) => row.positive).map((row) => row.writerId).sort()).toEqual([
      'writer-a',
      'writer-b',
    ]);
  });

  it('fresh xi and Paillier randomness change repeated preparations', async () => {
    const state = fixture();
    const common = {
      reader: state.target,
      keyword: 'audit',
      requestedWriterIds: ['writer-a', 'writer-b', 'writer-c'],
      indices: state.indices,
      authorizations: state.authorizations,
      paillier: state.paillier,
    } as const;
    const first = await runSplitTrustSearch({
      ...common,
      options: {
        zgbf: { slots: 32, hashCount: 3, shareBytes: 4 },
        blindingScalar: 23n,
        mapNonce: 7,
      },
    });
    const repeat = await runSplitTrustSearch({
      ...common,
      options: {
        zgbf: { slots: 32, hashCount: 3, shareBytes: 4 },
        blindingScalar: 29n,
        mapNonce: 8,
      },
    });

    expect(repeat.queryManager.trapdoorHex).not.toBe(first.queryManager.trapdoorHex);
    for (const firstMessage of first.queryManager.messages) {
      const secondMessage = repeat.queryManager.messages.find(
        (message) => message.writerId === firstMessage.writerId,
      );
      expect(secondMessage?.transformedElementHex).not.toBe(firstMessage.transformedElementHex);
      expect(secondMessage?.selectorDigestHex).not.toBe(firstMessage.selectorDigestHex);
    }
  });

  it('rejects an unauthorized mixed request before constructing either server view', async () => {
    const state = fixture();
    const outsider = new MuseReader('reader-outsider', 31n, new Uint8Array(32).fill(0x55));
    await expect(
      runSplitTrustSearch({
        reader: outsider,
        keyword: 'audit',
        requestedWriterIds: ['writer-a'],
        indices: state.indices,
        authorizations: state.authorizations,
        paillier: state.paillier,
      }),
    ).rejects.toThrow(/not authorized/);
  });

  it('binds each encrypted writer id to its reader and response context', async () => {
    const state = fixture();
    const trace = await runSplitTrustSearch({
      reader: state.target,
      keyword: 'audit',
      requestedWriterIds: ['writer-a', 'writer-b', 'writer-c'],
      indices: state.indices,
      authorizations: state.authorizations,
      paillier: state.paillier,
      options: {
        zgbf: { slots: 32, hashCount: 3, shareBytes: 4 },
        blindingScalar: 23n,
        mapNonce: 7,
      },
    });
    const key = state.target.resultKeyForOpen();
    for (const response of trace.queryManager.shuffledResponses) {
      const route = trace.dataHost.responseRouting.find(
        (candidate) => candidate.responseId === response.responseId,
      );
      expect(route).toBeDefined();
      const aad = frame(
        utf8('crypto-lab/search-vault/muse/v1/result-id'),
        utf8('reader-target'),
        utf8(response.responseId),
      );
      expect(fromUtf8(await open(key, fromHex(response.encryptedWriterIdHex), aad))).toBe(
        route!.writerId,
      );
      const changed = fromHex(response.encryptedWriterIdHex);
      changed[changed.length - 1] ^= 1;
      await expect(open(key, changed, aad)).rejects.toThrow();
      const wrongAad = frame(
        utf8('crypto-lab/search-vault/muse/v1/result-id'),
        utf8('reader-target'),
        utf8(`${response.responseId}-other`),
      );
      await expect(open(key, fromHex(response.encryptedWriterIdHex), wrongAad)).rejects.toThrow();
    }
  });

  it('makes disabled sanitization and disabled shuffling explicit parameters', async () => {
    const state = fixture();
    const trace = await runSplitTrustSearch({
      reader: state.target,
      keyword: 'audit',
      requestedWriterIds: ['writer-a', 'writer-b'],
      indices: state.indices,
      authorizations: state.authorizations,
      paillier: state.paillier,
      options: {
        zgbf: { slots: 16, hashCount: 3, shareBytes: 4 },
        blindingScalar: 23n,
        mapNonce: 7,
        sanitizeResponses: false,
        shuffleResponses: false,
      },
    });
    expect(trace.parameters.sanitizedResponses).toBe(false);
    expect(trace.parameters.shuffledResponses).toBe(false);
    expect(trace.dataHost.responseOrder).toEqual(
      trace.dataHost.responseRouting.map((route) => route.responseId),
    );
  });
});
