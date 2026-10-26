import { describe, expect, it } from 'vitest';
import { queryNode, rowNode, runKeywordAccessPatternAttack } from './attack';
import {
  decodeGt,
  IterativeMuseServer,
  MuseReader,
  MuseWriter,
  transformMuseTrapdoor,
} from './core';

describe('pairing-based multi-user exact search', () => {
  it('executes the paper’s delegation equation against the stored GT value', () => {
    const writer = new MuseWriter('writer-a', ['audit', 'budget'], 7n);
    const reader = new MuseReader('reader-a', 11n, new Uint8Array(32).fill(0x44));
    const index = writer.encryptIndex();
    const authorization = writer.delegate(reader.publicKey);
    const transformed = transformMuseTrapdoor(
      reader.issueSingleServerTrapdoor('audit'),
      authorization,
    );
    expect(index.rows).toHaveLength(2);
    expect(decodeGt(index.rows[0]!.gtBytes, 'test row')).toEqual(transformed);
    expect(decodeGt(index.rows[1]!.gtBytes, 'test row')).not.toEqual(transformed);
  });

  it('searches only authorized writer indexes and rejects a mixed request atomically', () => {
    const writerA = new MuseWriter('writer-a', ['audit', 'budget'], 7n);
    const writerB = new MuseWriter('writer-b', ['audit', 'lawsuit'], 13n);
    const reader = new MuseReader('reader-a', 11n, new Uint8Array(32).fill(0x44));
    const server = new IterativeMuseServer(
      [writerA.encryptIndex(), writerB.encryptIndex()],
      [writerA.delegate(reader.publicKey)],
    );
    const trapdoor = reader.issueSingleServerTrapdoor('audit');

    expect(() => server.search(trapdoor, ['writer-a', 'writer-b'])).toThrow(/not authorized/);
    expect(server.observations()).toHaveLength(0);
    const result = server.search(trapdoor, ['writer-a']);
    expect(result.matchedWriterIds).toEqual(['writer-a']);
    expect(result.testedRows).toBe(2);
    expect(server.observations()).toHaveLength(1);
  });

  it('binds an authorization delta to its named reader and rejects malformed encodings', () => {
    const writer = new MuseWriter('writer-a', ['audit'], 7n);
    const alice = new MuseReader('reader-a', 11n, new Uint8Array(32).fill(1));
    const bob = new MuseReader('reader-b', 19n, new Uint8Array(32).fill(2));
    const authorization = writer.delegate(alice.publicKey);
    expect(() => transformMuseTrapdoor(bob.issueSingleServerTrapdoor('audit'), authorization)).toThrow(
      /different reader/,
    );
    expect(() =>
      transformMuseTrapdoor(alice.issueSingleServerTrapdoor('audit'), {
        ...authorization,
        deltaBytes: authorization.deltaBytes.slice(1),
      }),
    ).toThrow(/96 bytes/);
  });

  it('rejects zero/out-of-range scalars and unsupported keyword syntax', () => {
    expect(() => new MuseWriter('writer-a', ['audit'], 0n)).toThrow(/writer scalar/);
    expect(() => new MuseReader('reader-a', 0n)).toThrow(/reader scalar/);
    expect(() => new MuseWriter('writer-a', ['audit 2026'], 7n)).toThrow(/ASCII letters/);
  });
});

describe('keyword-access-pattern attack', () => {
  it('propagates one colluding label to another reader and unauthorized writer index', () => {
    const writerA = new MuseWriter('writer-a', ['audit', 'budget'], 7n);
    const writerB = new MuseWriter('writer-b', ['audit', 'lawsuit'], 13n);
    const writerC = new MuseWriter('writer-c', ['breach', 'forensic'], 17n);
    const known = new MuseReader('reader-known', 11n, new Uint8Array(32).fill(1));
    const target = new MuseReader('reader-target', 19n, new Uint8Array(32).fill(2));
    const server = new IterativeMuseServer(
      [writerA.encryptIndex(), writerB.encryptIndex(), writerC.encryptIndex()],
      [
        writerA.delegate(known.publicKey),
        writerA.delegate(target.publicKey),
        writerB.delegate(target.publicKey),
        writerC.delegate(target.publicKey),
      ],
    );
    const knownResult = server.search(known.issueSingleServerTrapdoor('audit'), ['writer-a']);
    const targetResult = server.search(target.issueSingleServerTrapdoor('audit'), [
      'writer-a',
      'writer-b',
      'writer-c',
    ]);
    const changedResult = server.search(target.issueSingleServerTrapdoor('breach'), [
      'writer-a',
      'writer-b',
      'writer-c',
    ]);
    const transcript = server.observations();
    const attack = runKeywordAccessPatternAttack(transcript, [
      { queryId: knownResult.queryId, keyword: 'audit' },
    ]);
    const recovered = new Set(attack.recovered.map((entry) => entry.nodeId));

    expect(recovered).toContain(queryNode(targetResult.queryId));
    expect(
      targetResult.matches
        .filter((match) => match.writerId === 'writer-b')
        .every((match) => recovered.has(rowNode(match.rowId))),
    ).toBe(true);
    expect(recovered).not.toContain(queryNode(changedResult.queryId));
    expect(JSON.stringify(transcript)).not.toContain('"keyword"');
    expect(JSON.stringify(transcript)).not.toContain('audit');
  });

  it('refuses contradictory labels and labels for absent transcript nodes', () => {
    const observation = {
      queryId: 'query-1',
      readerId: 'reader-a',
      requestedWriterIds: ['writer-a'],
      trapdoorHex: '00',
      testedRows: 1,
      matches: [{ writerId: 'writer-a', rowId: 'writer-a:row-1' }],
    } as const;
    expect(() =>
      runKeywordAccessPatternAttack([observation], [
        { queryId: 'query-1', keyword: 'audit' },
        { queryId: 'query-1', keyword: 'breach' },
      ]),
    ).toThrow(/contradictory/);
    expect(() =>
      runKeywordAccessPatternAttack([observation], [
        { queryId: 'query-missing', keyword: 'audit' },
      ]),
    ).toThrow(/missing query/);
  });
});
