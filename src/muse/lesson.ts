/** End-to-end L-R-08 scenario: roles, KWAP attack, and split-trust comparison. */
import { rowNode, runKeywordAccessPatternAttack, type KeywordAccessAttackResult } from './attack';
import {
  IterativeMuseServer,
  MuseReader,
  MuseWriter,
  normalizeMuseKeyword,
  type MuseAuthorization,
  type MuseEncryptedIndex,
  type SingleServerResult,
} from './core';
import { generatePaillierKeyPair, type PaillierKeyPair } from './math';
import {
  combineSplitTrustViews,
  runSplitTrustSearch,
  type SplitTrustTrace,
} from './split';
import { MUSE_SCENARIO } from './scenario';

export interface RejectedOperation {
  readonly operation: string;
  readonly actorId: string;
  readonly reason: string;
  readonly transcriptCountBefore: number;
  readonly transcriptCountAfter: number;
}

export interface MuseLessonRun {
  readonly singleServer: {
    readonly knownQuery: SingleServerResult;
    readonly targetQuery: SingleServerResult;
    readonly changedTargetQuery: SingleServerResult;
    readonly attack: KeywordAccessAttackResult;
    readonly recoveredTarget: boolean;
    readonly crossedAuthorizationBoundary: boolean;
    readonly changedTargetStayedUnknown: boolean;
    readonly transcript: ReturnType<IterativeMuseServer['observations']>;
  };
  readonly rejected: readonly RejectedOperation[];
  readonly splitTrust: {
    readonly first: SplitTrustTrace;
    readonly repeat: SplitTrustTrace;
    readonly oracleWriterIds: readonly string[];
    readonly falsePositiveWriterIds: readonly string[];
    readonly falseNegativeWriterIds: readonly string[];
    readonly freshTrapdoor: boolean;
    readonly freshSelectorCiphertexts: boolean;
    readonly combinedViews: ReturnType<typeof combineSplitTrustViews>;
  };
}

export class MuseAccessController {
  readonly #readers: ReadonlySet<string>;
  readonly #writers: ReadonlySet<string>;

  constructor(readerIds: readonly string[], writerIds: readonly string[]) {
    this.#readers = new Set(readerIds);
    this.#writers = new Set(writerIds);
    if (this.#readers.size !== readerIds.length || this.#writers.size !== writerIds.length) {
      throw new Error('principal ids must be unique within each role');
    }
    for (const id of this.#readers) {
      if (this.#writers.has(id)) throw new Error('one teaching principal cannot hold both roles');
    }
  }

  assertCanUpload(actorId: string): void {
    if (!this.#writers.has(actorId)) throw new Error(`${actorId} does not hold the writer role`);
  }

  assertCanQuery(actorId: string): void {
    if (!this.#readers.has(actorId)) throw new Error(`${actorId} does not hold the reader role`);
  }
}

export class MuseLesson {
  readonly #readers: ReadonlyMap<string, MuseReader>;
  readonly #indices: readonly MuseEncryptedIndex[];
  readonly #authorizations: readonly MuseAuthorization[];
  readonly #paillier: PaillierKeyPair;
  readonly #roles: MuseAccessController;

  private constructor(args: {
    readers: ReadonlyMap<string, MuseReader>;
    indices: readonly MuseEncryptedIndex[];
    authorizations: readonly MuseAuthorization[];
    paillier: PaillierKeyPair;
    roles: MuseAccessController;
  }) {
    this.#readers = args.readers;
    this.#indices = args.indices;
    this.#authorizations = args.authorizations;
    this.#paillier = args.paillier;
    this.#roles = args.roles;
  }

  static async create(): Promise<MuseLesson> {
    const writers = new Map<string, MuseWriter>(
      MUSE_SCENARIO.writers.map((entry) => [
        entry.id,
        new MuseWriter(entry.id, entry.keywords),
      ]),
    );
    const readers = new Map<string, MuseReader>(
      MUSE_SCENARIO.readers.map((entry) => [entry.id, new MuseReader(entry.id)]),
    );
    const indices = [...writers.values()].map((writer) => writer.encryptIndex());
    const authorizations: MuseAuthorization[] = [];
    for (const [readerId, writerIds] of Object.entries(MUSE_SCENARIO.authorizations)) {
      const reader = readers.get(readerId);
      if (!reader) throw new Error(`scenario reader missing: ${readerId}`);
      for (const writerId of writerIds) {
        const writer = writers.get(writerId);
        if (!writer) throw new Error(`scenario writer missing: ${writerId}`);
        authorizations.push(writer.delegate(reader.publicKey));
      }
    }
    return new MuseLesson({
      readers,
      indices,
      authorizations,
      paillier: await generatePaillierKeyPair(1024),
      roles: new MuseAccessController([...readers.keys()], [...writers.keys()]),
    });
  }

  async run(): Promise<MuseLessonRun> {
    const server = new IterativeMuseServer(this.#indices, this.#authorizations);
    const rejected: RejectedOperation[] = [];

    rejected.push(this.#rejectRoleOperation(server, 'reader-known', 'upload writer index', () => {
      this.#roles.assertCanUpload('reader-known');
    }));
    rejected.push(this.#rejectRoleOperation(server, 'writer-a', 'issue reader query', () => {
      this.#roles.assertCanQuery('writer-a');
    }));

    const knownReader = this.#reader('reader-known');
    const targetReader = this.#reader('reader-target');
    rejected.push(this.#rejectRoleOperation(server, knownReader.id, 'search writer-b', () => {
      this.#roles.assertCanQuery(knownReader.id);
      server.search(knownReader.issueSingleServerTrapdoor('audit'), ['writer-b']);
    }));

    this.#roles.assertCanQuery(knownReader.id);
    const knownQuery = server.search(
      knownReader.issueSingleServerTrapdoor('audit'),
      ['writer-a'],
    );
    this.#roles.assertCanQuery(targetReader.id);
    const targetWriters = [...MUSE_SCENARIO.authorizations['reader-target']];
    const targetQuery = server.search(
      targetReader.issueSingleServerTrapdoor('audit'),
      targetWriters,
    );
    const changedTargetQuery = server.search(
      targetReader.issueSingleServerTrapdoor('breach'),
      targetWriters,
    );

    const attack = runKeywordAccessPatternAttack(server.observations(), [
      { queryId: knownQuery.queryId, keyword: 'audit' },
    ]);
    const targetNode = `query/${targetQuery.queryId}`;
    const changedNode = `query/${changedTargetQuery.queryId}`;
    const writerBRows = new Set(
      targetQuery.matches
        .filter((match) => match.writerId === 'writer-b')
        .map((match) => rowNode(match.rowId)),
    );
    const recoveredNodes = new Set(
      attack.recovered
        .filter((recovered) => recovered.keyword === 'audit')
        .map((recovered) => recovered.nodeId),
    );

    const splitArgs = {
      reader: targetReader,
      keyword: 'audit',
      requestedWriterIds: targetWriters,
      indices: this.#indices,
      authorizations: this.#authorizations,
      paillier: this.#paillier,
    } as const;
    const first = await runSplitTrustSearch(splitArgs);
    const repeat = await runSplitTrustSearch(splitArgs);
    const oracleWriterIds = this.#oracleWriters('reader-target', 'audit');
    const actual = new Set(first.reader.writerIds);
    const oracle = new Set(oracleWriterIds);

    return {
      singleServer: {
        knownQuery,
        targetQuery,
        changedTargetQuery,
        attack,
        recoveredTarget: recoveredNodes.has(targetNode),
        crossedAuthorizationBoundary: [...writerBRows].some((node) => recoveredNodes.has(node)),
        changedTargetStayedUnknown: !recoveredNodes.has(changedNode),
        transcript: server.observations(),
      },
      rejected,
      splitTrust: {
        first,
        repeat,
        oracleWriterIds,
        falsePositiveWriterIds: first.reader.writerIds.filter((writerId) => !oracle.has(writerId)),
        falseNegativeWriterIds: oracleWriterIds.filter((writerId) => !actual.has(writerId)),
        freshTrapdoor: first.queryManager.trapdoorHex !== repeat.queryManager.trapdoorHex,
        freshSelectorCiphertexts: first.queryManager.messages.every((message) => {
          const repeated = repeat.queryManager.messages.find((row) => row.writerId === message.writerId);
          return repeated !== undefined && repeated.selectorDigestHex !== message.selectorDigestHex;
        }),
        combinedViews: combineSplitTrustViews(first),
      },
    };
  }

  #reader(id: string): MuseReader {
    const reader = this.#readers.get(id);
    if (!reader) throw new Error(`unknown scenario reader: ${id}`);
    return reader;
  }

  #oracleWriters(readerId: keyof typeof MUSE_SCENARIO.authorizations, keyword: string): string[] {
    const normalized = normalizeMuseKeyword(keyword);
    return MUSE_SCENARIO.authorizations[readerId].filter((writerId) => {
      const writer = MUSE_SCENARIO.writers.find((candidate) => candidate.id === writerId);
      return (writer?.keywords as readonly string[] | undefined)?.includes(normalized) ?? false;
    });
  }

  #rejectRoleOperation(
    server: IterativeMuseServer,
    actorId: string,
    operation: string,
    action: () => void,
  ): RejectedOperation {
    const before = server.observations().length;
    let reason = '';
    try {
      action();
    } catch (error) {
      reason = error instanceof Error ? error.message : String(error);
    }
    if (!reason) throw new Error(`expected operation to be rejected: ${operation}`);
    const after = server.observations().length;
    if (after !== before) throw new Error('rejected operation altered the server transcript');
    return {
      operation,
      actorId,
      reason,
      transcriptCountBefore: before,
      transcriptCountAfter: after,
    };
  }
}
