/** Bounded execution of the SCC 2018 Query-Multiplexer/Data-Host split. */
import { open, seal } from '../core/aead';
import { frame, fromUtf8, randomBytes, toHex, utf8 } from '../core/bytes';
import { sha256 } from '../core/prf';
import {
  blindEncryptedIndex,
  gtSearchElement,
  transformMuseTrapdoor,
  type MuseAuthorization,
  type MuseEncryptedIndex,
  type MuseReader,
} from './core';
import {
  applyPackedSelector,
  ciphertextBytes,
  createPackedSelector,
  openPackedResponse,
  type PackedSelector,
  type PaillierKeyPair,
} from './math';
import {
  buildZgbf,
  checkZeroSum,
  mapZgbfPositions,
  ZgbfBuildError,
  ZGBF_DEFAULTS,
  type ZgbfParameters,
} from './zgbf';

const RESULT_AAD_DOMAIN = 'crypto-lab/search-vault/muse/v1/result-id';
const SELECTOR_DIGEST_DOMAIN = 'crypto-lab/search-vault/muse/v1/selector-digest';

export interface QueryManagerMessageView {
  readonly writerId: string;
  readonly transformedElementHex: string;
  readonly selectedPositions: readonly number[];
  readonly selectorDigestHex: string;
}

export interface QueryManagerResponseView {
  readonly responseId: string;
  readonly packedResponseHex: string;
  readonly encryptedWriterIdHex: string;
  readonly positive: boolean;
}

export interface QueryManagerView {
  readonly readerId: string;
  readonly trapdoorHex: string;
  readonly authorizedWriterIds: readonly string[];
  readonly messages: readonly QueryManagerMessageView[];
  readonly shuffledResponses: readonly QueryManagerResponseView[];
  readonly positiveResponseIds: readonly string[];
  readonly resultLength: number;
}

export interface DataHostView {
  readonly readerId: string;
  readonly blindingScalarHex: string;
  readonly incoming: readonly {
    readonly writerId: string;
    readonly encryptedIndexRows: number;
    readonly selectorDigestHex: string;
  }[];
  /** DH knows routing, but not which response QM accepts. */
  readonly responseRouting: readonly {
    readonly responseId: string;
    readonly writerId: string;
  }[];
  readonly responseOrder: readonly string[];
}

export interface ReaderResultView {
  readonly readerId: string;
  readonly writerIds: readonly string[];
}

export interface SplitTrustTrace {
  readonly queryManager: QueryManagerView;
  readonly dataHost: DataHostView;
  readonly reader: ReaderResultView;
  readonly parameters: ZgbfParameters & {
    readonly paillierModulusBits: number;
    readonly sanitizedResponses: boolean;
    readonly shuffledResponses: boolean;
  };
}

interface QueryMessage {
  readonly writerId: string;
  readonly selector: PackedSelector;
  readonly selectorDigestHex: string;
  readonly transformedElementHex: string;
  readonly selectedPositions: readonly number[];
}

interface DataHostResponse {
  readonly responseId: string;
  readonly packedResponse: bigint;
  readonly encryptedWriterId: Uint8Array;
}

export interface SplitTrustOptions {
  readonly zgbf?: Partial<Omit<ZgbfParameters, 'mapNonce'>>;
  readonly sanitizeResponses?: boolean;
  readonly shuffleResponses?: boolean;
  readonly maxBuildAttempts?: number;
  /** Test-only deterministic hook. Learner runs sample fresh xi. */
  readonly blindingScalar?: bigint;
  /** Test-only deterministic map selection. Learner runs sample a fresh u32. */
  readonly mapNonce?: number;
}

export async function runSplitTrustSearch(args: {
  readonly reader: MuseReader;
  readonly keyword: string;
  readonly requestedWriterIds: readonly string[];
  readonly indices: readonly MuseEncryptedIndex[];
  readonly authorizations: readonly MuseAuthorization[];
  readonly paillier: PaillierKeyPair;
  readonly options?: SplitTrustOptions;
}): Promise<SplitTrustTrace> {
  const requested = validateRequestedWriters(args.requestedWriterIds);
  const indexMap = new Map(args.indices.map((index) => [index.writerId, index]));
  if (indexMap.size !== args.indices.length) throw new Error('split-trust writer ids must be unique');
  const authorizationMap = new Map(
    args.authorizations.map((authorization) => [
      authorizationKey(authorization.readerId, authorization.writerId),
      authorization,
    ]),
  );
  if (authorizationMap.size !== args.authorizations.length) {
    throw new Error('split-trust authorizations must be unique');
  }

  // Capability resolution happens before a reader emits a trapdoor or either
  // server records a transcript.
  const work = requested.map((writerId) => {
    const index = indexMap.get(writerId);
    if (!index) throw new Error(`unknown writer index: ${writerId}`);
    const authorization = authorizationMap.get(authorizationKey(args.reader.id, writerId));
    if (!authorization) throw new Error(`reader ${args.reader.id} is not authorized for ${writerId}`);
    return { index, authorization };
  });

  const options = args.options ?? {};
  const maxBuildAttempts = options.maxBuildAttempts ?? 8;
  if (!Number.isSafeInteger(maxBuildAttempts) || maxBuildAttempts <= 0) {
    throw new Error('ZGBF build-attempt bound must be a positive safe integer');
  }
  const slots = options.zgbf?.slots ?? ZGBF_DEFAULTS.slots;
  const hashCount = options.zgbf?.hashCount ?? ZGBF_DEFAULTS.hashCount;
  const shareBytes = options.zgbf?.shareBytes ?? ZGBF_DEFAULTS.shareBytes;
  const sanitizeResponses = options.sanitizeResponses ?? true;
  const shuffleResponses = options.shuffleResponses ?? true;

  for (let attempt = 0; attempt < maxBuildAttempts; attempt++) {
    const issued = args.reader.issueSplitTrustTrapdoor(args.keyword, options.blindingScalar);
    const parameters: ZgbfParameters = {
      slots,
      hashCount,
      shareBytes,
      mapNonce: options.mapNonce ?? randomU32(),
    };
    try {
      const messages: QueryMessage[] = [];
      const preparedFilters = new Map<string, readonly Uint8Array[]>();

      for (const { index, authorization } of work) {
        const transformedElement = await gtSearchElement(
          transformMuseTrapdoor(issued.trapdoor, authorization),
        );
        const selectedPositions = await mapZgbfPositions(transformedElement, parameters);
        const selector = createPackedSelector(
          args.paillier.publicKey,
          slots,
          selectedPositions,
          shareBytes * 8,
        );
        const selectorDigestHex = await selectorDigest(args.paillier, selector);
        messages.push({
          writerId: index.writerId,
          selector,
          selectorDigestHex,
          transformedElementHex: toHex(transformedElement),
          selectedPositions,
        });

        const blindedElements = await Promise.all(
          blindEncryptedIndex(index, issued.dhBlinding).map(gtSearchElement),
        );
        const filter = await buildZgbf(blindedElements, parameters);
        preparedFilters.set(index.writerId, filter.cells);
      }

      const resultKey = args.reader.resultKeyForDataHost();
      const routed: { writerId: string; response: DataHostResponse }[] = [];
      for (const message of messages) {
        const cells = preparedFilters.get(message.writerId);
        if (!cells) throw new Error('data host is missing a prepared writer filter');
        const responseId = toHex(randomBytes(8));
        const packedResponse = applyPackedSelector(
          args.paillier.publicKey,
          message.selector,
          cells,
          sanitizeResponses,
        );
        const encryptedWriterId = await seal(
          resultKey,
          utf8(message.writerId),
          resultAad(args.reader.id, responseId),
        );
        routed.push({
          writerId: message.writerId,
          response: { responseId, packedResponse, encryptedWriterId },
        });
      }

      const responses = routed.map(({ response }) => response);
      if (shuffleResponses) secureShuffle(responses);

      const positiveResponses: DataHostResponse[] = [];
      const responseViews: QueryManagerResponseView[] = [];
      for (const response of responses) {
        const shares = openPackedResponse(
          args.paillier,
          response.packedResponse,
          hashCount,
          shareBytes * 8,
        );
        const positive = checkZeroSum(shares, shareBytes);
        if (positive) positiveResponses.push(response);
        responseViews.push({
          responseId: response.responseId,
          packedResponseHex: toHex(ciphertextBytes(args.paillier.publicKey, response.packedResponse)),
          encryptedWriterIdHex: toHex(response.encryptedWriterId),
          positive,
        });
      }

      const writerIds: string[] = [];
      for (const response of positiveResponses) {
        writerIds.push(
          fromUtf8(
            await open(
              args.reader.resultKeyForOpen(),
              response.encryptedWriterId,
              resultAad(args.reader.id, response.responseId),
            ),
          ),
        );
      }

      return {
        queryManager: {
          readerId: args.reader.id,
          trapdoorHex: toHex(issued.trapdoor.bytes),
          authorizedWriterIds: [...requested],
          messages: messages.map((message) => ({
            writerId: message.writerId,
            transformedElementHex: message.transformedElementHex,
            selectedPositions: [...message.selectedPositions],
            selectorDigestHex: message.selectorDigestHex,
          })),
          shuffledResponses: responseViews,
          positiveResponseIds: positiveResponses.map((response) => response.responseId),
          resultLength: positiveResponses.length,
        },
        dataHost: {
          readerId: args.reader.id,
          blindingScalarHex: issued.dhBlinding.toString(16),
          incoming: messages.map((message) => ({
            writerId: message.writerId,
            encryptedIndexRows: indexMap.get(message.writerId)!.rows.length,
            selectorDigestHex: message.selectorDigestHex,
          })),
          responseRouting: routed.map(({ writerId, response }) => ({
            responseId: response.responseId,
            writerId,
          })),
          responseOrder: responses.map((response) => response.responseId),
        },
        reader: { readerId: args.reader.id, writerIds },
        parameters: {
          ...parameters,
          paillierModulusBits: args.paillier.publicKey.modulusBits,
          sanitizedResponses: sanitizeResponses,
          shuffledResponses: shuffleResponses,
        },
      };
    } catch (error) {
      if (!(error instanceof ZgbfBuildError) || options.blindingScalar !== undefined) throw error;
      // The paper's Build algorithm aborts when all mapped cells were already
      // occupied. Discard this pre-transcript attempt and retry with fresh xi.
    }
  }
  throw new Error(`ZGBF build aborted ${maxBuildAttempts} consecutive times`);
}

export function combineSplitTrustViews(trace: SplitTrustTrace): {
  readonly responseId: string;
  readonly writerId: string;
  readonly positive: boolean;
}[] {
  const positive = new Set(trace.queryManager.positiveResponseIds);
  return trace.dataHost.responseRouting.map((route) => ({
    ...route,
    positive: positive.has(route.responseId),
  }));
}

async function selectorDigest(
  paillier: PaillierKeyPair,
  selector: PackedSelector,
): Promise<string> {
  const digest = await sha256(
    frame(
      utf8(SELECTOR_DIGEST_DOMAIN),
      ...selector.ciphertexts.map((ciphertext) =>
        ciphertextBytes(paillier.publicKey, ciphertext),
      ),
    ),
  );
  return toHex(digest);
}

function resultAad(readerId: string, responseId: string): Uint8Array {
  return frame(utf8(RESULT_AAD_DOMAIN), utf8(readerId), utf8(responseId));
}

function authorizationKey(readerId: string, writerId: string): string {
  return `${readerId}\u0000${writerId}`;
}

function validateRequestedWriters(writerIds: readonly string[]): string[] {
  if (writerIds.length === 0) throw new Error('a query must name at least one writer index');
  if (new Set(writerIds).size !== writerIds.length) throw new Error('requested writer ids must be unique');
  return [...writerIds];
}

function randomU32(): number {
  const bytes = randomBytes(4);
  return bytes[0]! * 0x1000000 + bytes[1]! * 0x10000 + bytes[2]! * 0x100 + bytes[3]!;
}

function secureShuffle<T>(values: T[]): void {
  for (let end = values.length - 1; end > 0; end--) {
    const limit = Math.floor(0x100000000 / (end + 1)) * (end + 1);
    let candidate: number;
    do candidate = randomU32(); while (candidate >= limit);
    const index = candidate % (end + 1);
    [values[end], values[index]] = [values[index]!, values[end]!];
  }
}
