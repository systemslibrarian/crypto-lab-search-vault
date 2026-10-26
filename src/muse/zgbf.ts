/** Zero-sum garbled Bloom filter from Van Rompay–Molva–Önen §4.2. */
import { frame, randomBytes, u32be, utf8 } from '../core/bytes';
import { sha256 } from '../core/prf';

export const ZGBF_DEFAULTS = {
  slots: 64,
  hashCount: 3,
  shareBytes: 16,
} as const;

export const ZGBF_MAP_DOMAIN = 'crypto-lab/search-vault/muse/v1/zgbf-map';

export class ZgbfBuildError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ZgbfBuildError';
  }
}

export interface ZgbfParameters {
  readonly slots: number;
  readonly hashCount: number;
  readonly shareBytes: number;
  readonly mapNonce: number;
}

export interface Zgbf {
  readonly parameters: ZgbfParameters;
  readonly cells: readonly Uint8Array[];
}

export async function mapZgbfPositions(
  element: Uint8Array,
  parameters: Pick<ZgbfParameters, 'slots' | 'hashCount' | 'mapNonce'>,
): Promise<number[]> {
  assertMapParameters(parameters);
  if (element.length === 0) throw new Error('ZGBF elements must not be empty');
  const positions: number[] = [];
  for (let hashIndex = 0; hashIndex < parameters.hashCount; hashIndex++) {
    let retry = 0;
    while (true) {
      const digest = await sha256(
        frame(
          utf8(ZGBF_MAP_DOMAIN),
          u32be(parameters.mapNonce),
          u32be(hashIndex),
          u32be(retry),
          element,
        ),
      );
      const candidate =
        digest[0]! * 0x1000000 +
        digest[1]! * 0x10000 +
        digest[2]! * 0x100 +
        digest[3]!;
      const unbiasedLimit = Math.floor(0x100000000 / parameters.slots) * parameters.slots;
      if (candidate < unbiasedLimit) {
        const position = candidate % parameters.slots;
        if (!positions.includes(position)) {
          positions.push(position);
          break;
        }
      }
      retry += 1;
      if (retry > 0xffff) throw new Error('could not derive distinct ZGBF positions');
    }
  }
  return positions;
}

export async function buildZgbf(
  elements: readonly Uint8Array[],
  parameters: ZgbfParameters,
  randomShare: (length: number) => Uint8Array = randomBytes,
): Promise<Zgbf> {
  assertParameters(parameters);
  if (elements.length === 0) throw new Error('ZGBF requires at least one element');
  const cells: (Uint8Array | undefined)[] = Array.from({ length: parameters.slots });

  for (const element of elements) {
    const positions = await mapZgbfPositions(element, parameters);
    const pivot = positions.find((position) => cells[position] === undefined);
    if (pivot === undefined) {
      throw new ZgbfBuildError('every mapped position was already occupied');
    }
    for (const position of positions) {
      if (position !== pivot && cells[position] === undefined) {
        cells[position] = checkedRandomShare(randomShare, parameters.shareBytes);
      }
    }
    const otherShares = positions
      .filter((position) => position !== pivot)
      .map((position) => cells[position]!);
    cells[pivot] = xorShares(otherShares, parameters.shareBytes);
  }

  for (let index = 0; index < cells.length; index++) {
    if (cells[index] === undefined) {
      cells[index] = checkedRandomShare(randomShare, parameters.shareBytes);
    }
  }
  return {
    parameters: { ...parameters },
    cells: cells.map((cell) => cell!.slice()),
  };
}

export function checkZeroSum(shares: readonly Uint8Array[], shareBytes: number): boolean {
  const combined = xorShares(shares, shareBytes);
  let aggregate = 0;
  for (const byte of combined) aggregate |= byte;
  return aggregate === 0;
}

export function xorShares(shares: readonly Uint8Array[], shareBytes: number): Uint8Array {
  if (!Number.isSafeInteger(shareBytes) || shareBytes <= 0) {
    throw new Error('ZGBF share width must be a positive safe integer');
  }
  const out = new Uint8Array(shareBytes);
  for (const share of shares) {
    if (share.length !== shareBytes) throw new Error('ZGBF shares have inconsistent widths');
    for (let index = 0; index < shareBytes; index++) out[index] ^= share[index]!;
  }
  return out;
}

function checkedRandomShare(
  source: (length: number) => Uint8Array,
  shareBytes: number,
): Uint8Array {
  const share = source(shareBytes);
  if (!(share instanceof Uint8Array) || share.length !== shareBytes) {
    throw new Error('ZGBF randomness source returned the wrong number of bytes');
  }
  return share.slice();
}

function assertMapParameters(
  parameters: Pick<ZgbfParameters, 'slots' | 'hashCount' | 'mapNonce'>,
): void {
  if (!Number.isSafeInteger(parameters.slots) || parameters.slots < 2) {
    throw new Error('ZGBF slot count must be at least two');
  }
  if (
    !Number.isSafeInteger(parameters.hashCount) ||
    parameters.hashCount <= 0 ||
    parameters.hashCount > parameters.slots
  ) {
    throw new Error('ZGBF hash count must fit the filter');
  }
  if (!Number.isSafeInteger(parameters.mapNonce) || parameters.mapNonce < 0 || parameters.mapNonce > 0xffffffff) {
    throw new Error('ZGBF map nonce must be a u32');
  }
}

function assertParameters(parameters: ZgbfParameters): void {
  assertMapParameters(parameters);
  if (!Number.isSafeInteger(parameters.shareBytes) || parameters.shareBytes <= 0) {
    throw new Error('ZGBF share width must be a positive safe integer');
  }
}
