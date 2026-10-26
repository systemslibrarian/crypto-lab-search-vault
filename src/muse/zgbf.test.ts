import { describe, expect, it } from 'vitest';
import { utf8 } from '../core/bytes';
import {
  buildZgbf,
  checkZeroSum,
  mapZgbfPositions,
  ZgbfBuildError,
  type ZgbfParameters,
} from './zgbf';

describe('zero-sum garbled Bloom filters', () => {
  const parameters: ZgbfParameters = {
    slots: 32,
    hashCount: 3,
    shareBytes: 16,
    mapNonce: 7,
  };

  it('maps each element deterministically to distinct in-range positions', async () => {
    const first = await mapZgbfPositions(utf8('alpha'), parameters);
    const second = await mapZgbfPositions(utf8('alpha'), parameters);
    expect(second).toEqual(first);
    expect(new Set(first).size).toBe(parameters.hashCount);
    expect(first.every((position) => position >= 0 && position < parameters.slots)).toBe(true);
    expect(await mapZgbfPositions(utf8('beta'), parameters)).not.toEqual(first);
  });

  it('makes every inserted element sum to zero while a fixed non-member does not', async () => {
    let counter = 1;
    const filter = await buildZgbf(
      [utf8('alpha'), utf8('beta')],
      parameters,
      (length) => Uint8Array.from({ length }, () => counter++ & 0xff),
    );
    for (const element of ['alpha', 'beta']) {
      const positions = await mapZgbfPositions(utf8(element), parameters);
      expect(checkZeroSum(positions.map((position) => filter.cells[position]!), 16)).toBe(true);
    }
    const absent = await mapZgbfPositions(utf8('gamma'), parameters);
    expect(checkZeroSum(absent.map((position) => filter.cells[position]!), 16)).toBe(false);
  });

  it('implements the paper’s explicit abort when every mapped cell is occupied', async () => {
    await expect(
      buildZgbf(
        [utf8('first'), utf8('second')],
        { slots: 3, hashCount: 3, shareBytes: 4, mapNonce: 0 },
        (length) => new Uint8Array(length).fill(0x5a),
      ),
    ).rejects.toBeInstanceOf(ZgbfBuildError);
  });

  it('rejects empty elements and inconsistent share widths', async () => {
    await expect(mapZgbfPositions(new Uint8Array(), parameters)).rejects.toThrow(/must not be empty/);
    expect(() => checkZeroSum([new Uint8Array(15)], 16)).toThrow(/inconsistent/);
  });
});
