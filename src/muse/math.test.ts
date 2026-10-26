import { describe, expect, it } from 'vitest';
import {
  applyPackedSelector,
  bigIntToBytes,
  createPackedSelector,
  derivePaillierKeyPair,
  generatePaillierKeyPair,
  openPackedResponse,
  paillierDecrypt,
  paillierEncrypt,
} from './math';

const P = BigInt('0xCF1ADEE9E745BD6B91DD865E6249024150C52438BC314F4135E12C56B122EDED');
const Q = BigInt('0xEEBFFF9F6C78D07EF708918FC946C930B1DA87D2848B86C7A951E779BFC3AA27');

describe('Paillier selector arithmetic', () => {
  it('round-trips deterministic messages and adds under ciphertext multiplication', () => {
    const pair = derivePaillierKeyPair(P, Q);
    const left = paillierEncrypt(pair.publicKey, 17n, 2n);
    const right = paillierEncrypt(pair.publicKey, 29n, 3n);
    expect(paillierDecrypt(pair, left)).toBe(17n);
    expect(paillierDecrypt(pair, right)).toBe(29n);
    expect(paillierDecrypt(pair, (left * right) % pair.publicKey.nSquared)).toBe(46n);
  });

  it('retrieves three selected 128-bit cells in their declared order', () => {
    const pair = derivePaillierKeyPair(P, Q);
    const cells = Array.from({ length: 8 }, (_, index) =>
      bigIntToBytes(BigInt(index + 1) * 0x0102030405060708090a0b0c0d0e0fn, 16),
    );
    const selector = createPackedSelector(pair.publicKey, cells.length, [6, 1, 4], 128);
    const response = applyPackedSelector(pair.publicKey, selector, cells);
    expect(openPackedResponse(pair, response, 3, 128)).toEqual([
      cells[6],
      cells[1],
      cells[4],
    ]);
  });

  it('randomizes identical packed-selector plaintext vectors independently', () => {
    const pair = derivePaillierKeyPair(P, Q);
    const selected = [5, 1, 3] as const;
    const first = createPackedSelector(pair.publicKey, 8, selected, 32);
    const second = createPackedSelector(pair.publicKey, 8, selected, 32);
    expect(second.ciphertexts).not.toEqual(first.ciphertexts);
    for (let position = 0; position < first.ciphertexts.length; position++) {
      const order = selected.indexOf(position as 5 | 1 | 3);
      const expected = order < 0 ? 0n : 1n << BigInt(order * 32);
      expect(paillierDecrypt(pair, first.ciphertexts[position]!)).toBe(expected);
      expect(paillierDecrypt(pair, second.ciphertexts[position]!)).toBe(expected);
    }
  });

  it('sanitizes the same homomorphic response with a fresh encryption of zero', () => {
    const pair = derivePaillierKeyPair(P, Q);
    const cells = Array.from({ length: 6 }, (_, index) => bigIntToBytes(BigInt(index + 1), 16));
    const selector = createPackedSelector(pair.publicKey, cells.length, [0, 2, 5], 128);
    const rawOne = applyPackedSelector(pair.publicKey, selector, cells, false);
    const rawTwo = applyPackedSelector(pair.publicKey, selector, cells, false);
    const sanitizedOne = applyPackedSelector(pair.publicKey, selector, cells, true);
    const sanitizedTwo = applyPackedSelector(pair.publicKey, selector, cells, true);

    expect(rawTwo).toBe(rawOne);
    expect(sanitizedOne).not.toBe(rawOne);
    expect(sanitizedTwo).not.toBe(sanitizedOne);
    expect(paillierDecrypt(pair, sanitizedOne)).toBe(paillierDecrypt(pair, rawOne));
    expect(paillierDecrypt(pair, sanitizedTwo)).toBe(paillierDecrypt(pair, rawOne));
  });

  it('rejects duplicate/out-of-range positions, oversized packing, and malformed ciphertexts', () => {
    const pair = derivePaillierKeyPair(P, Q);
    expect(() => createPackedSelector(pair.publicKey, 4, [1, 1], 32)).toThrow(/distinct/);
    expect(() => createPackedSelector(pair.publicKey, 4, [4], 32)).toThrow(/outside/);
    expect(() => createPackedSelector(pair.publicKey, 4, [0, 1, 2, 3], 256)).toThrow(/does not fit/);
    expect(() => paillierDecrypt(pair, 0n)).toThrow(/ciphertext/);
    expect(() => paillierDecrypt(pair, pair.publicKey.nSquared)).toThrow(/ciphertext/);
  });

  it('derives a fresh browser Paillier modulus from WebCrypto-generated primes', async () => {
    const pair = await generatePaillierKeyPair(1024);
    expect(pair.publicKey.modulusBits).toBeGreaterThanOrEqual(1023);
    const ciphertext = paillierEncrypt(pair.publicKey, 0x123456789abcdefn);
    expect(paillierDecrypt(pair, ciphertext)).toBe(0x123456789abcdefn);
  });
});
