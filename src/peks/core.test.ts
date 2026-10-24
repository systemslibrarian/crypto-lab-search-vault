import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { describe, expect, it } from 'vitest';
import { toHex, utf8 } from '../core/bytes';
import {
  PEKS_H1_DST,
  PEKS_H2_DOMAIN,
  derivePeksKeyPair,
  encryptKeyword,
  encryptKeywordWithScalar,
  generatePeksKeyPair,
  hashKeywordToG1,
  issueTrapdoor,
  normalizePeksKeyword,
  randomNonzeroScalar,
  testTag,
} from './core';

describe('RFC 9380 hash-to-curve foundation', () => {
  it('matches Appendix J.9.1 for the empty message in both affine coordinates', () => {
    const dst = 'QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_';
    const point = bls.G1.hashToCurve(new Uint8Array(), { DST: dst });
    const { x, y } = point.toAffine();
    expect(x.toString(16).padStart(96, '0')).toBe(
      '052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1',
    );
    expect(y.toString(16).padStart(96, '0')).toBe(
      '08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265',
    );
    expect(point.isTorsionFree()).toBe(true);
  });

  it('uses a PEKS-only domain and exact-match normalization', () => {
    const a = hashKeywordToG1('  AUDIT ');
    const b = hashKeywordToG1('audit');
    const otherDomain = bls.G1.hashToCurve(utf8('audit'), {
      DST: 'BLS12381G1_XMD:SHA-256_SSWU_RO_',
    });
    expect(a.equals(b)).toBe(true);
    expect(a.equals(otherDomain)).toBe(false);
    expect(PEKS_H1_DST).toContain('PEKS-V1');
    expect(normalizePeksKeyword('  Audit  ')).toBe('audit');
    expect(() => normalizePeksKeyword('   ')).toThrow(/must not be empty/);
  });
});

describe('Type-3 BDOP PEKS correctness', () => {
  it('matches an independent fixed-scalar pairing and H2 computation', async () => {
    const recipientScalar = 7n;
    const senderScalar = 11n;
    const keyPair = derivePeksKeyPair(recipientScalar);
    const tag = await encryptKeywordWithScalar(keyPair.publicKey, 'audit', senderScalar);
    const trapdoor = issueTrapdoor(keyPair.secretKey, 'audit');

    const q = bls.G1.hashToCurve(utf8('audit'), { DST: PEKS_H1_DST });
    const x = bls.G2.Point.BASE.multiply(recipientScalar);
    const a = bls.G2.Point.BASE.multiply(senderScalar);
    // Independent sender-side route: e(H1(w), X)^r, rather than calling the
    // implementation's e(H1(w), rX) path again.
    const senderGt = bls.fields.Fp12.pow(bls.pairing(q, x), senderScalar);
    const recipientGt = bls.pairing(q.multiply(recipientScalar), a);

    expect(bls.fields.Fp12.eql(senderGt, recipientGt)).toBe(true);
    const qAffine = q.toAffine();
    expect(qAffine.x.toString(16).padStart(96, '0')).toBe(
      '16d71872bffc44e1ee531f65586ce8ec3cae934c7991c907e4c26cebeb8644afc41880d15605715b6002f67946e18c16',
    );
    expect(qAffine.y.toString(16).padStart(96, '0')).toBe(
      '148982805cfe6c3809a01a073102f83379fde22ef99e20892be68824acda94405f1f358f69465c82e1df6cb81490f2a0',
    );
    // Local deterministic regression transcript (not a published standard
    // vector), independently derived with the formulas above and Node SHA-256.
    expect(toHex(keyPair.publicKey.bytes)).toBe(
      '8d0273f6bf31ed37c3b8d68083ec3d8e20b5f2cc170fa24b9b5be35b34ed013f9a921f1cad1644d4bdb14674247234c8049cd1dbb2d2c3581e54c088135fef36505a6823d61b859437bfc79b617030dc8b40e32bad1fa85b9c0f368af6d38d3c',
    );
    expect(toHex(tag.a)).toBe(
      'a190be857d602284393305bfe0a29e29a6982ed3f04ccaabafb7e59cdc7eda85c22bc3e8690355c7a0fb7590ae40f1b009303f04d568e289a35102b6df883d5ed620355c0eb5d02236718cdaf99fba6e19ef5cee2996268eb9a53ae1ee09bce3',
    );
    expect(toHex(trapdoor.bytes)).toBe(
      '8978f8b3f80b8fd790e07daebc0f3303ebd2c43935eb285d87ebeef04fa8ea8913760c0e0099edcc119bf730c1f09f4c',
    );
    expect(toHex(tag.b)).toBe(
      '69993654f7bcebb205d92f6a6ea5a7ca9c56a69cdf0aba1c8306ecf17f10c141',
    );
    expect(toHex(tag.a)).toBe(toHex(a.toBytes(true)));
    expect(toHex(trapdoor.bytes)).toBe(toHex(q.multiply(recipientScalar).toBytes(true)));
    expect(toHex(tag.b)).toBe(toHex(await referenceH2(senderGt)));
    expect(await testTag(tag, trapdoor)).toBe(true);
  });

  it('randomizes equal-keyword tags while both still pass Test', async () => {
    const keys = generatePeksKeyPair();
    const first = await encryptKeyword(keys.publicKey, 'audit');
    const second = await encryptKeyword(keys.publicKey, 'audit');
    const trapdoor = issueTrapdoor(keys.secretKey, 'audit');
    expect(toHex(first.a)).not.toBe(toHex(second.a));
    expect(toHex(first.b)).not.toBe(toHex(second.b));
    expect(await testTag(first, trapdoor)).toBe(true);
    expect(await testTag(second, trapdoor)).toBe(true);
  });

  it('rejects a wrong keyword and a trapdoor from a different recipient', async () => {
    const alice = derivePeksKeyPair(17n);
    const bob = derivePeksKeyPair(19n);
    const tag = await encryptKeywordWithScalar(alice.publicKey, 'audit', 23n);
    expect(await testTag(tag, issueTrapdoor(alice.secretKey, 'merger'))).toBe(false);
    expect(await testTag(tag, issueTrapdoor(bob.secretKey, 'audit'))).toBe(false);
  });

  it('allows an arbitrary sender holding only the public key to make a valid tag', async () => {
    const recipient = generatePeksKeyPair();
    const publicOnly = { bytes: recipient.publicKey.bytes.slice() };
    const tag = await encryptKeyword(publicOnly, 'breach');
    expect(Object.keys(tag).sort()).toEqual(['a', 'b']);
    expect(await testTag(tag, issueTrapdoor(recipient.secretKey, 'breach'))).toBe(true);
  });

  it('normalizes the sender and recipient keyword identically', async () => {
    const keys = derivePeksKeyPair(29n);
    const tag = await encryptKeywordWithScalar(keys.publicKey, '  SALARY ', 31n);
    expect(await testTag(tag, issueTrapdoor(keys.secretKey, 'salary'))).toBe(true);
  });
});

describe('fail-closed encodings and parameters', () => {
  it('samples only nonzero subgroup scalars without modulo reduction', () => {
    const order = bls.fields.Fr.ORDER;
    for (let i = 0; i < 64; i++) {
      const scalar = randomNonzeroScalar();
      expect(scalar).toBeGreaterThan(0n);
      expect(scalar).toBeLessThan(order);
    }
  });

  it('rejects zero and out-of-range recipient or sender scalars', async () => {
    const order = bls.fields.Fr.ORDER;
    expect(() => derivePeksKeyPair(0n)).toThrow(/recipient secret/);
    expect(() => derivePeksKeyPair(order)).toThrow(/recipient secret/);
    const keys = derivePeksKeyPair(3n);
    await expect(encryptKeywordWithScalar(keys.publicKey, 'audit', 0n)).rejects.toThrow(
      /sender randomness/,
    );
    await expect(encryptKeywordWithScalar(keys.publicKey, 'audit', order)).rejects.toThrow(
      /sender randomness/,
    );
  });

  it('rejects empty keywords at both role boundaries', async () => {
    const keys = derivePeksKeyPair(5n);
    await expect(encryptKeyword(keys.publicKey, '  ')).rejects.toThrow(/must not be empty/);
    expect(() => issueTrapdoor(keys.secretKey, '')).toThrow(/must not be empty/);
  });

  it('returns false for a digest tampered at its first, middle, or last byte', async () => {
    const keys = derivePeksKeyPair(37n);
    const tag = await encryptKeywordWithScalar(keys.publicKey, 'audit', 41n);
    const trapdoor = issueTrapdoor(keys.secretKey, 'audit');
    for (const index of [0, Math.floor(tag.b.length / 2), tag.b.length - 1]) {
      const changed = { a: tag.a, b: tag.b.slice() };
      changed.b[index] ^= 0x80;
      expect(await testTag(changed, trapdoor)).toBe(false);
    }
  });

  it('rejects the wrong digest length', async () => {
    const keys = derivePeksKeyPair(37n);
    const tag = await encryptKeywordWithScalar(keys.publicKey, 'audit', 41n);
    const trapdoor = issueTrapdoor(keys.secretKey, 'audit');
    await expect(testTag({ a: tag.a, b: tag.b.slice(0, 31) }, trapdoor)).rejects.toThrow(
      /digest must be 32 bytes/,
    );
  });

  it('rejects malformed, identity, and wrong-length group encodings', async () => {
    const keys = derivePeksKeyPair(43n);
    const tag = await encryptKeywordWithScalar(keys.publicKey, 'audit', 47n);
    const trapdoor = issueTrapdoor(keys.secretKey, 'audit');

    await expect(
      encryptKeyword({ bytes: bls.G2.Point.ZERO.toBytes(true) }, 'audit'),
    ).rejects.toThrow(/identity point/);
    await expect(encryptKeyword({ bytes: new Uint8Array(95) }, 'audit')).rejects.toThrow(
      /96 bytes/,
    );
    await expect(
      testTag({ a: bls.G2.Point.ZERO.toBytes(true), b: tag.b }, trapdoor),
    ).rejects.toThrow(/identity point/);
    await expect(
      testTag(tag, { bytes: bls.G1.Point.ZERO.toBytes(true) }),
    ).rejects.toThrow(/identity point/);
    await expect(testTag({ a: new Uint8Array(96), b: tag.b }, trapdoor)).rejects.toThrow();
    await expect(testTag(tag, { bytes: new Uint8Array(47) })).rejects.toThrow(/48 bytes/);
  });

  it('rejects on-curve points outside the prime-order G1 and G2 subgroups', async () => {
    const keys = derivePeksKeyPair(43n);
    const tag = await encryptKeywordWithScalar(keys.publicKey, 'audit', 47n);
    const trapdoor = issueTrapdoor(keys.secretKey, 'audit');
    // Valid compressed curve points chosen specifically outside the prime-order
    // subgroups. noble decodes the curve equation, then rejects subgroup membership.
    const nonSubgroupG1 = new Uint8Array(48);
    nonSubgroupG1[0] = 0x80;
    const nonSubgroupG2 = new Uint8Array(96);
    nonSubgroupG2[0] = 0xa0;
    nonSubgroupG2[47] = 0x01;

    await expect(encryptKeyword({ bytes: nonSubgroupG2 }, 'audit')).rejects.toThrow(/subgroup|bad point/i);
    await expect(testTag({ a: nonSubgroupG2, b: tag.b }, trapdoor)).rejects.toThrow(/subgroup|bad point/i);
    await expect(testTag(tag, { bytes: nonSubgroupG1 })).rejects.toThrow(/subgroup|bad point/i);
  });

  it('rejects non-canonical field encodings at G1 and G2 wire boundaries', async () => {
    const keys = derivePeksKeyPair(67n);
    const tag = await encryptKeywordWithScalar(keys.publicKey, 'audit', 71n);
    const trapdoor = issueTrapdoor(keys.secretKey, 'audit');
    const fieldOrder = bls.fields.Fp.ORDER;
    const nonCanonicalG1 = bigIntToBytes(fieldOrder, 48);
    nonCanonicalG1[0] |= 0x80;
    const nonCanonicalG2 = new Uint8Array(96);
    nonCanonicalG2.set(bigIntToBytes(fieldOrder, 48), 0);
    nonCanonicalG2[0] |= 0x80;

    await expect(encryptKeyword({ bytes: nonCanonicalG2 }, 'audit')).rejects.toThrow();
    await expect(testTag({ a: nonCanonicalG2, b: tag.b }, trapdoor)).rejects.toThrow();
    await expect(testTag(tag, { bytes: nonCanonicalG1 })).rejects.toThrow();
  });
});

async function referenceH2(gt: ReturnType<typeof bls.pairing>): Promise<Uint8Array> {
  const domain = utf8(PEKS_H2_DOMAIN);
  const element = bls.fields.Fp12.toBytes(gt);
  const framed = new Uint8Array(4 + domain.length + 4 + element.length);
  const view = new DataView(framed.buffer);
  view.setUint32(0, domain.length, false);
  framed.set(domain, 4);
  view.setUint32(4 + domain.length, element.length, false);
  framed.set(element, 8 + domain.length);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', framed));
}

function bigIntToBytes(value: bigint, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let rest = value;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  if (rest !== 0n) throw new Error('integer does not fit');
  return out;
}
