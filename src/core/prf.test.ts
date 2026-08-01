import { describe, expect, it } from 'vitest';
import { concat, fromHex, toHex, utf8, u32be, frame, ctEqual } from './bytes';
import { DOMAIN, hmacSha256, prf, sha256 } from './prf';

/** RFC 4231 §4 — HMAC-SHA-256 known-answer vectors. These pin the PRF that
 *  every search token, index address, and posting key in this demo is built
 *  from: if they pass, the tokens the server sees are real HMAC output. */
describe('HMAC-SHA-256 — RFC 4231 known-answer tests', () => {
  const cases: Array<{ name: string; key: Uint8Array; data: Uint8Array; mac: string }> = [
    {
      name: 'Test Case 1',
      key: new Uint8Array(20).fill(0x0b),
      data: utf8('Hi There'),
      mac: 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
    },
    {
      name: 'Test Case 2 (key shorter than the block)',
      key: utf8('Jefe'),
      data: utf8('what do ya want for nothing?'),
      mac: '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
    },
    {
      name: 'Test Case 3 (combined length > block size)',
      key: new Uint8Array(20).fill(0xaa),
      data: new Uint8Array(50).fill(0xdd),
      mac: '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe',
    },
    {
      name: 'Test Case 4 (key of 0x01..0x19)',
      key: fromHex('0102030405060708090a0b0c0d0e0f10111213141516171819'),
      data: new Uint8Array(50).fill(0xcd),
      mac: '82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b',
    },
    {
      name: 'Test Case 6 (key longer than the block — hashed first)',
      key: new Uint8Array(131).fill(0xaa),
      data: utf8('Test Using Larger Than Block-Size Key - Hash Key First'),
      mac: '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54',
    },
    {
      name: 'Test Case 7 (oversized key and oversized data)',
      key: new Uint8Array(131).fill(0xaa),
      data: utf8(
        'This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.',
      ),
      mac: '9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2',
    },
  ];

  for (const c of cases) {
    it(`matches RFC 4231 ${c.name}`, async () => {
      expect(toHex(await hmacSha256(c.key, c.data))).toBe(c.mac);
    });
  }
});

/** FIPS 180-4 / NIST example vectors for the hash under the HMAC. */
describe('SHA-256 — FIPS 180-4 known-answer tests', () => {
  it('hashes the empty string', async () => {
    expect(toHex(await sha256(new Uint8Array(0)))).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
  });
  it('hashes "abc"', async () => {
    expect(toHex(await sha256(utf8('abc')))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });
  it('hashes the 448-bit two-block message', async () => {
    expect(
      toHex(await sha256(utf8('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'))),
    ).toBe('248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
  });
});

describe('domain separation', () => {
  it('gives different outputs for the same input under different domains', async () => {
    const key = new Uint8Array(32).fill(7);
    const a = await prf(key, DOMAIN.TOKEN, utf8('salary'));
    const b = await prf(key, DOMAIN.POSTING_KEY, utf8('salary'));
    expect(toHex(a)).not.toBe(toHex(b));
  });

  it('cannot be confused by re-splitting the same concatenated bytes', async () => {
    // Without length framing, prf(K, D, "ab", "c") and prf(K, D, "a", "bc")
    // would hash identical bytes. The framing is what stops that collision.
    const key = new Uint8Array(32).fill(9);
    const a = await prf(key, DOMAIN.ADDRESS, utf8('ab'), utf8('c'));
    const b = await prf(key, DOMAIN.ADDRESS, utf8('a'), utf8('bc'));
    expect(toHex(a)).not.toBe(toHex(b));
  });

  it('is deterministic — the same keyword always yields the same token', async () => {
    const key = new Uint8Array(32).fill(3);
    const a = await prf(key, DOMAIN.TOKEN, utf8('merger'));
    const b = await prf(key, DOMAIN.TOKEN, utf8('merger'));
    expect(ctEqual(a, b)).toBe(true);
  });

  it('produces a full 32-byte token', async () => {
    const t = await prf(new Uint8Array(32), DOMAIN.TOKEN, utf8('audit'));
    expect(t.length).toBe(32);
  });
});

describe('byte helpers', () => {
  it('round-trips hex', () => {
    expect(toHex(fromHex('00ff10'))).toBe('00ff10');
  });
  it('rejects malformed hex', () => {
    expect(() => fromHex('abc')).toThrow(/odd length/);
    expect(() => fromHex('zz')).toThrow(/non-hex/);
  });
  it('encodes big-endian u32 and rejects out-of-range counters', () => {
    expect(toHex(u32be(1))).toBe('00000001');
    expect(toHex(u32be(0xdeadbeef))).toBe('deadbeef');
    expect(() => u32be(-1)).toThrow(/out of range/);
    expect(() => u32be(2 ** 32)).toThrow(/out of range/);
  });
  it('length-prefixes each framed part', () => {
    expect(toHex(frame(utf8('hi')))).toBe(`00000002${toHex(utf8('hi'))}`);
  });
  it('concatenates in order', () => {
    expect(toHex(concat(fromHex('01'), fromHex('0203')))).toBe('010203');
  });
  it('compares in constant time, including on length mismatch', () => {
    expect(ctEqual(fromHex('0102'), fromHex('0102'))).toBe(true);
    expect(ctEqual(fromHex('0102'), fromHex('0103'))).toBe(false);
    expect(ctEqual(fromHex('0102'), fromHex('010203'))).toBe(false);
  });
});
