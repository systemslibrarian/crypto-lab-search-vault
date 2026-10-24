import { ristretto255 } from '@noble/curves/ed25519.js';
import { beforeAll, describe, expect, it } from 'vitest';
import { seal } from '../core/aead';
import { fromHex, toHex, utf8 } from '../core/bytes';
import { CORPUS, KEYWORDS, documentsFor } from '../sse/corpus';
import type { Document } from '../sse/types';
import {
  OXT_DOMAIN,
  RISTRETTO_ORDER,
  blindScalar,
  buildOxtIndex,
  bytesToBigIntLittleEndian,
  createOxtQuery,
  crossTagFor,
  decryptOxtMatches,
  documentScalar,
  evaluateCrossToken,
  generateOxtKeys,
  oxtPrf256,
  randomIndex,
  scalarPrf,
  scalarPrfWithMac,
  scalarFromBytes,
  scalarToHex,
  selectTerms,
  shuffleWithCsprng,
  stagFor,
  tsetAddressFor,
  xtermScalar,
  type OxtClientQuery,
  type OxtEncryptedIndex,
  type OxtEncryptedMatch,
  type OxtKeys,
} from './core';

const Point = ristretto255.Point;
const Scalar = Point.Fn;

// RFC 9496, Appendix A.1. These deliberately span the identity, generator,
// nearby multiples, and both fixed points used by the cancellation transcript.
const RFC_MULTIPLES = new Map<number, string>([
  [0, '0000000000000000000000000000000000000000000000000000000000000000'],
  [1, 'e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76'],
  [2, '6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919'],
  [6, 'f64746d3c92b13050ed8d80236a7f0007c3b3f962f5ba793d19a601ebb1df403'],
  [10, '20706fd788b2720a1ed2a5dad4952b01f413bcf0e7564de8cdc816689e2db95f'],
  [15, 'e0c418f7c8d9c4cdd7395b93ea124f3ad99021bb681dfc3302a9d99a2e53e64e'],
]);

// Every invalid ristretto255 encoding published in RFC 9496, Appendix A.2.
// Testing the complete list prevents a permissive decoder from slipping past
// a hand-picked example from only one rejection category.
const RFC_INVALID_ENCODINGS = [
  // Non-canonical field encodings.
  '00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  // Negative field elements.
  '0100000000000000000000000000000000000000000000000000000000000000',
  '01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'ed57ffd8c914fb201471d1c3d245ce3c746fcbe63a3679d51b6a516ebebe0e20',
  'c34c4e1826e5d403b78e246e88aa051c36ccf0aafebffe137d148a2bf9104562',
  'c940e5a4404157cfb1628b108db051a8d439e1a421394ec4ebccb9ec92a8ac78',
  '47cfc5497c53dc8e61c91d17fd626ffb1c49e2bca94eed052281b510b1117a24',
  'f1c6165d33367351b0da8f6e4511010c68174a03b6581212c71c0e1d026c3c72',
  '87260f7a2f12495118360f02c26a470f450dadf34a413d21042b43b9d93e1309',
  // Non-square x^2.
  '26948d35ca62e643e26a83177332e6b6afeb9d08e4268b650f1f5bbd8d81d371',
  '4eac077a713c57b4f4397629a4145982c661f48044dd3f96427d40b147d9742f',
  'de6a7b00deadc788eb6b6c8d20c0ae96c2f2019078fa604fee5b87d6e989ad7b',
  'bcab477be20861e01e4a0e295284146a510150d9817763caf1a6f4b422d67042',
  '2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08',
  'f4a9e534fc0d216c44b218fa0c42d99635a0127ee2e53c712f70609649fdff22',
  '8268436f8c4126196cf64b3c7ddbda90746a378625f9813dd9b8457077256731',
  '2810e5cbc2cc4d4eece54f61c6f69758e289aa7ab440b3cbeaa21995c2f4232b',
  // Negative x*y.
  '3eb858e78f5a7254d8c9731174a94f76755fd3941c0ac93735c07ba14579630e',
  'a45fdc55c76448c049a1ab33f17023edfb2be3581e9c7aade8a6125215e04220',
  'd483fe813c6ba647ebbfd3ec41adca1c6130c2beeee9d9bf065c8d151c5f396e',
  '8a2e1d30050198c65a54483123960ccc38aef6848e1ec8f5f780e8523769ba32',
  '32888462f8b486c68ad7dd9610be5192bbeaf3b443951ac1a8118419d9fa097b',
  '227142501b9d4355ccba290404bde41575b037693cef1f438c47f8fbf35d1165',
  '5c37cc491da847cfeb9281d407efc41e15144c876e0170b499a96a22ed31e01e',
  '445425117cb8c90edcbc7c1cc0e74f747f2c1efa5630a967c64f287792a48a4b',
  // s = -1, which makes y = 0 during decoding.
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
] as const;

let keys: OxtKeys;
let index: OxtEncryptedIndex;

beforeAll(async () => {
  keys = fixedKeys();
  index = await buildOxtIndex(keys);
});

describe('RFC 9496 ristretto255 wire boundary', () => {
  it('matches and canonically round-trips the published B[0], B[1], B[2], B[6], B[10], and B[15] vectors', () => {
    for (const [multiple, expected] of RFC_MULTIPLES) {
      const calculated = multiple === 0 ? Point.ZERO : Point.BASE.multiply(BigInt(multiple));
      expect(toHex(calculated.toBytes()), `B[${multiple}] encoding`).toBe(expected);
      expect(toHex(Point.fromBytes(fromHex(expected)).toBytes()), `B[${multiple}] round trip`).toBe(
        expected,
      );
    }
  });

  it('rejects all 29 invalid encodings from RFC 9496 Appendix A.2', () => {
    expect(RFC_INVALID_ENCODINGS).toHaveLength(29);
    for (const encoded of RFC_INVALID_ENCODINGS) {
      expect(() => Point.fromBytes(fromHex(encoded)), encoded).toThrow();
      expect(() => evaluateCrossToken(fromHex(encoded), 1n), encoded).toThrow(
        /canonical ristretto255/,
      );
    }
  });

  it('rejects wrong lengths, the identity, and non-canonical y scalars at the server boundary', () => {
    const generator = fromHex(RFC_MULTIPLES.get(1)!);
    expect(() => evaluateCrossToken(new Uint8Array(31), 1n)).toThrow(/32-byte/);
    expect(() => evaluateCrossToken(new Uint8Array(33), 1n)).toThrow(/32-byte/);
    expect(() => evaluateCrossToken(fromHex(RFC_MULTIPLES.get(0)!), 1n)).toThrow(/identity/);
    expect(() => evaluateCrossToken(generator, 0n)).toThrow(/canonical nonzero scalar/);
    expect(() => evaluateCrossToken(generator, -1n)).toThrow(/canonical nonzero scalar/);
    expect(() => evaluateCrossToken(generator, RISTRETTO_ORDER)).toThrow(
      /canonical nonzero scalar/,
    );
    expect(() => evaluateCrossToken(generator, RISTRETTO_ORDER + 1n)).toThrow(
      /canonical nonzero scalar/,
    );
  });
});

describe('fixed OXT cancellation transcript', () => {
  it('independently cancels z=5 from xtoken=[10]B with y=3/5 to recover XSet element [6]B', () => {
    const xTermScalar = 2n;
    const documentScalar = 3n;
    const blind = 5n;
    const xsetPoint = Point.BASE.multiply(Scalar.mul(xTermScalar, documentScalar)).toBytes();
    const xtoken = Point.BASE.multiply(Scalar.mul(blind, xTermScalar)).toBytes();
    const y = Scalar.div(documentScalar, blind);

    expect(toHex(xsetPoint)).toBe(RFC_MULTIPLES.get(6));
    expect(toHex(xtoken)).toBe(RFC_MULTIPLES.get(10));
    expect(y).toBe(
      4342203346399357328383911937825796544514269815627944563601170562971272550594n,
    );
    expect(scalarToHex(y)).toBe(
      'c2182d9edca1a401e72a2ec8b8621fa699999999999999999999999999999909',
    );
    expect(toHex(evaluateCrossToken(xtoken, y))).toBe(RFC_MULTIPLES.get(6));
  });

  it('does not produce a false membership hit when the x-term scalar is wrong', () => {
    const y = Scalar.div(3n, 5n);
    const wrongXToken = Point.BASE.multiply(15n).toBytes();
    expect(toHex(evaluateCrossToken(wrongXToken, y))).not.toBe(RFC_MULTIPLES.get(6));
    expect(toHex(evaluateCrossToken(wrongXToken, y))).toBe(
      toHex(Point.BASE.multiply(9n).toBytes()),
    );
  });
});

describe('OXT PRFs, keys, framing, and counters', () => {
  it('generates five independent 32-byte keys', () => {
    const generated = generateOxtKeys();
    const values = Object.values(generated);
    expect(values).toHaveLength(5);
    for (const value of values) expect(value).toHaveLength(32);
    expect(new Set(values.map(toHex)).size).toBe(5);
  });

  it('keeps every protocol role in a distinct domain even under one deliberately reused test key', async () => {
    expect(new Set(Object.values(OXT_DOMAIN)).size).toBe(Object.values(OXT_DOMAIN).length);
    const key = new Uint8Array(32).fill(0xa5);
    const input = utf8('audit');
    const outputs = await Promise.all(
      Object.values(OXT_DOMAIN).map(async (domain) => toHex(await oxtPrf256(key, domain, input))),
    );
    expect(new Set(outputs).size).toBe(outputs.length);
  });

  it('derives deterministic, nonzero, canonical scalars and separates domains and framed inputs', async () => {
    const key = new Uint8Array(32).fill(0x42);
    const first = await scalarPrf(key, OXT_DOMAIN.XTERM, utf8('audit'));
    const repeated = await scalarPrf(key, OXT_DOMAIN.XTERM, utf8('audit'));
    const otherDomain = await scalarPrf(key, OXT_DOMAIN.DOCUMENT, utf8('audit'));
    const splitOne = await scalarPrf(key, OXT_DOMAIN.XTERM, utf8('ab'), utf8('c'));
    const splitTwo = await scalarPrf(key, OXT_DOMAIN.XTERM, utf8('a'), utf8('bc'));

    expect(first).toBe(repeated);
    // Fixed local transcript independently calculated from HMAC-SHA-512 over
    // frame(domain, "audit", u32be(0)), then little-endian reduction mod l.
    expect(first).toBe(
      4358584713853820647733008857209155310476715304842787132209695059467412617181n,
    );
    expect(scalarToHex(first)).toBe(
      'ddb70aa34cda1ed20586bc591f0eb6c31fbfb63bd1a13a08da33084a1cdfa209',
    );
    expect(first).toBeGreaterThan(0n);
    expect(first).toBeLessThan(RISTRETTO_ORDER);
    expect(otherDomain).not.toBe(first);
    expect(splitOne).not.toBe(splitTwo);
    expect(scalarToHex(first)).toMatch(/^[0-9a-f]{64}$/);
  });

  it('uses little-endian wide-output reduction and retries an injected zero scalar with a framed counter', async () => {
    expect(bytesToBigIntLittleEndian(new Uint8Array())).toBe(0n);
    expect(bytesToBigIntLittleEndian(new Uint8Array([0x01, 0x02, 0x03]))).toBe(0x030201n);

    const key = new Uint8Array(32).fill(0x7a);
    const messages: string[] = [];
    let calls = 0;
    const scalar = await scalarPrfWithMac(
      key,
      'test-domain',
      [utf8('a'), utf8('bc')],
      async (receivedKey, message) => {
        expect(toHex(receivedKey)).toBe(toHex(key));
        messages.push(toHex(message));
        const output = new Uint8Array(64);
        if (calls++ > 0) output[0] = 7;
        return output;
      },
    );

    expect(scalar).toBe(7n);
    expect(messages).toEqual([
      '0000000b746573742d646f6d61696e00000001610000000262630000000400000000',
      '0000000b746573742d646f6d61696e00000001610000000262630000000400000001',
    ]);
  });

  it('rejects empty scalar domains and non-wide injected MAC outputs', async () => {
    const key = new Uint8Array(32).fill(0x51);
    const wide = async (): Promise<Uint8Array> => new Uint8Array(64).fill(1);
    await expect(scalarPrfWithMac(key, '', [utf8('audit')], wide)).rejects.toThrow(
      /domain must not be empty/,
    );
    await expect(
      scalarPrfWithMac(key, OXT_DOMAIN.XTERM, [utf8('audit')], async () => new Uint8Array(63)),
    ).rejects.toThrow(/64-byte wide-MAC output/);
  });

  it('separates keyword, document, and one-based position inputs', async () => {
    const stagAudit = await stagFor(keys, 'audit');
    const stagAuditNormalized = await stagFor(keys, '  AUDIT ');
    const stagBreach = await stagFor(keys, 'breach');
    expect(toHex(stagAuditNormalized)).toBe(toHex(stagAudit));
    expect(toHex(stagBreach)).not.toBe(toHex(stagAudit));

    expect(await xtermScalar(keys, 'audit')).not.toBe(await documentScalar(keys, 'audit'));
    expect(await documentScalar(keys, 'd01')).not.toBe(await documentScalar(keys, 'd02'));
    expect(await blindScalar(keys, 'audit', 1)).not.toBe(await blindScalar(keys, 'audit', 2));
    expect(await blindScalar(keys, 'audit', 1)).not.toBe(await blindScalar(keys, 'breach', 1));
    expect(toHex(await tsetAddressFor(stagAudit, 1))).not.toBe(
      toHex(await tsetAddressFor(stagAudit, 2)),
    );
  });

  it('rejects malformed keys, keywords, document ids, and counter boundaries', async () => {
    await expect(scalarPrf(new Uint8Array(31), OXT_DOMAIN.XTERM, utf8('audit'))).rejects.toThrow(
      /exactly 32 bytes/,
    );
    await expect(stagFor({ ...keys, kStag: new Uint8Array(33) }, 'audit')).rejects.toThrow(
      /exactly 32 bytes/,
    );
    await expect(stagFor(keys, 'not-indexed')).rejects.toThrow(/fixed indexed vocabulary/);
    await expect(documentScalar(keys, '')).rejects.toThrow(/must not be empty/);
    await expect(blindScalar(keys, 'audit', 0)).rejects.toThrow(/1 through 2\^32-1/);
    await expect(blindScalar(keys, 'audit', 0x100000000)).rejects.toThrow(/1 through 2\^32-1/);
    await expect(tsetAddressFor(new Uint8Array(31), 1)).rejects.toThrow(/exactly 32 bytes/);
    await expect(tsetAddressFor(new Uint8Array(32), 0)).rejects.toThrow(/1 through 2\^32-1/);
    await expect(tsetAddressFor(new Uint8Array(32), 1.5)).rejects.toThrow(/1 through 2\^32-1/);
  });

  it('rejects non-canonical scalar serialization while permitting canonical zero serialization', () => {
    expect(scalarToHex(0n)).toBe('00'.repeat(32));
    expect(() => scalarToHex(-1n)).toThrow(/not canonical/);
    expect(() => scalarToHex(RISTRETTO_ORDER)).toThrow(/not canonical/);
  });
});

describe('unbiased random-index and shuffle plumbing', () => {
  it('rejects the incomplete modulo range and redraws before reducing', () => {
    const draws = [0xffffffff, 5];
    let used = 0;
    expect(randomIndex(3, () => draws[used++]!)).toBe(2);
    expect(used).toBe(2);
  });

  it('supports both inclusive uint32 source endpoints and the maximum upper bound', () => {
    expect(randomIndex(2, () => 0)).toBe(0);
    expect(randomIndex(2, () => 0xfffffffe)).toBe(0);
    expect(randomIndex(0x100000000, () => 0xffffffff)).toBe(0xffffffff);
  });

  it('rejects invalid bounds and invalid entropy-source values', () => {
    for (const bound of [0, -1, 1.5, 0x100000001, Number.NaN]) {
      expect(() => randomIndex(bound, () => 0)).toThrow(/upper bound/);
    }
    for (const candidate of [-1, 1.5, 0x100000000, Number.NaN]) {
      expect(() => randomIndex(2, () => candidate)).toThrow(/outside uint32/);
    }
  });

  it('returns a permutation without mutating its caller-owned input', () => {
    const input = Array.from({ length: 32 }, (_, i) => i);
    const before = [...input];
    const output = shuffleWithCsprng(input);
    expect(input).toEqual(before);
    expect([...output].sort((a, b) => a - b)).toEqual(before);
    expect(output).not.toBe(input);
  });
});

describe('flat encrypted OXT index setup', () => {
  it('stores exactly 55 unique addressed TSet rows and 55 unique sorted XSet elements', () => {
    expect(CORPUS.reduce((total, document) => total + document.keywords.length, 0)).toBe(55);
    expect(index.tsetRows).toHaveLength(55);
    expect(index.xset).toHaveLength(55);
    expect(new Set(index.tsetRows.map((row) => row.addressHex)).size).toBe(55);
    expect(new Set(index.xset).size).toBe(55);
    expect(index.xset).toEqual([...index.xset].sort());

    for (const row of index.tsetRows) {
      expect(Object.keys(row).sort()).toEqual(['addressHex', 'encryptedId', 'y']);
      expect(row.addressHex).toMatch(/^[0-9a-f]{64}$/);
      expect(row.encryptedId).toHaveLength(31); // 12-byte IV + 3-byte id + 16-byte tag
      expect(row.y).toHaveLength(32);
      expect(scalarFromBytes(row.y)).toBeGreaterThan(0n);
      expect(scalarFromBytes(row.y)).toBeLessThan(RISTRETTO_ORDER);
    }
    for (const encoded of index.xset) {
      expect(encoded).toMatch(/^[0-9a-f]{64}$/);
      const point = Point.fromBytes(fromHex(encoded));
      expect(point.is0()).toBe(false);
      expect(toHex(point.toBytes())).toBe(encoded);
    }
  });

  it('globally shuffles the addressed rows instead of exposing keyword-list boundaries', async () => {
    const groupedAddresses: string[] = [];
    for (const keyword of KEYWORDS) {
      const stag = await stagFor(keys, keyword);
      for (let position = 1; position <= documentsFor(keyword).length; position++) {
        groupedAddresses.push(toHex(await tsetAddressFor(stag, position)));
      }
    }
    const actualAddresses = index.tsetRows.map((row) => row.addressHex);
    expect([...actualAddresses].sort()).toEqual([...groupedAddresses].sort());
    expect(actualAddresses).not.toEqual(groupedAddresses);
  });

  it('exposes only the flat server schema, not plaintext labels, ids, or setup keys', () => {
    expect(Object.keys(index).sort()).toEqual(['tsetRows', 'xset']);
    const exposedStrings = [
      ...index.tsetRows.flatMap((row) => [row.addressHex]),
      ...index.xset,
    ];
    for (const cleartext of [...KEYWORDS, ...CORPUS.map((document) => document.id)]) {
      expect(exposedStrings).not.toContain(cleartext);
    }
    const exposedBytes = index.tsetRows.flatMap((row) => [
      toHex(row.encryptedId),
      toHex(row.y),
    ]);
    for (const keyBytes of Object.values(keys)) expect(exposedBytes).not.toContain(toHex(keyBytes));
  });

  it('keeps labels and XSet deterministic under one key set while rerandomizing every ciphertext and row order', async () => {
    const rebuilt = await buildOxtIndex(keys);
    expect(rebuilt.xset).toEqual(index.xset);
    expect(rebuilt.tsetRows.map((row) => row.addressHex).sort()).toEqual(
      index.tsetRows.map((row) => row.addressHex).sort(),
    );
    expect(rebuilt.tsetRows.map((row) => row.addressHex)).not.toEqual(
      index.tsetRows.map((row) => row.addressHex),
    );

    const firstCiphertexts = new Map(
      index.tsetRows.map((row) => [row.addressHex, toHex(row.encryptedId)]),
    );
    for (const row of rebuilt.tsetRows) {
      expect(toHex(row.encryptedId)).not.toBe(firstCiphertexts.get(row.addressHex));
    }
  });

  it('gives a fresh setup disjoint labels and cross-tags under fresh keys', async () => {
    const fresh = await buildOxtIndex(fixedKeys(20));
    const oldAddresses = new Set(index.tsetRows.map((row) => row.addressHex));
    const oldXSet = new Set(index.xset);
    expect(fresh.tsetRows.some((row) => oldAddresses.has(row.addressHex))).toBe(false);
    expect(fresh.xset.some((encoded) => oldXSet.has(encoded))).toBe(false);
  });

  it('builds every XSet element from the actual corpus relation', async () => {
    const independentlyDerived = (
      await Promise.all(
        CORPUS.flatMap((document) =>
          document.keywords.map((keyword) => crossTagFor(keys, keyword, document.id)),
        ),
      )
    )
      .map(toHex)
      .sort();
    expect(index.xset).toEqual(independentlyDerived);
  });

  it('rejects empty, duplicate-id, repeated-keyword, unknown-keyword, and incomplete corpora', async () => {
    await expect(buildOxtIndex(keys, [])).rejects.toThrow(/unique document ids/);

    const duplicateId = cloneCorpus();
    duplicateId[1]!.id = duplicateId[0]!.id;
    await expect(buildOxtIndex(keys, duplicateId)).rejects.toThrow(/unique document ids/);

    const repeatedKeyword = cloneCorpus();
    repeatedKeyword[0]!.keywords.push(repeatedKeyword[0]!.keywords[0]!);
    await expect(buildOxtIndex(keys, repeatedKeyword)).rejects.toThrow(/repeats a keyword/);

    const unknownKeyword = cloneCorpus();
    unknownKeyword[0]!.keywords[0] = 'not-indexed';
    await expect(buildOxtIndex(keys, unknownKeyword)).rejects.toThrow(/fixed indexed vocabulary/);

    const nonCanonicalKeyword = cloneCorpus();
    nonCanonicalKeyword[1]!.keywords[1] = ' AUDIT ';
    await expect(buildOxtIndex(keys, nonCanonicalKeyword)).rejects.toThrow(
      /keyword must already be normalized/,
    );

    const missingKeyword = cloneCorpus();
    for (const document of missingKeyword) {
      document.keywords = document.keywords.filter((keyword) => keyword !== 'harassment');
    }
    await expect(buildOxtIndex(keys, missingKeyword)).rejects.toThrow(
      /missing indexed keyword: harassment/,
    );

    const emptyId = cloneCorpus();
    emptyId[0]!.id = '';
    await expect(buildOxtIndex(keys, emptyId)).rejects.toThrow(/document id must not be empty/);

    const variableLengthId = cloneCorpus();
    variableLengthId[0]!.id = 'record-one';
    await expect(buildOxtIndex(keys, variableLengthId)).rejects.toThrow(/fixed UTF-8 byte length/);

    const malformedUnicodeId = cloneCorpus();
    malformedUnicodeId[0]!.id = '\ud800d1';
    await expect(buildOxtIndex(keys, malformedUnicodeId)).rejects.toThrow(/well-formed Unicode/);
  });

  it('rejects an invalid key bundle before setup', async () => {
    for (const field of ['kStag', 'kEnc', 'kX', 'kId', 'kZ'] as const) {
      await expect(buildOxtIndex({ ...keys, [field]: new Uint8Array(31) })).rejects.toThrow(
        /exactly 32 bytes/,
      );
    }
  });
});

describe('query selection and end-to-end core algebra', () => {
  it('chooses the lower-frequency s-term and breaks equal-volume ties by ASCII order', () => {
    expect(selectTerms('audit', 'harassment')).toEqual(['harassment', 'audit']);
    expect(selectTerms('subpoena', 'breach')).toEqual(['breach', 'subpoena']);
    expect(selectTerms('  SUBPOENA ', ' Breach ')).toEqual(['breach', 'subpoena']);
    expect(() => selectTerms('audit', ' AUDIT ')).toThrow(/distinct keywords/);
    expect(() => selectTerms('audit', 'not-indexed')).toThrow(/fixed indexed vocabulary/);
  });

  it('emits only a stag and one canonical nonidentity xtoken per s-term tuple', async () => {
    const query = await createOxtQuery(keys, 'audit', 'breach');
    expect(query.sTerm).toBe('breach');
    expect(query.xTerm).toBe('audit');
    expect(query.serverQuery.stag).toHaveLength(32);
    expect(query.serverQuery.xtokens).toHaveLength(documentsFor('breach').length);
    expect(Object.keys(query.serverQuery).sort()).toEqual(['stag', 'xtokens']);
    for (const token of query.serverQuery.xtokens) {
      expect(token).toHaveLength(32);
      const point = Point.fromBytes(token);
      expect(point.is0()).toBe(false);
      expect(toHex(point.toBytes())).toBe(toHex(token));
    }
  });

  it('makes repeated and operand-reversed conjunctions byte-identical at the server boundary', async () => {
    const first = await createOxtQuery(keys, 'breach', 'audit');
    const repeated = await createOxtQuery(keys, 'breach', 'audit');
    const reversed = await createOxtQuery(keys, 'audit', 'breach');
    for (const other of [repeated, reversed]) {
      expect(other.sTerm).toBe(first.sTerm);
      expect(other.xTerm).toBe(first.xTerm);
      expect(toHex(other.serverQuery.stag)).toBe(toHex(first.serverQuery.stag));
      expect(other.serverQuery.xtokens.map(toHex)).toEqual(first.serverQuery.xtokens.map(toHex));
    }
    expect(first.canonical).toBe('breach AND audit');
    expect(reversed.canonical).toBe('audit AND breach');
  });

  it('matches the plaintext intersection for all 91 keyword pairs in both operand orders', async () => {
    for (let i = 0; i < KEYWORDS.length; i++) {
      for (let j = i + 1; j < KEYWORDS.length; j++) {
        const left = KEYWORDS[i]!;
        const right = KEYWORDS[j]!;
        const expected = plaintextIntersection(left, right);
        const forward = await createOxtQuery(keys, left, right);
        const reversed = await createOxtQuery(keys, right, left);

        expect(await evaluateIndexQuery(keys, index, forward), `${left} AND ${right}`).toEqual(
          expected,
        );
        expect(await evaluateIndexQuery(keys, index, reversed), `${right} AND ${left}`).toEqual(
          expected,
        );
        expect(reversed.sTerm).toBe(forward.sTerm);
        expect(reversed.xTerm).toBe(forward.xTerm);
        expect(toHex(reversed.serverQuery.stag)).toBe(toHex(forward.serverQuery.stag));
        expect(reversed.serverQuery.xtokens.map(toHex)).toEqual(
          forward.serverQuery.xtokens.map(toHex),
        );
      }
    }
  }, 20_000);

  it('rejects duplicate or unindexed query terms before producing a query', async () => {
    await expect(createOxtQuery(keys, 'audit', ' AUDIT ')).rejects.toThrow(/distinct keywords/);
    await expect(createOxtQuery(keys, 'audit', 'not-indexed')).rejects.toThrow(
      /fixed indexed vocabulary/,
    );

    const incomplete = cloneCorpus();
    for (const document of incomplete) {
      document.keywords = document.keywords.filter((keyword) => keyword !== 'harassment');
    }
    await expect(createOxtQuery(keys, 'audit', 'breach', incomplete)).rejects.toThrow(
      /missing indexed keyword: harassment/,
    );
  });
});

describe('authenticated result decryption', () => {
  it('decrypts only exact XSet membership hits and sorts their document ids', async () => {
    const query = await createOxtQuery(keys, 'breach', 'audit');
    expect(await evaluateIndexQuery(keys, index, query)).toEqual(
      plaintextIntersection('breach', 'audit'),
    );
  });

  it('fails closed for a flipped ciphertext, a relocated row, a wrong key, and a partial answer', async () => {
    const query = await createOxtQuery(keys, 'harassment', 'audit');
    const matches = await matchingRows(index, query);
    expect(matches.length).toBeGreaterThan(0);

    const flipped = cloneMatch(matches[0]!);
    flipped.encryptedId[flipped.encryptedId.length - 1] ^= 0x01;
    await expect(decryptOxtMatches(keys, query, [flipped])).rejects.toBeTruthy();

    const relocated = cloneMatch(matches[0]!);
    relocated.addressHex = index.tsetRows.find(
      (row) => row.addressHex !== relocated.addressHex,
    )!.addressHex;
    await expect(decryptOxtMatches(keys, query, [relocated])).rejects.toBeTruthy();

    await expect(
      decryptOxtMatches({ ...keys, kEnc: new Uint8Array(32).fill(0xee) }, query, matches),
    ).rejects.toBeTruthy();

    const partial = matches.map(cloneMatch);
    partial[partial.length - 1]!.encryptedId[12] ^= 0x80;
    await expect(decryptOxtMatches(keys, query, partial)).rejects.toBeTruthy();
  });

  it('rejects malformed addresses, out-of-corpus plaintext ids, and replayed ids', async () => {
    const query = await createOxtQuery(keys, 'harassment', 'audit');
    const matches = await matchingRows(index, query);
    const malformed = { ...cloneMatch(matches[0]!), addressHex: 'not-hex' };
    await expect(decryptOxtMatches(keys, query, [malformed])).rejects.toThrow(/hex string/);

    const address = fromHex(matches[0]!.addressHex);
    const encryptionKey = await oxtPrf256(
      keys.kEnc,
      OXT_DOMAIN.ENCRYPTION_KEY,
      utf8(query.sTerm),
    );
    const invalidId: OxtEncryptedMatch = {
      position: matches[0]!.position,
      addressHex: matches[0]!.addressHex,
      encryptedId: await seal(encryptionKey, utf8('bad-id'), address),
    };
    await expect(decryptOxtMatches(keys, query, [invalidId])).rejects.toThrow(
      /not in the client corpus/,
    );

    const replayed = [cloneMatch(matches[0]!), cloneMatch(matches[0]!)];
    await expect(decryptOxtMatches(keys, query, replayed)).rejects.toThrow(/repeated a document id/);
  });

  it('demonstrates that an authentic s-list row is not an active-server x-membership proof', async () => {
    const query = await createOxtQuery(keys, 'breach', 'audit');
    const rowsByAddress = new Map(index.tsetRows.map((row) => [row.addressHex, row] as const));
    const xset = new Set(index.xset);
    let falseInclusion: OxtEncryptedMatch | undefined;

    for (let offset = 0; offset < query.serverQuery.xtokens.length; offset++) {
      const position = offset + 1;
      const addressHex = toHex(await tsetAddressFor(query.serverQuery.stag, position));
      const row = rowsByAddress.get(addressHex)!;
      const candidate = toHex(
        evaluateCrossToken(query.serverQuery.xtokens[offset]!, scalarFromBytes(row.y)),
      );
      if (!xset.has(candidate)) {
        falseInclusion = {
          position,
          addressHex,
          encryptedId: row.encryptedId.slice(),
        };
        break;
      }
    }

    if (!falseInclusion) throw new Error('test fixture needs an s-only document');
    const acceptedIds = await decryptOxtMatches(keys, query, [falseInclusion]);
    expect(acceptedIds).toHaveLength(1);
    expect(documentsFor(query.sTerm)).toContain(acceptedIds[0]);
    expect(documentsFor(query.xTerm)).not.toContain(acceptedIds[0]);
  });

  it('round-trips arbitrary nonempty custom-corpus ids only when the client supplies that corpus', async () => {
    const customCorpus = cloneCorpus();
    for (let index = 0; index < customCorpus.length; index++) {
      customCorpus[index]!.id = `record-${String(index + 1).padStart(3, '0')}`;
    }
    const customIndex = await buildOxtIndex(keys, customCorpus);
    const query = await createOxtQuery(keys, 'breach', 'audit', customCorpus);
    const matches = await matchingRows(customIndex, query);
    const expected = customCorpus
      .filter(
        (document) =>
          document.keywords.includes('breach') && document.keywords.includes('audit'),
      )
      .map((document) => document.id)
      .sort();

    await expect(decryptOxtMatches(keys, query, matches, customCorpus)).resolves.toEqual(expected);
    await expect(decryptOxtMatches(keys, query, matches)).rejects.toThrow(/not in the client corpus/);
  });

  it('returns an empty result for an empty authenticated response', async () => {
    const query = await createOxtQuery(keys, 'patent', 'harassment');
    await expect(decryptOxtMatches(keys, query, [])).resolves.toEqual([]);
  });
});

function fixedKeys(offset = 0): OxtKeys {
  return {
    kStag: new Uint8Array(32).fill(0x11 + offset),
    kEnc: new Uint8Array(32).fill(0x22 + offset),
    kX: new Uint8Array(32).fill(0x33 + offset),
    kId: new Uint8Array(32).fill(0x44 + offset),
    kZ: new Uint8Array(32).fill(0x55 + offset),
  };
}

function cloneCorpus(): Document[] {
  return CORPUS.map((document) => ({ ...document, keywords: [...document.keywords] }));
}

function plaintextIntersection(left: string, right: string): string[] {
  const rightIds = new Set(documentsFor(right));
  return documentsFor(left)
    .filter((id) => rightIds.has(id))
    .sort();
}

async function matchingRows(
  encryptedIndex: OxtEncryptedIndex,
  query: OxtClientQuery,
): Promise<OxtEncryptedMatch[]> {
  const rowsByAddress = new Map(
    encryptedIndex.tsetRows.map((row) => [row.addressHex, row] as const),
  );
  const xset = new Set(encryptedIndex.xset);
  const matches: OxtEncryptedMatch[] = [];
  for (let offset = 0; offset < query.serverQuery.xtokens.length; offset++) {
    const position = offset + 1;
    const addressHex = toHex(await tsetAddressFor(query.serverQuery.stag, position));
    const row = rowsByAddress.get(addressHex);
    if (!row) throw new Error(`test fixture is missing TSet row ${position}`);
    const candidate = toHex(
      evaluateCrossToken(query.serverQuery.xtokens[offset]!, scalarFromBytes(row.y)),
    );
    if (xset.has(candidate)) {
      matches.push({
        position,
        addressHex,
        encryptedId: row.encryptedId.slice(),
      });
    }
  }
  return matches;
}

async function evaluateIndexQuery(
  clientKeys: OxtKeys,
  encryptedIndex: OxtEncryptedIndex,
  query: OxtClientQuery,
  corpus: readonly Document[] = CORPUS,
): Promise<string[]> {
  return decryptOxtMatches(clientKeys, query, await matchingRows(encryptedIndex, query), corpus);
}

function cloneMatch(match: OxtEncryptedMatch): OxtEncryptedMatch & { addressHex: string; encryptedId: Uint8Array } {
  return {
    position: match.position,
    addressHex: match.addressHex,
    encryptedId: match.encryptedId.slice(),
  };
}
