import { describe, expect, it } from 'vitest';
import { fromHex, toHex, utf8, fromUtf8 } from './bytes';
import { gcmDecrypt, gcmEncrypt, open, seal } from './aead';

/**
 * AES-256-GCM known-answer tests from the GCM specification's test-vector set
 * (McGrew & Viega, adopted in NIST SP 800-38D validation material). Cases 13
 * and 14 are the AES-256 all-zero-key vectors; they pin the exact
 * ciphertext-and-tag bytes WebCrypto produces for a fixed IV.
 */
describe('AES-256-GCM — GCM specification known-answer tests', () => {
  const zeroKey = new Uint8Array(32);
  const zeroIv = new Uint8Array(12);

  it('Test Case 13 — empty plaintext, empty AAD (tag only)', async () => {
    const out = await gcmEncrypt(zeroKey, zeroIv, new Uint8Array(0));
    expect(toHex(out)).toBe('530f8afbc74536b9a963b4f1c4cb738b');
  });

  it('Test Case 14 — one all-zero block', async () => {
    const out = await gcmEncrypt(zeroKey, zeroIv, new Uint8Array(16));
    expect(toHex(out)).toBe('cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919');
  });

  it('decrypts Test Case 14 back to the all-zero block', async () => {
    const pt = await gcmDecrypt(
      zeroKey,
      zeroIv,
      fromHex('cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919'),
    );
    expect(toHex(pt)).toBe(toHex(new Uint8Array(16)));
  });
});

describe('sealed postings and documents', () => {
  const key = new Uint8Array(32).fill(0x2a);

  it('round-trips a document body', async () => {
    const blob = await seal(key, utf8('Q3 compensation review — final'));
    expect(fromUtf8(await open(key, blob))).toBe('Q3 compensation review — final');
  });

  it('never reuses an IV across two seals of the same plaintext', async () => {
    const a = await seal(key, utf8('same'));
    const b = await seal(key, utf8('same'));
    // Distinct IVs mean distinct ciphertexts: the server cannot tell that two
    // postings hold the same document id by comparing the stored bytes.
    expect(toHex(a)).not.toBe(toHex(b));
    expect(toHex(a.slice(0, 12))).not.toBe(toHex(b.slice(0, 12)));
  });

  it('fails closed on a flipped ciphertext bit', async () => {
    const blob = await seal(key, utf8('d07'));
    blob[blob.length - 3] ^= 0x01;
    await expect(open(key, blob)).rejects.toBeTruthy();
  });

  it('fails closed on a tampered IV', async () => {
    const blob = await seal(key, utf8('d07'));
    blob[0] ^= 0x80;
    await expect(open(key, blob)).rejects.toBeTruthy();
  });

  it('fails closed under the wrong keyword key', async () => {
    const blob = await seal(key, utf8('d07'));
    await expect(open(new Uint8Array(32).fill(0x2b), blob)).rejects.toBeTruthy();
  });

  it('fails closed on a truncated blob', async () => {
    await expect(open(key, new Uint8Array(8))).rejects.toThrow(/too short/);
  });

  it('binds associated data — a posting moved to another address will not open', async () => {
    const blob = await seal(key, utf8('d07'), utf8('address-A'));
    await expect(open(key, blob, utf8('address-B'))).rejects.toBeTruthy();
    expect(fromUtf8(await open(key, blob, utf8('address-A')))).toBe('d07');
  });

  it('rejects a key that is not 32 bytes', async () => {
    await expect(seal(new Uint8Array(16), utf8('x'))).rejects.toThrow(/32-byte key/);
  });
});
