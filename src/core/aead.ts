/**
 * AES-256-GCM (NIST SP 800-38D) via WebCrypto — the confidentiality layer for
 * index postings and document bodies.
 *
 * Every ciphertext carries its own 96-bit random IV. GCM is catastrophically
 * broken by IV reuse under one key, so the IV is generated per call and never
 * derived from the plaintext; a caller cannot supply one by accident.
 */
import { concat, randomBytes } from './bytes';

export const IV_LENGTH = 12;
export const TAG_BITS = 128;

async function importAesKey(keyBytes: Uint8Array, usage: KeyUsage[]): Promise<CryptoKey> {
  if (keyBytes.length !== 32) throw new Error(`AES-256 needs a 32-byte key, got ${keyBytes.length}`);
  return crypto.subtle.importKey(
    'raw',
    keyBytes as unknown as BufferSource,
    { name: 'AES-GCM' },
    false,
    usage,
  );
}

/** Encrypt, returning iv‖ciphertext‖tag as one blob (what the server stores). */
export async function seal(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  const iv = randomBytes(IV_LENGTH);
  const ct = await gcmEncrypt(key, iv, plaintext, aad);
  return concat(iv, ct);
}

/**
 * Decrypt iv‖ciphertext‖tag. Fail-closed: a tampered posting, a wrong key, or
 * a truncated blob throws — it never returns partial or unauthenticated bytes.
 */
export async function open(
  key: Uint8Array,
  blob: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  if (blob.length < IV_LENGTH + TAG_BITS / 8) throw new Error('ciphertext too short to be valid');
  const iv = blob.slice(0, IV_LENGTH);
  const body = blob.slice(IV_LENGTH);
  return gcmDecrypt(key, iv, body, aad);
}

/** Explicit-IV form — only for known-answer tests against the GCM spec. */
export async function gcmEncrypt(
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  const k = await importAesKey(key, ['encrypt']);
  const params: AesGcmParams = {
    name: 'AES-GCM',
    iv: iv as unknown as BufferSource,
    tagLength: TAG_BITS,
  };
  if (aad) params.additionalData = aad as unknown as BufferSource;
  const ct = await crypto.subtle.encrypt(params, k, plaintext as unknown as BufferSource);
  return new Uint8Array(ct);
}

export async function gcmDecrypt(
  key: Uint8Array,
  iv: Uint8Array,
  ciphertextAndTag: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  const k = await importAesKey(key, ['decrypt']);
  const params: AesGcmParams = {
    name: 'AES-GCM',
    iv: iv as unknown as BufferSource,
    tagLength: TAG_BITS,
  };
  if (aad) params.additionalData = aad as unknown as BufferSource;
  const pt = await crypto.subtle.decrypt(params, k, ciphertextAndTag as unknown as BufferSource);
  return new Uint8Array(pt);
}
