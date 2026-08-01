/**
 * The pseudorandom function behind every label in the encrypted index:
 * HMAC-SHA-256 (FIPS 198-1 / RFC 2104), via WebCrypto — real, not modelled.
 *
 * SSE needs exactly one property from this: given F_K(w) for keywords the
 * client has searched, an adversary who never sees K cannot distinguish
 * F_K(w') for an unqueried w' from a random 32-byte string. Every "the server
 * learns nothing about the keyword" claim in this demo reduces to that.
 */
import { concat, frame } from './bytes';

/** Domain-separation tags. Distinct keys/labels must never come from the
 *  same PRF input, or the separation the security argument assumes is a lie. */
export const DOMAIN = {
  /** search token: t_w = F_{K_prf}(w) — the only value the server ever receives */
  TOKEN: 'crypto-lab/search-vault/v1/token',
  /** per-keyword posting key: k_w = F_{K_enc}(w) */
  POSTING_KEY: 'crypto-lab/search-vault/v1/posting-key',
  /** index address: addr_i = F_{t_w}(counter i) */
  ADDRESS: 'crypto-lab/search-vault/v1/address',
  /** document body key: k_d = F_{K_doc}(docId) */
  DOC_KEY: 'crypto-lab/search-vault/v1/doc-key',
} as const;

export async function importHmacKey(keyBytes: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    keyBytes as unknown as BufferSource,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
}

/** Raw HMAC-SHA-256 over exactly the bytes given — the shape the RFC 4231
 *  known-answer tests exercise. */
export async function hmacSha256(key: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  const k = await importHmacKey(key);
  const mac = await crypto.subtle.sign('HMAC', k, message as unknown as BufferSource);
  return new Uint8Array(mac);
}

/**
 * The PRF as this demo uses it: a domain tag plus length-framed inputs, so
 * F_K("address", t, 1) can never equal F_K("token", …) for any other split.
 */
export async function prf(
  key: Uint8Array,
  domain: string,
  ...inputs: Uint8Array[]
): Promise<Uint8Array> {
  const msg = concat(new TextEncoder().encode(domain), frame(...inputs));
  return hmacSha256(key, msg);
}

export async function sha256(message: Uint8Array): Promise<Uint8Array> {
  const d = await crypto.subtle.digest('SHA-256', message as unknown as BufferSource);
  return new Uint8Array(d);
}
