/** Exact integer and Paillier arithmetic for the bounded MUSE lesson. */
import { ctEqual, randomBytes } from '../core/bytes';

export interface PaillierPublicKey {
  readonly n: bigint;
  readonly nSquared: bigint;
  readonly modulusBits: number;
}

export interface PaillierPrivateKey {
  readonly lambda: bigint;
  readonly mu: bigint;
}

export interface PaillierKeyPair {
  readonly publicKey: PaillierPublicKey;
  readonly privateKey: PaillierPrivateKey;
}

export interface PackedSelector {
  readonly slotCount: number;
  readonly selectedPositions: readonly number[];
  readonly shareBits: number;
  readonly ciphertexts: readonly bigint[];
}

export async function generatePaillierKeyPair(modulusBits = 1024): Promise<PaillierKeyPair> {
  if (!Number.isSafeInteger(modulusBits) || modulusBits < 1024 || modulusBits % 256 !== 0) {
    throw new Error('Paillier teaching modulus must be a multiple of 256 and at least 1024 bits');
  }

  // WebCrypto supplies independently generated odd primes and does not expose
  // a standalone prime generator. No RSA encryption is performed: its JWK p/q
  // values are immediately re-derived as a fresh Paillier key.
  for (let attempt = 0; attempt < 4; attempt++) {
    const rsa = await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: modulusBits,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['encrypt', 'decrypt'],
    );
    const jwk = await crypto.subtle.exportKey('jwk', rsa.privateKey);
    if (!jwk.p || !jwk.q) throw new Error('WebCrypto did not export RSA prime factors');
    const pair = derivePaillierKeyPair(base64UrlToBigInt(jwk.p), base64UrlToBigInt(jwk.q));
    if (pair.publicKey.modulusBits >= modulusBits - 1) return pair;
  }
  throw new Error('could not derive the requested Paillier modulus size');
}

/** Deterministic derivation for independent arithmetic tests. */
export function derivePaillierKeyPair(p: bigint, q: bigint): PaillierKeyPair {
  if (p <= 2n || q <= 2n || p === q || p % 2n === 0n || q % 2n === 0n) {
    throw new Error('Paillier factors must be distinct odd integers greater than two');
  }
  const n = p * q;
  const lambda = lcm(p - 1n, q - 1n);
  if (gcd(lambda, n) !== 1n) throw new Error('Paillier factors do not yield invertible lambda');
  return {
    publicKey: {
      n,
      nSquared: n * n,
      modulusBits: bitLength(n),
    },
    privateKey: {
      lambda,
      // With g=n+1, L(g^lambda mod n²) = lambda mod n.
      mu: modInverse(lambda, n),
    },
  };
}

export function paillierEncrypt(
  key: PaillierPublicKey,
  message: bigint,
  randomness?: bigint,
): bigint {
  assertPaillierMessage(key, message);
  const r = randomness ?? randomCoprimeBelow(key.n);
  if (r <= 0n || r >= key.n || gcd(r, key.n) !== 1n) {
    throw new Error('Paillier randomness must be in Z_n*');
  }
  // (n+1)^m = 1+nm mod n², avoiding one unnecessary large exponentiation.
  const gm = (1n + key.n * message) % key.nSquared;
  return (gm * modPow(r, key.n, key.nSquared)) % key.nSquared;
}

export function paillierDecrypt(keyPair: PaillierKeyPair, ciphertext: bigint): bigint {
  assertPaillierCiphertext(keyPair.publicKey, ciphertext);
  const u = modPow(ciphertext, keyPair.privateKey.lambda, keyPair.publicKey.nSquared);
  const numerator = u - 1n;
  if (numerator % keyPair.publicKey.n !== 0n) {
    throw new Error('malformed Paillier ciphertext');
  }
  return ((numerator / keyPair.publicKey.n) * keyPair.privateKey.mu) % keyPair.publicKey.n;
}

/** Homomorphically select and pack fixed-width array cells. */
export function applyPackedSelector(
  key: PaillierPublicKey,
  selector: PackedSelector,
  cells: readonly Uint8Array[],
  sanitize = true,
): bigint {
  if (selector.slotCount !== cells.length || selector.ciphertexts.length !== cells.length) {
    throw new Error('selector and ZGBF dimensions differ');
  }
  const expectedBytes = selector.shareBits / 8;
  if (!Number.isSafeInteger(expectedBytes) || expectedBytes <= 0 || selector.shareBits % 8 !== 0) {
    throw new Error('packed share width must be a positive whole number of bytes');
  }
  let response = 1n;
  for (let index = 0; index < cells.length; index++) {
    const cell = cells[index]!;
    if (cell.length !== expectedBytes) throw new Error('ZGBF cell has the wrong width');
    const queryCiphertext = selector.ciphertexts[index]!;
    assertPaillierCiphertext(key, queryCiphertext);
    response = (response * modPow(queryCiphertext, bytesToBigInt(cell), key.nSquared)) % key.nSquared;
  }
  // Lipmaa's sanitization step: multiply by an independent Enc(0), so a
  // response cannot be linked to the exact query ciphertexts that produced it.
  return sanitize
    ? (response * paillierEncrypt(key, 0n)) % key.nSquared
    : response;
}

export function createPackedSelector(
  key: PaillierPublicKey,
  slotCount: number,
  selectedPositions: readonly number[],
  shareBits: number,
): PackedSelector {
  if (!Number.isSafeInteger(slotCount) || slotCount <= 0) {
    throw new Error('selector slot count must be a positive safe integer');
  }
  if (!Number.isSafeInteger(shareBits) || shareBits <= 0 || shareBits % 8 !== 0) {
    throw new Error('selector share width must be a positive whole number of bytes');
  }
  if (selectedPositions.length === 0 || new Set(selectedPositions).size !== selectedPositions.length) {
    throw new Error('selector positions must be non-empty and distinct');
  }
  for (const position of selectedPositions) {
    if (!Number.isSafeInteger(position) || position < 0 || position >= slotCount) {
      throw new Error('selector position is outside the ZGBF');
    }
  }
  const packedBits = shareBits * selectedPositions.length;
  if (packedBits >= key.modulusBits - 1) {
    throw new Error('packed selector plaintext does not fit the Paillier modulus');
  }
  const coefficients = new Map<number, bigint>();
  selectedPositions.forEach((position, order) => {
    coefficients.set(position, 1n << BigInt(order * shareBits));
  });
  return {
    slotCount,
    selectedPositions: [...selectedPositions],
    shareBits,
    ciphertexts: Array.from({ length: slotCount }, (_, position) =>
      paillierEncrypt(key, coefficients.get(position) ?? 0n),
    ),
  };
}

export function openPackedResponse(
  keyPair: PaillierKeyPair,
  response: bigint,
  shareCount: number,
  shareBits: number,
): Uint8Array[] {
  if (!Number.isSafeInteger(shareCount) || shareCount <= 0) {
    throw new Error('share count must be a positive safe integer');
  }
  if (!Number.isSafeInteger(shareBits) || shareBits <= 0 || shareBits % 8 !== 0) {
    throw new Error('share width must be a positive whole number of bytes');
  }
  let plaintext = paillierDecrypt(keyPair, response);
  const mask = (1n << BigInt(shareBits)) - 1n;
  const byteLength = shareBits / 8;
  const shares: Uint8Array[] = [];
  for (let index = 0; index < shareCount; index++) {
    shares.push(bigIntToBytes(plaintext & mask, byteLength));
    plaintext >>= BigInt(shareBits);
  }
  if (plaintext !== 0n) throw new Error('Paillier response has data outside the packed share range');
  return shares;
}

export function ciphertextBytes(key: PaillierPublicKey, ciphertext: bigint): Uint8Array {
  assertPaillierCiphertext(key, ciphertext);
  return bigIntToBytes(ciphertext, Math.ceil(bitLength(key.nSquared) / 8));
}

export function equalCiphertextBytes(
  key: PaillierPublicKey,
  left: bigint,
  right: bigint,
): boolean {
  return ctEqual(ciphertextBytes(key, left), ciphertextBytes(key, right));
}

export function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  if (modulus <= 0n || exponent < 0n) throw new Error('invalid modular exponentiation input');
  let value = ((base % modulus) + modulus) % modulus;
  let power = exponent;
  let out = 1n % modulus;
  while (power > 0n) {
    if (power & 1n) out = (out * value) % modulus;
    value = (value * value) % modulus;
    power >>= 1n;
  }
  return out;
}

export function modInverse(value: bigint, modulus: bigint): bigint {
  if (modulus <= 1n) throw new Error('modulus must be greater than one');
  let [oldR, r] = [((value % modulus) + modulus) % modulus, modulus];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const quotient = oldR / r;
    [oldR, r] = [r, oldR - quotient * r];
    [oldS, s] = [s, oldS - quotient * s];
  }
  if (oldR !== 1n) throw new Error('value is not invertible modulo the modulus');
  return ((oldS % modulus) + modulus) % modulus;
}

export function gcd(left: bigint, right: bigint): bigint {
  let a = left < 0n ? -left : left;
  let b = right < 0n ? -right : right;
  while (b !== 0n) [a, b] = [b, a % b];
  return a;
}

export function bytesToBigInt(bytes: Uint8Array): bigint {
  let out = 0n;
  for (const byte of bytes) out = (out << 8n) | BigInt(byte);
  return out;
}

export function bigIntToBytes(value: bigint, length: number): Uint8Array {
  if (value < 0n || !Number.isSafeInteger(length) || length < 0) {
    throw new Error('invalid integer encoding request');
  }
  const out = new Uint8Array(length);
  let remaining = value;
  for (let index = length - 1; index >= 0; index--) {
    out[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  if (remaining !== 0n) throw new Error('integer does not fit requested byte length');
  return out;
}

function lcm(left: bigint, right: bigint): bigint {
  return (left / gcd(left, right)) * right;
}

function bitLength(value: bigint): number {
  if (value < 0n) value = -value;
  return value === 0n ? 0 : value.toString(2).length;
}

function randomCoprimeBelow(modulus: bigint): bigint {
  const length = Math.ceil(bitLength(modulus) / 8);
  while (true) {
    const candidate = bytesToBigInt(randomBytes(length));
    if (candidate > 0n && candidate < modulus && gcd(candidate, modulus) === 1n) return candidate;
  }
}

function assertPaillierMessage(key: PaillierPublicKey, message: bigint): void {
  if (message < 0n || message >= key.n) throw new Error('Paillier plaintext must be in Z_n');
}

function assertPaillierCiphertext(key: PaillierPublicKey, ciphertext: bigint): void {
  if (ciphertext <= 0n || ciphertext >= key.nSquared || gcd(ciphertext, key.n) !== 1n) {
    throw new Error('Paillier ciphertext must be in Z_n²*');
  }
}

function base64UrlToBigInt(value: string): bigint {
  const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  return bytesToBigInt(bytes);
}
