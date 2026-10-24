/**
 * Bounded offline keyword-guessing attack against an exposed PEKS trapdoor.
 *
 * The attacker needs only public inputs: recipient public key, captured
 * trapdoor, candidate words, and the public PEKS/Test algorithms. For every
 * guess it creates a valid fresh PEKS tag, then tests the captured trapdoor
 * against that tag. No recipient secret, plaintext truth, or server oracle is
 * accepted by this interface.
 */
import { encryptKeyword, normalizePeksKeyword, testTag, type PeksPublicKey, type PeksTag, type PeksTrapdoor } from './core';

export interface DictionaryAttackInput {
  readonly publicKey: PeksPublicKey;
  readonly exposedTrapdoor: PeksTrapdoor;
  readonly candidates: readonly string[];
  readonly maxGuesses: number;
}

export interface DictionaryAttempt {
  readonly candidate: string;
  readonly tag: PeksTag;
  readonly matched: boolean;
}

export interface DictionaryAttackResult {
  readonly status: 'recovered' | 'not-recovered-within-bound';
  readonly recoveredKeyword: string | null;
  readonly attempts: readonly DictionaryAttempt[];
  readonly bound: number;
  readonly availableCandidates: number;
}

export interface DictionaryAttackOptions {
  /** Browser UI hook: yield after each expensive pairing trial. */
  readonly afterAttempt?: (attempt: DictionaryAttempt) => void | Promise<void>;
  /** Optional UI cancellation boundary; not part of the attacker's inputs. */
  readonly signal?: AbortSignal;
}

export async function runBoundedDictionaryAttack(
  input: DictionaryAttackInput,
  options: DictionaryAttackOptions = {},
): Promise<DictionaryAttackResult> {
  if (!Number.isSafeInteger(input.maxGuesses) || input.maxGuesses < 0) {
    throw new Error('dictionary bound must be a non-negative safe integer');
  }

  const candidates = uniqueNormalized(input.candidates);
  const limit = Math.min(input.maxGuesses, candidates.length);
  const attempts: DictionaryAttempt[] = [];

  for (let i = 0; i < limit; i++) {
    options.signal?.throwIfAborted();
    const candidate = candidates[i]!;
    const tag = await encryptKeyword(input.publicKey, candidate);
    options.signal?.throwIfAborted();
    const attempt: DictionaryAttempt = {
      candidate,
      tag,
      matched: await testTag(tag, input.exposedTrapdoor),
    };
    options.signal?.throwIfAborted();
    attempts.push(attempt);
    await options.afterAttempt?.(attempt);
    options.signal?.throwIfAborted();
    if (attempt.matched) {
      return {
        status: 'recovered',
        recoveredKeyword: candidate,
        attempts,
        bound: input.maxGuesses,
        availableCandidates: candidates.length,
      };
    }
  }

  return {
    status: 'not-recovered-within-bound',
    recoveredKeyword: null,
    attempts,
    bound: input.maxGuesses,
    availableCandidates: candidates.length,
  };
}

function uniqueNormalized(candidates: readonly string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const candidate of candidates) {
    const normalized = normalizePeksKeyword(candidate);
    if (seen.has(normalized)) continue;
    seen.add(normalized);
    out.push(normalized);
  }
  return out;
}
