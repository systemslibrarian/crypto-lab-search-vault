import { beforeAll, describe, expect, it } from 'vitest';
import { toHex } from '../core/bytes';
import { derivePeksKeyPair, issueTrapdoor, type PeksKeyPair } from './core';
import { runBoundedDictionaryAttack } from './dictionary';

let recipient: PeksKeyPair;

beforeAll(() => {
  recipient = derivePeksKeyPair(59n);
});

describe('bounded offline keyword guessing', () => {
  it('recovers an in-dictionary keyword at the first passing candidate', async () => {
    const result = await runBoundedDictionaryAttack({
      publicKey: recipient.publicKey,
      exposedTrapdoor: issueTrapdoor(recipient.secretKey, 'audit'),
      candidates: ['budget', 'merger', 'audit', 'salary', 'breach'],
      maxGuesses: 5,
    });
    expect(result.status).toBe('recovered');
    expect(result.recoveredKeyword).toBe('audit');
    expect(result.attempts.map((attempt) => attempt.candidate)).toEqual([
      'budget',
      'merger',
      'audit',
    ]);
    expect(result.attempts.map((attempt) => attempt.matched)).toEqual([false, false, true]);
  });

  it('reports only bounded non-recovery when the target is absent', async () => {
    const result = await runBoundedDictionaryAttack({
      publicKey: recipient.publicKey,
      exposedTrapdoor: issueTrapdoor(recipient.secretKey, 'audit'),
      candidates: ['budget', 'merger', 'salary', 'breach'],
      maxGuesses: 4,
    });
    expect(result.status).toBe('not-recovered-within-bound');
    expect(result.recoveredKeyword).toBeNull();
    expect(result.attempts).toHaveLength(4);
    expect(result.attempts.every((attempt) => !attempt.matched)).toBe(true);
  });

  it('honors a bound that stops before the correct candidate', async () => {
    const result = await runBoundedDictionaryAttack({
      publicKey: recipient.publicKey,
      exposedTrapdoor: issueTrapdoor(recipient.secretKey, 'audit'),
      candidates: ['budget', 'merger', 'audit'],
      maxGuesses: 2,
    });
    expect(result.status).toBe('not-recovered-within-bound');
    expect(result.attempts.map((attempt) => attempt.candidate)).toEqual(['budget', 'merger']);
  });

  it('supports the zero-guess boundary without pretending it established security', async () => {
    const result = await runBoundedDictionaryAttack({
      publicKey: recipient.publicKey,
      exposedTrapdoor: issueTrapdoor(recipient.secretKey, 'audit'),
      candidates: ['audit'],
      maxGuesses: 0,
    });
    expect(result.status).toBe('not-recovered-within-bound');
    expect(result.attempts).toEqual([]);
    expect(result.availableCandidates).toBe(1);
  });

  it('normalizes and deduplicates candidates before spending the bound', async () => {
    const result = await runBoundedDictionaryAttack({
      publicKey: recipient.publicKey,
      exposedTrapdoor: issueTrapdoor(recipient.secretKey, 'audit'),
      candidates: [' Budget ', 'budget', ' AUDIT '],
      maxGuesses: 3,
    });
    expect(result.availableCandidates).toBe(2);
    expect(result.attempts.map((attempt) => attempt.candidate)).toEqual(['budget', 'audit']);
    expect(result.recoveredKeyword).toBe('audit');
  });

  it('has no secret or ground-truth input and produces fresh public tags', async () => {
    const input = {
      publicKey: recipient.publicKey,
      exposedTrapdoor: issueTrapdoor(recipient.secretKey, 'audit'),
      candidates: ['audit'],
      maxGuesses: 1,
    };
    expect(Object.keys(input).sort()).toEqual([
      'candidates',
      'exposedTrapdoor',
      'maxGuesses',
      'publicKey',
    ]);
    const first = await runBoundedDictionaryAttack(input);
    const second = await runBoundedDictionaryAttack(input);
    expect(first.status).toBe('recovered');
    expect(second.status).toBe('recovered');
    expect(toHex(first.attempts[0]!.tag.a)).not.toBe(toHex(second.attempts[0]!.tag.a));
  });

  it('does not recover under a trapdoor from another recipient', async () => {
    const other = derivePeksKeyPair(61n);
    const result = await runBoundedDictionaryAttack({
      publicKey: recipient.publicKey,
      exposedTrapdoor: issueTrapdoor(other.secretKey, 'audit'),
      candidates: ['audit'],
      maxGuesses: 1,
    });
    expect(result.status).toBe('not-recovered-within-bound');
  });

  it('stops before a second guess when the caller cancels after the first attempt', async () => {
    const controller = new AbortController();
    let callbacks = 0;
    await expect(
      runBoundedDictionaryAttack(
        {
          publicKey: recipient.publicKey,
          exposedTrapdoor: issueTrapdoor(recipient.secretKey, 'audit'),
          candidates: ['budget', 'merger', 'audit'],
          maxGuesses: 3,
        },
        {
          signal: controller.signal,
          afterAttempt: () => {
            callbacks += 1;
            controller.abort();
          },
        },
      ),
    ).rejects.toThrow(/aborted/i);
    expect(callbacks).toBe(1);
  });

  it('rejects malformed bounds and empty candidate words', async () => {
    const base = {
      publicKey: recipient.publicKey,
      exposedTrapdoor: issueTrapdoor(recipient.secretKey, 'audit'),
      candidates: ['audit'],
    };
    await expect(runBoundedDictionaryAttack({ ...base, maxGuesses: -1 })).rejects.toThrow(
      /non-negative/,
    );
    await expect(
      runBoundedDictionaryAttack({ ...base, candidates: ['  '], maxGuesses: 1 }),
    ).rejects.toThrow(/must not be empty/);
  });
});
