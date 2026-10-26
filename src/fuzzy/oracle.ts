/**
 * Independent plaintext oracle for Exhibit 9's error ledger.
 *
 * The client filter in client.ts calls the rolling-row implementation in
 * core.ts. This oracle deliberately uses a full dynamic-programming matrix so
 * the learner-visible accuracy comparison does not reuse that implementation.
 */
import { normalizeFuzzyWord } from './core';

export function oracleLevenshteinDistance(leftInput: string, rightInput: string): number {
  const left = normalizeFuzzyWord(leftInput);
  const right = normalizeFuzzyWord(rightInput);
  const width = right.length + 1;
  const matrix = new Uint16Array((left.length + 1) * width);

  for (let row = 0; row <= left.length; row++) matrix[row * width] = row;
  for (let column = 0; column <= right.length; column++) matrix[column] = column;

  for (let row = 1; row <= left.length; row++) {
    for (let column = 1; column <= right.length; column++) {
      const offset = row * width + column;
      const deletion = matrix[(row - 1) * width + column]! + 1;
      const insertion = matrix[row * width + column - 1]! + 1;
      const substitution = matrix[(row - 1) * width + column - 1]!
        + (left[row - 1] === right[column - 1] ? 0 : 1);
      matrix[offset] = Math.min(deletion, insertion, substitution);
    }
  }

  return matrix[left.length * width + right.length]!;
}
