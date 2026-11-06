/**
 * A uniform draw below a bound, by rejection.
 *
 * `shuffle` in client.ts randomises the SSE index rows before they reach the server,
 * and that shuffle is the only thing stopping the row ORDER from saying which
 * document-keyword pair each row belongs to. It drew its Fisher-Yates index with
 * `crypto.getRandomValues(new Uint32Array(1))[0]! % (i + 1)`, and CodeQL flagged the
 * modulo: js/biased-cryptographic-random, `src/sse/client.ts:127`.
 *
 * The bias is small and it is real. One 32-bit draw has 2^32 outcomes; for a bound that
 * does not divide 2^32 -- which is every bound here except the powers of two -- the low
 * residues have one more preimage than the high ones, so early positions are very
 * slightly likelier to receive low indices. In a shuffle whose whole job is to carry no
 * information about the input order, "very slightly likelier" is the wrong kind of
 * defect to argue about; rejection removes it rather than bounding it.
 *
 * `rejectionLimit` is the largest multiple of the bound that fits one draw. Everything
 * at or above it is the tail that would make the low residues likelier, so it is
 * discarded and drawn again, and the residues that survive are equally likely for ANY
 * bound. The bound is validated rather than assumed, which is the part that would
 * otherwise fail silently.
 */

/** The number of distinct values one 32-bit draw can take. */
export const DRAW_RANGE = 0x1_0000_0000;

/** Fills `out` with cryptographically random 32-bit values. */
export type Uint32Source = (out: Uint32Array<ArrayBuffer>) => void;

export const cryptoUint32Source: Uint32Source = (out) => {
  crypto.getRandomValues(out);
};

/**
 * The largest multiple of `bound` that fits in one 32-bit draw. Draws at or above it
 * are the tail that would make the low residues likelier, so they are rejected.
 */
export function rejectionLimit(bound: number): number {
  return DRAW_RANGE - (DRAW_RANGE % bound);
}

/** A uniform integer in [0, bound), with no modulo bias for any bound in range. */
export function randomBelow(bound: number, source: Uint32Source = cryptoUint32Source): number {
  if (!Number.isInteger(bound) || bound < 1 || bound > DRAW_RANGE) {
    throw new RangeError(`bound must be an integer in [1, ${DRAW_RANGE}]`);
  }
  const limit = rejectionLimit(bound);
  const draw = new Uint32Array(1) as Uint32Array<ArrayBuffer>;
  for (;;) {
    source(draw);
    if (draw[0]! < limit) return draw[0]! % bound;
  }
}
