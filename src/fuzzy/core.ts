/**
 * Bounded string and transcript operations for Exhibit 9.
 *
 * Li et al. ePrint 2009/593, Algorithm 2 constructs a "gram" set by deleting
 * up to d characters while preserving the order of every remaining character.
 * These are subsequences rather than only contiguous n-grams.  The same paper
 * proves completeness for this matching rule and explicitly notes that it can
 * return false positives, which the client must filter with the real edit
 * distance.
 */

export const FUZZY_THRESHOLDS = [0, 1, 2] as const;
export type FuzzyThreshold = (typeof FUZZY_THRESHOLDS)[number];

export class FuzzyInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FuzzyInputError';
  }
}

/** Case and surrounding whitespace are normalized before fuzzy matching.
 * Normalization itself is not counted as an edit. */
export function normalizeFuzzyWord(input: string): string {
  const normalized = input.trim().toLowerCase();
  if (!normalized) throw new FuzzyInputError('Enter a word to search.');
  if (!/^[a-z]+$/.test(normalized)) {
    throw new FuzzyInputError('Use ASCII letters a–z only in this bounded lesson.');
  }
  if (normalized.length < 3 || normalized.length > 12) {
    throw new FuzzyInputError('Use a word from 3 through 12 letters.');
  }
  return normalized;
}

export function assertFuzzyThreshold(value: number): asserts value is FuzzyThreshold {
  if (!FUZZY_THRESHOLDS.includes(value as FuzzyThreshold)) {
    throw new FuzzyInputError('The edit threshold must be 0, 1, or 2.');
  }
}

/** Every relative-order-preserving subsequence formed by deleting 0..d
 * characters. Duplicate subsequences caused by repeated letters occur once. */
export function deletionGramSet(input: string, threshold: FuzzyThreshold): string[] {
  const word = normalizeFuzzyWord(input);
  assertFuzzyThreshold(threshold);
  if (threshold > word.length) {
    throw new FuzzyInputError('The edit threshold cannot exceed the word length.');
  }

  const grams = new Set<string>();
  for (let removed = 0; removed <= threshold; removed++) {
    visitRemovalCombinations(word, removed, 0, [], grams);
  }
  return [...grams].sort();
}

function visitRemovalCombinations(
  word: string,
  remaining: number,
  start: number,
  removed: number[],
  out: Set<string>,
): void {
  if (remaining === 0) {
    const removedSet = new Set(removed);
    let gram = '';
    for (let index = 0; index < word.length; index++) {
      if (!removedSet.has(index)) gram += word[index]!;
    }
    out.add(gram);
    return;
  }

  for (let index = start; index <= word.length - remaining; index++) {
    removed.push(index);
    visitRemovalCombinations(word, remaining - 1, index + 1, removed, out);
    removed.pop();
  }
}

/** Unit-cost Levenshtein distance: insertion, deletion, and substitution.
 * A transposition is two edits; Damerau–Levenshtein is deliberately not used. */
export function levenshteinDistance(leftInput: string, rightInput: string): number {
  const left = normalizeFuzzyWord(leftInput);
  const right = normalizeFuzzyWord(rightInput);
  let previous = Array.from({ length: right.length + 1 }, (_, index) => index);

  for (let row = 1; row <= left.length; row++) {
    const current = [row];
    for (let column = 1; column <= right.length; column++) {
      const substitution = previous[column - 1]! +
        (left[row - 1] === right[column - 1] ? 0 : 1);
      current[column] = Math.min(
        current[column - 1]! + 1,
        previous[column]! + 1,
        substitution,
      );
    }
    previous = current;
  }
  return previous[right.length]!;
}

export interface ObservedQueryBundle {
  /** A prior query label known through declared outside context. */
  readonly label: string;
  readonly exactTokenHex: string;
  readonly fuzzyTokenHexes: readonly string[];
}

export interface AnchorOverlap {
  readonly label: string;
  readonly exactTokenEqual: boolean;
  readonly fuzzyIntersection: number;
  readonly fuzzyUnion: number;
}

export interface NeighborhoodInference {
  readonly overlaps: readonly AnchorOverlap[];
  /** Present only when one positive overlap is strictly largest. */
  readonly inferredAnchor: string | null;
  readonly ambiguous: boolean;
}

/**
 * Honest-but-curious server-side inference from observed bytes only.
 *
 * No query text, key, gram, plaintext candidate, edit distance, or corpus is an
 * argument.  This mirrors the fuzzy search-pattern matrix in the paper's trace
 * definition: any repeated trapdoor across two query bundles is visible.
 */
export function inferObservedNeighborhood(
  targetExactTokenHex: string,
  targetFuzzyTokenHexes: readonly string[],
  knownAnchors: readonly ObservedQueryBundle[],
): NeighborhoodInference {
  assertTokenHex(targetExactTokenHex, 'target exact token');
  const target = normalizedTokenSet(targetFuzzyTokenHexes, 'target fuzzy bundle');
  if (knownAnchors.length === 0) {
    return { overlaps: [], inferredAnchor: null, ambiguous: false };
  }

  const overlaps = knownAnchors.map((anchor): AnchorOverlap => {
    assertTokenHex(anchor.exactTokenHex, `exact token for ${anchor.label}`);
    const candidate = normalizedTokenSet(
      anchor.fuzzyTokenHexes,
      `fuzzy bundle for ${anchor.label}`,
    );
    let intersection = 0;
    for (const token of target) if (candidate.has(token)) intersection += 1;
    return {
      label: anchor.label,
      exactTokenEqual: anchor.exactTokenHex === targetExactTokenHex,
      fuzzyIntersection: intersection,
      fuzzyUnion: target.size + candidate.size - intersection,
    };
  });

  const largest = Math.max(...overlaps.map((overlap) => overlap.fuzzyIntersection));
  const leaders = overlaps.filter((overlap) => overlap.fuzzyIntersection === largest);
  return {
    overlaps,
    inferredAnchor: largest > 0 && leaders.length === 1 ? leaders[0]!.label : null,
    ambiguous: largest > 0 && leaders.length > 1,
  };
}

function normalizedTokenSet(tokens: readonly string[], label: string): Set<string> {
  if (tokens.length === 0) throw new Error(`${label} must contain at least one token`);
  const out = new Set<string>();
  for (const token of tokens) {
    assertTokenHex(token, label);
    out.add(token);
  }
  if (out.size !== tokens.length) throw new Error(`${label} must not repeat a token`);
  return out;
}

function assertTokenHex(token: string, label: string): void {
  if (!/^[0-9a-f]{64}$/.test(token)) {
    throw new Error(`${label} must be a lowercase 32-byte token`);
  }
}
