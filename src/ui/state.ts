/**
 * Demo-wide state. The split enforced here mirrors the security model:
 *
 *   `keys` and `truth` are the CLIENT's. Nothing in leakage.ts or attack.ts is
 *   ever handed either one — the adversary-side exhibits read only
 *   `server.observations()`, which is what a real server would hold.
 */
import { toHex } from '../core/bytes';
import { buildVault, generateKeys, openPostings, searchToken } from '../sse/client';
import { CORPUS, KEYWORDS } from '../sse/corpus';
import { SearchServer } from '../sse/server';
import type { BuildStep, VaultKeys } from '../sse/types';

export interface AppState {
  keys: VaultKeys;
  server: SearchServer;
  steps: BuildStep[];
  /** token → keyword, known to the demo narrator only (for scoring) */
  truth: Map<string, string>;
}

type Listener = () => void;

let state: AppState | null = null;
const listeners = new Set<Listener>();

export async function initState(): Promise<AppState> {
  const keys = generateKeys();
  const { vault, steps } = await buildVault(keys, CORPUS);
  const server = new SearchServer(vault);
  const truth = new Map<string, string>();
  for (const w of KEYWORDS) truth.set(toHex(await searchToken(keys, w)), w);
  state = { keys, server, steps, truth };
  return state;
}

export function getState(): AppState {
  if (!state) throw new Error('state not initialised');
  return state;
}

export function onChange(fn: Listener): void {
  listeners.add(fn);
}

export function notify(): void {
  for (const fn of listeners) fn();
}

/**
 * Run one real search end to end: token → server probe → client decrypt →
 * document fetch (which is what writes the server's ledger entry).
 */
export async function runSearch(keyword: string): Promise<{
  token: Uint8Array;
  ids: string[];
  /** the encrypted bodies the server handed back, still sealed */
  documents: Array<{ id: string; blob: Uint8Array }>;
}> {
  const { keys, server } = getState();
  const token = await searchToken(keys, keyword);
  const postings = await server.search(token);
  const ids = await openPostings(keys, keyword, postings);
  const documents = server.fetchDocuments(token, ids);
  notify();
  return { token, ids, documents };
}

/** Issue every keyword exactly once — a flat, unrealistically even log. */
export async function runAllQueries(): Promise<void> {
  for (const w of KEYWORDS) await runSearch(w);
}

/**
 * How often each keyword gets searched in the "realistic round".
 *
 * Real query logs are heavily skewed — a handful of terms dominate — and that
 * skew is itself a leak: the server can line the observed frequencies up
 * against published word-frequency tables before it does anything cleverer.
 * A uniform round would hide that, and would make the frequency chart flat.
 */
export const QUERY_MIX: ReadonlyArray<readonly [string, number]> = [
  ['salary', 6],
  ['audit', 5],
  ['contract', 4],
  ['lawsuit', 4],
  ['breach', 3],
  ['merger', 3],
  ['layoff', 2],
  ['invoice', 2],
  ['bonus', 2],
  ['subpoena', 2],
  ['resign', 1],
  ['patent', 1],
  ['acquisition', 1],
  ['harassment', 1],
];

/** Issue the skewed round, interleaved so the log is not ordered by keyword. */
export async function runRealisticRound(): Promise<void> {
  const queue: string[] = [];
  const remaining = QUERY_MIX.map(([w, n]) => ({ w, n }));
  let left = remaining.reduce((sum, r) => sum + r.n, 0);
  while (left > 0) {
    for (const r of remaining) {
      if (r.n === 0) continue;
      queue.push(r.w);
      r.n -= 1;
      left -= 1;
    }
  }
  for (const w of queue) await runSearch(w);
}

export function resetLedger(): void {
  getState().server.clearLedger();
  notify();
}
