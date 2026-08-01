/**
 * Leakage-abuse attacks against the access pattern.
 *
 * Two real attacks from the literature, run against this vault's genuine
 * leakage — no keyword, key, or plaintext is available to anything in here.
 *
 *  1. The count attack (Cash–Grubbs–Perry–Ristenpart, CCS 2015). A token whose
 *     result size matches exactly one known keyword's document count is
 *     identified outright. Volume alone, no co-occurrence needed.
 *
 *  2. The IKK attack (Islam–Kuzu–Kantarcioglu, NDSS 2012). Match the observed
 *     token-pair co-occurrence matrix against a co-occurrence matrix the
 *     adversary already has for a known corpus, searching over assignments of
 *     tokens to keywords by simulated annealing.
 *
 * The annealing is seeded, so a given (seed, dial setting) always produces the
 * same recovery — the demo can be replayed and tested.
 */
import type { TokenProfile } from './leakage';

export interface AttackConfig {
  /** 0 = the adversary's background statistics are exact; 1 = badly wrong. */
  noise: number;
  seed: number;
  restarts: number;
  iterations: number;
}

export const DEFAULT_ATTACK: AttackConfig = {
  noise: 0,
  seed: 0x5eed,
  restarts: 8,
  iterations: 12000,
};

export interface Recovery {
  tokenHex: string;
  keyword: string;
  /** which leak did the work */
  method: 'count' | 'cooccurrence';
  /** share of independent annealing restarts that agreed with this answer */
  confidence: number;
}

export interface AttackResult {
  recoveries: Recovery[];
  /** residual ‖M_obs − M_known[σ]‖² of the winning assignment */
  cost: number;
  /** how many tokens the count attack alone pinned down before annealing */
  pinnedByCount: number;
}

export interface AttackInput {
  profiles: TokenProfile[];
  candidates: readonly string[];
  /** token × token, from the server's ledger */
  observed: number[][];
  /** candidate × candidate, from the adversary's known corpus */
  known: number[][];
  /** per-candidate document counts in the adversary's known corpus */
  counts: number[];
  totalDocs: number;
}

export function runAttack(input: AttackInput, config: AttackConfig = DEFAULT_ATTACK): AttackResult {
  const { profiles, candidates, observed, totalDocs } = input;
  const T = profiles.length;
  const C = candidates.length;
  if (T === 0) return { recoveries: [], cost: 0, pinnedByCount: 0 };
  if (T > C) throw new Error('more distinct tokens observed than candidate keywords');

  const rng = xorshift32(config.seed);
  // The adversary's knowledge is degraded before use — at noise 0 this is the
  // exact matrix, which is the strongest (and least realistic) assumption.
  const known = perturbMatrix(input.known, config.noise, rng);
  const counts = input.counts.map((c) =>
    Math.max(0, Math.round(c + config.noise * c * (rng() * 2 - 1))),
  );

  // --- Attack 1: the count attack -----------------------------------------
  const countOwner = new Map<number, number[]>();
  counts.forEach((c, i) => countOwner.set(c, [...(countOwner.get(c) ?? []), i]));
  const pinned = new Map<number, number>(); // token index → candidate index
  const takenByCount = new Set<number>();
  profiles.forEach((p, t) => {
    const owners = countOwner.get(p.resultSize);
    if (owners && owners.length === 1 && !takenByCount.has(owners[0]!)) {
      pinned.set(t, owners[0]!);
      takenByCount.add(owners[0]!);
    }
  });

  // --- Attack 2: IKK annealing over the rest ------------------------------
  const cost = (assign: number[]): number => {
    let sum = 0;
    for (let i = 0; i < T; i++) {
      for (let j = 0; j < T; j++) {
        const d = observed[i]![j]! - known[assign[i]!]![assign[j]!]!;
        sum += d * d;
      }
    }
    return sum;
  };

  const free: number[] = [];
  for (let t = 0; t < T; t++) if (!pinned.has(t)) free.push(t);

  let best: number[] | null = null;
  let bestCost = Infinity;
  const votes: Array<Map<number, number>> = profiles.map(() => new Map());

  for (let r = 0; r < config.restarts; r++) {
    let assign = seedAssignment(T, C, pinned, rng);
    let current = cost(assign);
    const t0 = Math.max(current, 1e-6);
    for (let step = 0; step < config.iterations; step++) {
      if (free.length === 0) break;
      const temp = t0 * Math.pow(1e-4, step / config.iterations);
      const t = free[Math.floor(rng() * free.length)]!;
      const target = Math.floor(rng() * C);
      const holder = assign.indexOf(target);
      if (holder === t) continue;
      if (holder !== -1 && pinned.has(holder)) continue; // never move a pinned token
      const next = assign.slice();
      if (holder !== -1) next[holder] = assign[t]!;
      next[t] = target;
      const nextCost = cost(next);
      const delta = nextCost - current;
      if (delta <= 0 || rng() < Math.exp(-delta / temp)) {
        assign = next;
        current = nextCost;
      }
    }
    // Annealing lands near a good assignment but rarely exactly on it; a
    // greedy descent over the same move set finishes the job, so a restart's
    // answer is a genuine local optimum and the agreement count below is a
    // meaningful confidence rather than annealing jitter.
    ({ assign, cost: current } = polish(assign, current, T, C, pinned, cost));

    for (let t = 0; t < T; t++) {
      const v = votes[t]!;
      v.set(assign[t]!, (v.get(assign[t]!) ?? 0) + 1);
    }
    if (current < bestCost) {
      bestCost = current;
      best = assign;
    }
  }

  const winner = best ?? seedAssignment(T, C, pinned, rng);
  const recoveries: Recovery[] = profiles.map((p, t) => {
    const c = winner[t]!;
    const agreed = votes[t]!.get(c) ?? 0;
    return {
      tokenHex: p.tokenHex,
      keyword: candidates[c]!,
      method: pinned.has(t) ? 'count' : 'cooccurrence',
      confidence: config.restarts === 0 ? 0 : agreed / config.restarts,
    };
  });

  // totalDocs is the normaliser both matrices already share; kept in the input
  // so callers cannot accidentally compare differently-scaled matrices.
  void totalDocs;
  return { recoveries, cost: bestCost, pinnedByCount: pinned.size };
}

/** Share of tokens the attack labelled correctly, given the true mapping. */
export function recoveryRate(
  recoveries: Recovery[],
  truth: Map<string, string>,
): { correct: number; total: number; rate: number } {
  let correct = 0;
  for (const r of recoveries) if (truth.get(r.tokenHex) === r.keyword) correct++;
  const total = recoveries.length;
  return { correct, total, rate: total === 0 ? 0 : correct / total };
}

/** Hill-climb to a local optimum: try every reassignment and every swap of two
 *  unpinned tokens, take any improvement, repeat until nothing improves. */
function polish(
  start: number[],
  startCost: number,
  T: number,
  C: number,
  pinned: Map<number, number>,
  cost: (assign: number[]) => number,
): { assign: number[]; cost: number } {
  let assign = start.slice();
  let current = startCost;
  for (let pass = 0; pass < 64; pass++) {
    let improved = false;
    for (let t = 0; t < T; t++) {
      if (pinned.has(t)) continue;
      for (let c = 0; c < C; c++) {
        if (assign[t] === c) continue;
        const holder = assign.indexOf(c);
        if (holder !== -1 && pinned.has(holder)) continue;
        const next = assign.slice();
        if (holder !== -1) next[holder] = assign[t]!;
        next[t] = c;
        const nextCost = cost(next);
        if (nextCost < current - 1e-15) {
          assign = next;
          current = nextCost;
          improved = true;
        }
      }
    }
    if (!improved) break;
  }
  return { assign, cost: current };
}

function seedAssignment(
  T: number,
  C: number,
  pinned: Map<number, number>,
  rng: () => number,
): number[] {
  const used = new Set(pinned.values());
  const pool: number[] = [];
  for (let c = 0; c < C; c++) if (!used.has(c)) pool.push(c);
  for (let i = pool.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [pool[i], pool[j]] = [pool[j]!, pool[i]!];
  }
  const assign = new Array<number>(T);
  let k = 0;
  for (let t = 0; t < T; t++) assign[t] = pinned.get(t) ?? pool[k++]!;
  return assign;
}

/** Symmetric multiplicative noise — the adversary's statistics are close to,
 *  but not exactly, the target's. Clamped to a valid frequency. */
function perturbMatrix(m: number[][], noise: number, rng: () => number): number[][] {
  if (noise <= 0) return m.map((row) => row.slice());
  const n = m.length;
  const out = m.map((row) => row.slice());
  for (let i = 0; i < n; i++) {
    for (let j = i; j < n; j++) {
      const jitter = 1 + noise * (rng() * 2 - 1);
      const v = Math.max(0, Math.min(1, m[i]![j]! * jitter));
      out[i]![j] = v;
      out[j]![i] = v;
    }
  }
  return out;
}

/** Seeded xorshift32 in [0,1) — deterministic so every run is reproducible. */
export function xorshift32(seed: number): () => number {
  let s = seed >>> 0 || 0x9e3779b9;
  return () => {
    s ^= s << 13;
    s >>>= 0;
    s ^= s >>> 17;
    s ^= s << 5;
    s >>>= 0;
    return s / 0x100000000;
  };
}
