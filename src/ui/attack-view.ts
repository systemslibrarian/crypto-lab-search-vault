/**
 * Exhibit 4 — the leakage-abuse attack, run for real against this vault.
 *
 * The attack receives `server.observations()` and a co-occurrence matrix for a
 * corpus the adversary already knows. It never receives the keys, the tokens'
 * meanings, or any plaintext. Ground truth is used *only* to score the result
 * afterwards, in this file, after the attack has already committed.
 */
import { CORPUS, KEYWORDS } from '../sse/corpus';
import {
  knownCooccurrence,
  knownCounts,
  observedCooccurrence,
  profilesMatchingCandidateVolumes,
  tokenLabel,
  tokenProfiles,
} from '../sse/leakage';
import { DEFAULT_ATTACK, recoveryRate, runAttack, type AttackResult } from '../sse/attack';
import { badge, clear, el, labelled, panel, scrollRegion, verdict } from './dom';
import { getState, onChange, runRealisticRound } from './state';

export function renderAttack(): HTMLElement {
  const { section, body } = panel(
    'EXHIBIT 4',
    'Break it: turn the access pattern back into queries',
    'Two published attacks, run against the log the server just accumulated. Neither one touches a key.',
  );

  body.append(
    el(
      'p',
      {},
      el('strong', { text: 'The count attack ' }),
      '(Cash–Grubbs–Perry–Ristenpart, 2015): if the adversary knows a keyword appears in exactly six documents, and one token ' +
        'returned exactly six, that token is that keyword. Volume alone, no cleverness required.',
    ),
    el(
      'p',
      {},
      el('strong', { text: 'The IKK attack ' }),
      '(Islam–Kuzu–Kantarcioglu, 2012): build the table of how often each pair of tokens returns overlapping results, compare it ' +
        'against the same table computed on a corpus the adversary already has, and search for the assignment of tokens to keywords ' +
        'that makes the two tables agree. The search is simulated annealing — the same method the paper used.',
    ),
  );

  const noise = el('input', {
    type: 'range',
    id: 'attack-noise',
    min: '0',
    max: '150',
    step: '10',
    value: '0',
  }) as HTMLInputElement;

  const noiseOut = el('span', {
    id: 'attack-noise-value',
    class: 'mono',
    text: 'exact',
  });

  const runBtn = el('button', { id: 'attack-run', class: 'primary', type: 'button' }, 'Run the attack');
  const observeBtn = el(
    'button',
    { id: 'attack-observe', type: 'button' },
    'Observe a realistic round first',
  );

  const controls = el(
    'div',
    { class: 'controls' },
    labelled('Adversary’s background knowledge error', noise),
    noiseOut,
    runBtn,
    observeBtn,
  );

  const inputView = el('div', { id: 'attack-input' });
  const result = el('div', {
    id: 'attack-result',
    role: 'status',
    'aria-live': 'polite',
    'aria-label': 'Attack result',
  });

  body.append(controls, inputView, result);
  body.append(
    el(
      'p',
      { class: 'honesty' },
      'Honest about the assumption: the adversary needs statistics from a similar corpus. At 0% error it has this corpus’s exact ' +
        'statistics, which is the strongest possible assumption and not realistic — drag the slider right to degrade it and watch ' +
        'recovery fall. IKK’s actual finding was that partial, imperfect knowledge is already enough to recover most queries.',
    ),
    el(
      'p',
      { class: 'honesty' },
      'What this does NOT prove: that all SSE is broken. It shows that this leakage profile — access pattern plus volume, with no ' +
        'padding, no obliviousness and a static index — is invertible given background knowledge. Schemes that suppress or pad ' +
        'these leaks exist, and cost more.',
    ),
  );

  function noiseLevel(): number {
    return Number(noise.value) / 100;
  }

  function renderInput(): void {
    clear(inputView);
    const profiles = tokenProfiles(getState().server.observations());
    if (profiles.length < 2) return;
    const m = observedCooccurrence(profiles, CORPUS.length);
    const max = Math.max(...m.flat());
    inputView.append(
      el(
        'details',
        { id: 'attack-matrix-details' },
        el('summary', { text: `The attack’s entire input — a ${profiles.length}×${profiles.length} table of token overlaps` }),
        el('p', {
          class: 'note',
          text: 'Cell (i, j) is the fraction of the database returned by both token i and token j. The adversary computes this from the log; it never needed a key to do so.',
        }),
        scrollRegion(
          'Observed token co-occurrence matrix',
          el(
            'table',
            { class: 'matrix' },
            el(
              'thead',
              {},
              el(
                'tr',
                {},
                el('th', { scope: 'col', text: '' }),
                ...profiles.map((p) => el('th', { scope: 'col', text: p.tokenHex.slice(0, 4) })),
              ),
            ),
            el(
              'tbody',
              {},
              ...profiles.map((p, i) =>
                el(
                  'tr',
                  {},
                  el('th', { scope: 'row', class: 'mono', text: tokenLabel(p.tokenHex) }),
                  ...profiles.map((_, j) => {
                    const v = m[i]![j]!;
                    const pct = Math.round((v / max) * 35);
                    return el('td', {
                      style: v === 0 ? '' : `background-color:color-mix(in oklab,var(--accent) ${pct}%,transparent)`,
                      text: v === 0 ? '·' : v.toFixed(2).slice(1),
                    });
                  }),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }

  function run(): void {
    clear(result);
    const { server, truth } = getState();
    const allProfiles = tokenProfiles(server.observations());
    const counts = knownCounts(KEYWORDS, CORPUS);
    const profiles = profilesMatchingCandidateVolumes(allProfiles, counts);
    const excluded = allProfiles.length - profiles.length;

    if (profiles.length < 2) {
      result.append(
        verdict(
          'info',
          'ℹ',
          'NOTHING TO ATTACK YET',
          'The adversary needs observed queries. Press “Observe a realistic round first”, or run searches in Exhibit 2.',
        ),
      );
      return;
    }

    const started = performance.now();
    const attack: AttackResult = runAttack(
      {
        profiles,
        candidates: KEYWORDS,
        observed: observedCooccurrence(profiles, CORPUS.length),
        known: knownCooccurrence(KEYWORDS, CORPUS),
        counts,
        totalDocs: CORPUS.length,
      },
      { ...DEFAULT_ATTACK, noise: noiseLevel() },
    );
    const elapsed = performance.now() - started;
    const score = recoveryRate(attack.recoveries, truth);
    const pct = Math.round(score.rate * 100);

    // Colour tracks system integrity: a successful recovery is an ALARM for
    // the scheme, however impressive it is as an attack.
    result.append(
      verdict(
        pct >= 50 ? 'exposed' : pct > 0 ? 'warn' : 'ok',
        pct >= 50 ? '⚠' : pct > 0 ? '👁' : '✓',
        `${score.correct} OF ${score.total} QUERIES RECONSTRUCTED (${pct}%)`,
        `${attack.pinnedByCount} identified by result size alone; the rest by matching co-occurrence, in ${elapsed.toFixed(0)} ms. ` +
          `The adversary started from ${profiles.length} candidate-compatible opaque tokens and a public statistic.` +
          (excluded > 0
            ? ` It excluded ${excluded} zero-result token${excluded === 1 ? '' : 's'} because no candidate keyword has zero results.`
            : ''),
      ),
    );

    result.append(
      scrollRegion(
        'Attack results per token',
        el(
          'table',
          { class: 'data' },
          el(
            'caption',
            {},
            'The “actually” column is the demo scoring the attack afterwards — the attack itself never saw it.',
          ),
          el(
            'thead',
            {},
            el(
              'tr',
              {},
              el('th', { scope: 'col', text: 'token' }),
              el('th', { scope: 'col', text: 'result size' }),
              el('th', { scope: 'col', text: 'broken by' }),
              el('th', { scope: 'col', text: 'adversary says' }),
              el('th', { scope: 'col', text: 'confidence' }),
              el('th', { scope: 'col', text: 'actually' }),
            ),
          ),
          el(
            'tbody',
            {},
            ...attack.recoveries.map((r) => {
              const actual = truth.get(r.tokenHex) ?? '—';
              const right = actual === r.keyword;
              const profile = profiles.find((p) => p.tokenHex === r.tokenHex)!;
              return el(
                'tr',
                {},
                el('td', { class: 'mono', title: r.tokenHex, text: tokenLabel(r.tokenHex) }),
                el('td', { text: String(profile.resultSize) }),
                el(
                  'td',
                  {},
                  r.method === 'count' ? 'result size' : 'co-occurrence',
                ),
                el('td', { text: r.keyword }),
                el('td', { text: `${Math.round(r.confidence * 100)}%` }),
                el(
                  'td',
                  {},
                  right
                    ? badge('alarm', '⚠', `${actual} — recovered`)
                    : badge('ok', '✓', `${actual} — held`),
                ),
              );
            }),
          ),
        ),
      ),
    );
  }

  noise.addEventListener('input', () => {
    const v = Number(noise.value);
    noiseOut.textContent = v === 0 ? 'exact' : `±${v}%`;
  });
  runBtn.addEventListener('click', run);
  observeBtn.addEventListener('click', () => {
    void runRealisticRound().then(run);
  });

  onChange(renderInput);
  renderInput();
  result.append(
    el('p', {
      class: 'note',
      text: 'Press “Run the attack” once the server has watched a few queries.',
    }),
  );
  return section;
}
