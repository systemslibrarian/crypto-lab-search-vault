/**
 * Exhibit 5 — break-it-yourself. The learner plays the curious server.
 *
 * They get exactly what the adversary gets: the observed tokens with their
 * result sizes and overlaps, plus the public statistics of a corpus they
 * already know. Nothing else. Then the machine attempts the same puzzle.
 */
import { CORPUS, KEYWORDS, documentsFor } from '../sse/corpus';
import {
  knownCooccurrence,
  knownCounts,
  observedCooccurrence,
  tokenLabel,
  tokenProfiles,
  type TokenProfile,
} from '../sse/leakage';
import { DEFAULT_ATTACK, recoveryRate, runAttack } from '../sse/attack';
import { badge, clear, el, panel, scrollRegion, verdict } from './dom';
import { getState, onChange, runRealisticRound } from './state';

export function renderChallenge(): HTMLElement {
  const { section, body } = panel(
    'EXHIBIT 5',
    'Your turn: you are the server',
    'You never see a key or a keyword — only the tokens, the sizes, the overlaps, and public statistics about a corpus like this one. Work out which token is which.',
  );

  const observeBtn = el(
    'button',
    { id: 'challenge-observe', type: 'button' },
    'Observe a realistic round of queries',
  );
  const checkBtn = el('button', { id: 'challenge-check', class: 'primary', type: 'button' }, 'Check my answers');
  const machineBtn = el('button', { id: 'challenge-machine', type: 'button' }, 'Let the machine try');
  const clearBtn = el('button', { id: 'challenge-clear', type: 'button' }, 'Clear my guesses');
  const controls = el('div', { class: 'controls' }, observeBtn, checkBtn, machineBtn, clearBtn);

  const board = el('div', { id: 'challenge-board' });
  const outcome = el('div', {
    id: 'challenge-outcome',
    role: 'status',
    'aria-live': 'polite',
    'aria-label': 'Challenge result',
  });

  body.append(controls, board, outcome, backgroundKnowledge());
  body.append(
    el(
      'p',
      { class: 'honesty' },
      'This is the same puzzle the attack in Exhibit 4 solves, with the same inputs. If you can do it by hand on 14 tokens, ' +
        'a server with a real query log and a few thousand keywords can do it by machine.',
    ),
  );

  const guesses = new Map<string, string>();

  function profiles(): TokenProfile[] {
    return tokenProfiles(getState().server.observations());
  }

  function renderBoard(): void {
    clear(board);
    const ps = profiles();
    if (ps.length < 2) {
      board.append(
        el('p', {
          class: 'note',
          text: 'Nothing to work with yet — press “Observe a realistic round of queries” to give yourself a log to attack.',
        }),
      );
      checkBtn.disabled = true;
      machineBtn.disabled = true;
      return;
    }
    checkBtn.disabled = false;
    machineBtn.disabled = false;

    const m = observedCooccurrence(ps, CORPUS.length);

    board.append(
      scrollRegion(
        'Your working board: one row per observed token',
        el(
          'table',
          { class: 'data' },
          el('caption', {}, 'Overlaps are shown as the tokens whose results intersect this one the most.'),
          el(
            'thead',
            {},
            el(
              'tr',
              {},
              el('th', { scope: 'col', text: 'token' }),
              el('th', { scope: 'col', text: 'documents returned' }),
              el('th', { scope: 'col', text: 'overlaps most with' }),
              el('th', { scope: 'col', text: 'your guess' }),
              el('th', { scope: 'col', text: 'verdict' }),
            ),
          ),
          el(
            'tbody',
            {},
            ...ps.map((p, i) => {
              const neighbours = ps
                .map((q, j) => ({ q, v: i === j ? 0 : m[i]![j]! }))
                .filter((x) => x.v > 0)
                .sort((a, b) => b.v - a.v)
                .slice(0, 3)
                .map((x) => `${tokenLabel(x.q.tokenHex)} (${Math.round(x.v * CORPUS.length)})`)
                .join(', ');

              const select = el(
                'select',
                { 'aria-label': `Your guess for token ${tokenLabel(p.tokenHex)}` },
                el('option', { value: '', text: '— choose —' }),
                ...KEYWORDS.map((w) => el('option', { value: w, text: w })),
              ) as HTMLSelectElement;
              select.value = guesses.get(p.tokenHex) ?? '';
              select.addEventListener('change', () => {
                if (select.value) guesses.set(p.tokenHex, select.value);
                else guesses.delete(p.tokenHex);
              });

              return el(
                'tr',
                { class: 'challenge-row' },
                el('td', { class: 'mono', title: p.tokenHex, text: tokenLabel(p.tokenHex) }),
                el('td', { text: `${p.resultSize} — {${p.resultIds.join(', ')}}` }),
                el('td', { class: 'mono', text: neighbours || '—' }),
                el('td', {}, select),
                el('td', { class: 'challenge-verdict', 'data-token': p.tokenHex }, '—'),
              );
            }),
          ),
        ),
      ),
    );
  }

  function check(): void {
    clear(outcome);
    const { truth } = getState();
    const ps = profiles();
    let correct = 0;
    for (const p of ps) {
      const guess = guesses.get(p.tokenHex);
      const actual = truth.get(p.tokenHex)!;
      const cell = board.querySelector(`[data-token="${p.tokenHex}"]`);
      if (!cell) continue;
      clear(cell);
      if (!guess) {
        cell.append(badge('info', '·', 'no guess'));
      } else if (guess === actual) {
        correct++;
        cell.append(badge('alarm', '⚠', 'right — recovered'));
      } else {
        cell.append(badge('ok', '✓', `wrong — it was “${actual}”`));
      }
    }

    const answered = ps.filter((p) => guesses.has(p.tokenHex)).length;
    outcome.append(
      verdict(
        correct >= ps.length / 2 ? 'exposed' : 'warn',
        correct >= ps.length / 2 ? '⚠' : '👁',
        `YOU RECOVERED ${correct} OF ${ps.length}`,
        answered === 0
          ? 'Pick a keyword for at least one token, then check again.'
          : `${answered} answered, ${correct} correct. Every one you got right is a query the encryption was supposed to hide — and you did it with arithmetic, not cryptanalysis.`,
      ),
    );
  }

  function machine(): void {
    clear(outcome);
    const { truth } = getState();
    const ps = profiles();
    const attack = runAttack(
      {
        profiles: ps,
        candidates: KEYWORDS,
        observed: observedCooccurrence(ps, CORPUS.length),
        known: knownCooccurrence(KEYWORDS, CORPUS),
        counts: knownCounts(KEYWORDS, CORPUS),
        totalDocs: CORPUS.length,
      },
      DEFAULT_ATTACK,
    );
    const machineScore = recoveryRate(attack.recoveries, truth);
    let yours = 0;
    for (const p of ps) if (guesses.get(p.tokenHex) === truth.get(p.tokenHex)) yours++;

    outcome.append(
      el(
        'div',
        { class: 'challenge-score' },
        scoreBlock('You', `${yours} / ${ps.length}`),
        scoreBlock('IKK attack', `${machineScore.correct} / ${machineScore.total}`),
        scoreBlock('Guessing at random', `≈ ${(ps.length / KEYWORDS.length).toFixed(1)} / ${ps.length}`),
      ),
      verdict(
        'exposed',
        '⚠',
        'THE PATTERN WAS THE SECRET',
        'The tokens are still 32 bytes of HMAC output and the documents are still sealed under AES-256-GCM. None of that was attacked. ' +
          'The queries were reconstructed from which documents came back — leakage the scheme was designed to permit.',
      ),
    );
  }

  observeBtn.addEventListener('click', () => void runRealisticRound());
  checkBtn.addEventListener('click', check);
  machineBtn.addEventListener('click', machine);
  clearBtn.addEventListener('click', () => {
    guesses.clear();
    clear(outcome);
    renderBoard();
  });

  onChange(renderBoard);
  renderBoard();
  return section;
}

function scoreBlock(label: string, value: string): HTMLElement {
  return el(
    'div',
    { class: 'score-block' },
    el('div', { class: 'score-label', text: label }),
    el('div', { class: 'score-value', text: value }),
  );
}

/** The adversary's public statistics — handed to the learner as well, because
 *  the attack gets them too. Hiding them would make the exhibit a guessing game. */
function backgroundKnowledge(): HTMLElement {
  const m = knownCooccurrence(KEYWORDS, CORPUS);
  const counts = knownCounts(KEYWORDS, CORPUS);
  return el(
    'details',
    { id: 'challenge-knowledge' },
    el('summary', { text: 'Your background knowledge — public statistics for a corpus like this one' }),
    el('p', {
      class: 'note',
      text: 'This is the assumption the attacks rest on: the adversary knows roughly how often each keyword appears and which keywords travel together. Leaked archives, public filings, and similar organisations all supply it.',
    }),
    scrollRegion(
      'Known keyword statistics',
      el(
        'table',
        { class: 'data' },
        el(
          'thead',
          {},
          el(
            'tr',
            {},
            el('th', { scope: 'col', text: 'keyword' }),
            el('th', { scope: 'col', text: 'documents' }),
            el('th', { scope: 'col', text: 'travels with' }),
          ),
        ),
        el(
          'tbody',
          {},
          ...KEYWORDS.map((w, i) =>
            el(
              'tr',
              {},
              el('th', { scope: 'row', text: w }),
              el(
                'td',
                {},
                String(counts[i]),
                counts.filter((c) => c === counts[i]).length === 1
                  ? el('span', {}, ' ', badge('alarm', '⚠', 'unique count'))
                  : null,
              ),
              el('td', {
                class: 'note',
                text:
                  KEYWORDS.map((v, j) => ({ v, n: i === j ? 0 : Math.round(m[i]![j]! * CORPUS.length) }))
                    .filter((x) => x.n > 0)
                    .sort((a, b) => b.n - a.n)
                    .map((x) => `${x.v} (${x.n})`)
                    .join(', ') || '—',
              }),
            ),
          ),
        ),
      ),
    ),
    el('p', {
      class: 'note',
      text: `Corpus size: ${CORPUS.length} documents. Keyword universe: ${KEYWORDS.length}. Total postings: ${KEYWORDS.reduce((n, w) => n + documentsFor(w).length, 0)}.`,
    }),
  );
}
