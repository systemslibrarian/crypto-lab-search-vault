/**
 * Exhibit 3 — the leakage profile, drawn from the server's ledger only.
 *
 * Three views of the same observations: how often each token came back
 * (search pattern), how result sets overlap (access pattern), and which
 * documents keep travelling together (the shape of the database).
 */
import { CORPUS } from '../sse/corpus';
import {
  documentCooccurrence,
  tokenLabel,
  tokenProfiles,
  touchedDocuments,
  type TokenProfile,
} from '../sse/leakage';
import { clear, el, panel, scrollRegion, svgEl, verdict } from './dom';
import { getState, onChange, runRealisticRound } from './state';

export function renderLeakage(): HTMLElement {
  const { section, body } = panel(
    'EXHIBIT 3',
    'What the pattern alone reveals',
    'Every chart below is built from the server’s log and nothing else — no keys, no keywords, no plaintext. This is the view a curious host actually has.',
  );

  const runBtn = el(
    'button',
    { id: 'leak-run-all', class: 'primary', type: 'button' },
    'Observe a realistic round of queries',
  );
  const controls = el('div', { class: 'controls' }, runBtn);

  const summary = el('div', {
    id: 'leak-summary',
    role: 'status',
    'aria-live': 'polite',
    'aria-label': 'Leakage summary',
  });
  const views = el('div', { id: 'leak-views' });

  body.append(controls, summary, views);
  body.append(
    el(
      'p',
      { class: 'honesty' },
      'What this proves: the pattern is rich. What it does not prove on its own: that the pattern is invertible — ' +
        'that takes the attack in Exhibit 4, and it takes background knowledge the adversary has to get from somewhere else.',
    ),
  );

  function render(): void {
    clear(summary);
    clear(views);
    const observations = getState().server.observations();
    const profiles = tokenProfiles(observations);

    if (profiles.length < 2) {
      summary.append(
        verdict(
          'info',
          'ℹ',
          'NOT ENOUGH OBSERVED YET',
          'Run some searches in Exhibit 2, or press the button above — leakage is cumulative, and a single query reveals very little.',
        ),
      );
      return;
    }

    const touched = touchedDocuments(observations);
    const exposedPct = Math.round((touched.size / CORPUS.length) * 100);
    summary.append(
      verdict(
        exposedPct >= 50 ? 'exposed' : 'warn',
        exposedPct >= 50 ? '⚠' : '👁',
        `${exposedPct}% OF THE DATABASE HAS BEEN IN SOME RESULT SET`,
        `${observations.length} queries, ${profiles.length} distinct tokens, ${touched.size} of ${CORPUS.length} documents named at least once. None of them were decrypted — the server just knows which is which.`,
      ),
    );

    views.append(
      frequencyView(profiles),
      intersectionGraph(profiles),
      documentMatrix(observations.length > 0 ? profiles : [], touched),
    );
  }

  runBtn.addEventListener('click', () => void runRealisticRound());
  onChange(render);
  render();
  return section;
}

/** (a) Search-pattern leakage: repeats of the same token are linkable. */
function frequencyView(profiles: TokenProfile[]): HTMLElement {
  const ranked = profiles.slice().sort((a, b) => b.queryCount - a.queryCount);
  const max = Math.max(...ranked.map((p) => p.queryCount));
  const flat = ranked.every((p) => p.queryCount === max);
  return el(
    'div',
    {},
    el('h3', { text: 'Query frequency — the search pattern' }),
    el('p', {
      class: 'note',
      text: 'Tokens are deterministic, so the server recognises a repeat instantly. Real query logs are heavily skewed, and published word-frequency tables are a starting point for guessing which token is which — before any cleverer attack begins.',
    }),
    flat
      ? el('p', {
          class: 'note',
          text: 'Every token here has been queried the same number of times, which is not what a real log looks like. Press “Observe a realistic round of queries” for a skewed one.',
        })
      : el('span'),
    el(
      'ul',
      { class: 'histogram', role: 'list', 'aria-label': 'Query count per observed token' },
      ...ranked.map((p) =>
        el(
          'li',
          { role: 'listitem' },
          el('span', { class: 'mono', title: p.tokenHex, text: tokenLabel(p.tokenHex) }),
          el(
            'span',
            { class: 'bar-track', 'aria-hidden': 'true' },
            el('span', {
              class: 'bar-fill',
              style: `width:${Math.round((p.queryCount / max) * 100)}%`,
            }),
          ),
          el('span', {
            class: 'bar-value',
            text: `${p.queryCount}× · ${p.resultSize} docs`,
          }),
        ),
      ),
    ),
  );
}

/** (b) Access-pattern leakage: overlap between result sets, as a graph. */
function intersectionGraph(profiles: TokenProfile[]): HTMLElement {
  const n = profiles.length;
  const size = 460;
  const r = size / 2 - 46;
  const cx = size / 2;
  const cy = size / 2;
  const sets = profiles.map((p) => new Set(p.resultIds));
  const nodes = profiles.map((p, i) => {
    const angle = (2 * Math.PI * i) / n - Math.PI / 2;
    return { p, x: cx + r * Math.cos(angle), y: cy + r * Math.sin(angle) };
  });

  const edges: SVGElement[] = [];
  const edgeRows: HTMLElement[] = [];
  let maxOverlap = 1;
  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      const overlap = [...sets[i]!].filter((d) => sets[j]!.has(d)).length;
      if (overlap > maxOverlap) maxOverlap = overlap;
    }
  }
  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      const overlap = [...sets[i]!].filter((d) => sets[j]!.has(d)).length;
      if (overlap === 0) continue;
      edges.push(
        svgEl('line', {
          class: 'graph-edge',
          x1: nodes[i]!.x,
          y1: nodes[i]!.y,
          x2: nodes[j]!.x,
          y2: nodes[j]!.y,
          'stroke-width': (0.6 + (overlap / maxOverlap) * 3).toFixed(2),
          'stroke-opacity': (0.25 + (overlap / maxOverlap) * 0.55).toFixed(2),
        }),
      );
      edgeRows.push(
        el(
          'tr',
          {},
          el('td', { class: 'mono', text: tokenLabel(profiles[i]!.tokenHex) }),
          el('td', { class: 'mono', text: tokenLabel(profiles[j]!.tokenHex) }),
          el('td', { text: String(overlap) }),
        ),
      );
    }
  }

  const svg = svgEl(
    'svg',
    {
      viewBox: `0 0 ${size} ${size}`,
      role: 'img',
      'aria-label': `Result-set overlap graph: ${n} observed tokens, ${edgeRows.length} pairs whose result sets intersect. The equivalent numbers are listed in the table below.`,
    },
    ...edges,
    ...nodes.flatMap((node) => [
      svgEl('circle', { class: 'graph-node', cx: node.x, cy: node.y, r: 17 }),
      svgEl('text', {
        class: 'graph-label',
        x: node.x,
        y: node.y + 3,
        text: node.p.tokenHex.slice(0, 4),
      }),
    ]),
  );

  return el(
    'div',
    {},
    el('h3', { text: 'Result-set overlap — the access pattern' }),
    el('p', {
      class: 'note',
      text: 'One node per observed token; a line means their result sets share documents, and a thicker line means they share more. The clusters are real topics in the database — the server is looking at the structure of your corpus without having decrypted a byte of it.',
    }),
    el('div', { class: 'graph-wrap' }, svg),
    el(
      'details',
      {},
      el('summary', { text: 'The same graph as numbers' }),
      scrollRegion(
        'Result-set overlap, pair by pair',
        el(
          'table',
          { class: 'data' },
          el(
            'thead',
            {},
            el(
              'tr',
              {},
              el('th', { scope: 'col', text: 'token' }),
              el('th', { scope: 'col', text: 'token' }),
              el('th', { scope: 'col', text: 'shared documents' }),
            ),
          ),
          el('tbody', {}, ...edgeRows),
        ),
      ),
    ),
  );
}

/** (c) Document co-occurrence: which files keep coming back together. */
function documentMatrix(profiles: TokenProfile[], touched: Set<string>): HTMLElement {
  const ids = CORPUS.map((d) => d.id).filter((id) => touched.has(id));
  const observations = getState().server.observations();
  const m = documentCooccurrence(observations, ids);
  const max = Math.max(1, ...m.flat());

  const head = el(
    'tr',
    {},
    el('th', { scope: 'col', text: '' }),
    ...ids.map((id) => el('th', { scope: 'col', text: id })),
  );

  const rows = ids.map((id, i) =>
    el(
      'tr',
      {},
      el('th', { scope: 'row', text: id }),
      ...ids.map((_, j) => {
        const v = m[i]![j]!;
        // Tint capped at 35% so --text stays >= 4.5:1 on the cell in both
        // themes; the number carries the value, the tint only ranks it.
        const pct = Math.round((v / max) * 35);
        return el('td', {
          style: v === 0 ? '' : `background-color:color-mix(in oklab,var(--accent) ${pct}%,transparent)`,
          text: v === 0 ? '·' : String(v),
        });
      }),
    ),
  );

  return el(
    'div',
    {},
    el('h3', { text: 'Document co-occurrence — the shape of the corpus' }),
    el('p', {
      class: 'note',
      text: `How many times each pair of documents was returned by the same query, across ${observations.length} queries and ${profiles.length} distinct tokens. Dark blocks are documents that belong to the same topic. The server built this without a single decryption.`,
    }),
    scrollRegion(
      'Document co-occurrence matrix',
      el(
        'table',
        { class: 'matrix' },
        el('caption', {}, 'Rows and columns are document identifiers; each cell counts shared result sets.'),
        el('thead', {}, head),
        el('tbody', {}, ...rows),
      ),
    ),
  );
}
