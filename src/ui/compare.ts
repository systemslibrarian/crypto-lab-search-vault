/**
 * Exhibit 6 — where SSE sits between doing nothing and doing everything.
 *
 * The SSE latency column is measured here, in this browser, on this vault.
 * The ORAM and FHE columns are order-of-magnitude figures from the literature
 * and are labelled as such — this demo does not run either, and pretending
 * otherwise would be exactly the dishonesty the fleet standard forbids.
 */
import { KEYWORDS } from '../sse/corpus';
import { badge, clear, el, panel, scrollRegion, verdict } from './dom';
import { runSearch } from './state';

export function renderCompare(): HTMLElement {
  const { section, body } = panel(
    'EXHIBIT 6',
    'SSE, ORAM, FHE — what each one costs and what each one hides',
    'Three ways to query a database you do not trust. They differ by orders of magnitude in both directions: what leaks, and what it costs.',
  );

  const measureBtn = el(
    'button',
    { id: 'compare-measure', class: 'primary', type: 'button' },
    'Time 50 real searches in this browser',
  );
  const controls = el('div', { class: 'controls' }, measureBtn);

  const measurement = el('div', {
    id: 'compare-measurement',
    role: 'status',
    'aria-live': 'polite',
    'aria-label': 'Measured search latency',
  });

  const rows: Array<[string, string, string, string]> = [
    [
      'What the server learns per query',
      'The search token (linkable across repeats), the result size, and exactly which documents matched.',
      'Nothing about which logical record was touched — only that some access of a fixed shape happened.',
      'Nothing at all: the server computes on ciphertext and cannot tell one query from another.',
    ],
    [
      'Work per query',
      'Proportional to the number of matching documents — the same asymptotics as a plaintext index.',
      'Polylogarithmic in the database size, but every access rewrites and reshuffles a path of blocks.',
      'Proportional to the whole database: the server must touch every record to avoid revealing which one mattered.',
    ],
    [
      'Round trips',
      'One (plus the fetch of matching documents).',
      'Several per access, with client-side stash and position map to maintain.',
      'One, but with very large ciphertexts.',
    ],
    [
      'Client state',
      'Just the keys.',
      'Position map and stash — grows with the database.',
      'Just the keys.',
    ],
    [
      'Where it breaks',
      'Leakage-abuse attacks — the ones you just ran.',
      'Timing and volume of accesses; correlated access sequences.',
      'Cost. Correctness is fine; practicality is the problem for large corpora.',
    ],
  ];

  body.append(
    controls,
    measurement,
    scrollRegion(
      'Comparison of SSE, ORAM and FHE for database search',
      el(
        'table',
        { class: 'data' },
        el(
          'caption',
          {},
          'Qualitative comparison. Latency figures below the table are measured for SSE and cited for the others.',
        ),
        el(
          'thead',
          {},
          el(
            'tr',
            {},
            el('th', { scope: 'col', text: '' }),
            el('th', { scope: 'col', text: 'SSE (this demo)' }),
            el('th', { scope: 'col', text: 'ORAM' }),
            el('th', { scope: 'col', text: 'FHE' }),
          ),
        ),
        el(
          'tbody',
          {},
          ...rows.map(([label, sse, oram, fhe]) =>
            el(
              'tr',
              {},
              el('th', { scope: 'row', text: label }),
              el('td', { text: sse }),
              el('td', { text: oram }),
              el('td', { text: fhe }),
            ),
          ),
          el(
            'tr',
            {},
            el('th', { scope: 'row', text: 'Overhead vs. a plaintext index' }),
            el('td', {}, badge('ok', '✓', 'measured below'), ' — near-plaintext'),
            el('td', {}, badge('info', 'ℹ', 'cited'), ' — commonly reported in the tens to hundreds of times'),
            el('td', {}, badge('info', 'ℹ', 'cited'), ' — commonly reported in the thousands of times and up'),
          ),
        ),
      ),
    ),
  );

  body.append(
    el(
      'p',
      { class: 'honesty' },
      'The ORAM and FHE rows are cited, not measured: this page runs neither. They are order-of-magnitude descriptions of published ' +
        'results, and the real number depends heavily on the scheme, the parameters and the workload. Run the siblings — ',
      el('a', { href: 'https://systemslibrarian.github.io/crypto-lab-oram-vault/' }, 'ORAM Vault'),
      ' and ',
      el('a', { href: 'https://systemslibrarian.github.io/crypto-lab-fhe-arena/' }, 'FHE Arena'),
      ' — to see those two measured on their own terms.',
    ),
    el(
      'p',
      { class: 'honesty' },
      'The trade is the whole point: SSE is fast because it lets the server do ordinary index lookups, and the access pattern is ' +
        'the price of that speed. ORAM hides the pattern by making every access look alike. FHE hides everything by touching everything. ' +
        'There is no free position on this line.',
    ),
  );

  measureBtn.addEventListener('click', () => {
    void (async () => {
      clear(measurement);
      const runs = 50;
      const started = performance.now();
      for (let i = 0; i < runs; i++) {
        await runSearch(KEYWORDS[i % KEYWORDS.length]!);
      }
      const total = performance.now() - started;
      measurement.append(
        verdict(
          'info',
          '⏱',
          `${(total / runs).toFixed(2)} MS PER SEARCH`,
          `${runs} real searches — token derivation, index probing, AES-GCM posting decryption and document fetch — in ${total.toFixed(0)} ms total, in this browser. ` +
            'That is why SSE gets deployed: it is fast enough to be boring. Those 50 queries also just went into the server’s log.',
        ),
      );
    })();
  });

  return section;
}
