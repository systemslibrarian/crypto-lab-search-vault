/**
 * Exhibit 2 — search, shown from both ends at once.
 *
 * The left column is what the client does; the right column is the complete
 * set of facts the server acquires. Both are produced by the same real query,
 * so the right column cannot flatter the scheme.
 */
import { toHex } from '../core/bytes';
import { addressFor, openDocument } from '../sse/client';
import { KEYWORDS } from '../sse/corpus';
import { tokenLabel } from '../sse/leakage';
import { badge, clear, el, labelled, panel, scrollRegion, shortHex, verdict } from './dom';
import { getState, onChange, resetLedger, runAllQueries, runIntegrityTrial, runSearch } from './state';
import type { QueryReplyMode } from '../sse/query-integrity';

export function renderSearch(): HTMLElement {
  const { section, body } = panel(
    'EXHIBIT 2',
    'Search it — and watch what the server learns',
    'Run a real query. The server answers correctly without ever seeing your keyword, and writes down everything it observes while doing so.',
  );

  const input = el('input', {
    type: 'text',
    id: 'search-input',
    list: 'search-suggestions',
    value: 'breach',
    autocomplete: 'off',
    spellcheck: 'false',
  }) as HTMLInputElement;

  const datalist = el(
    'datalist',
    { id: 'search-suggestions' },
    ...KEYWORDS.map((w) => el('option', { value: w })),
  );

  const searchBtn = el('button', { id: 'search-run', class: 'primary', type: 'button' }, 'Search');
  const allBtn = el(
    'button',
    { id: 'search-run-all', type: 'button' },
    `Run all ${KEYWORDS.length} keywords once`,
  );
  const clearBtn = el('button', { id: 'search-clear', type: 'button' }, 'Clear the server’s log');

  const controls = el(
    'div',
    { class: 'controls' },
    labelled('Keyword to search', input),
    searchBtn,
    allBtn,
    clearBtn,
    datalist,
  );

  const clientSide = el('div', { class: 'side side-client' });
  const serverSide = el('div', { class: 'side side-server' });
  const split = el('div', { class: 'split' }, clientSide, serverSide);

  const outcome = el('div', {
    id: 'search-outcome',
    role: 'status',
    'aria-live': 'polite',
    'aria-label': 'Search outcome',
  });

  const integrityMode = el(
    'select',
    { id: 'integrity-mode' },
    el('option', { value: 'honest', text: 'Honest current answer' }),
    el('option', { value: 'omit', text: 'Omit one authentic posting' }),
    el('option', { value: 'fabricate', text: 'Fabricate one posting (a server-invented row)' }),
    el('option', { value: 'stale', text: 'Replay an older snapshot' }),
  ) as HTMLSelectElement;
  const integrityBtn = el(
    'button',
    { id: 'integrity-run', type: 'button' },
    'Test the answer',
  );
  const integrityResult = el('div', {
    id: 'integrity-result',
    role: 'status',
    'aria-live': 'polite',
    'aria-label': 'Query integrity result',
  });
  const integrityLab = el(
    'div',
    { id: 'integrity-lab' },
    el('h3', { text: 'Can the server lie about the answer?' }),
    el('p', {
      class: 'note',
      text:
        'AES-GCM proves that each returned posting is authentic. It does not by itself prove that the server returned every match or that the answer came from the current database snapshot. This exercise adds a client-retained checkpoint for one snapshot: opaque token, expected result count, snapshot id, and a SHA-256 digest of the complete ordered encrypted answer. It is a teaching construction, not a general verifiable-SSE protocol.',
    }),
    el(
      'div',
      { class: 'controls' },
      labelled('Server behavior', integrityMode),
      integrityBtn,
    ),
    integrityResult,
  );

  const ledgerSlot = el('div', { id: 'search-ledger' });

  body.append(controls, split, outcome, integrityLab, ledgerSlot);
  body.append(
    el(
      'p',
      { class: 'honesty' },
      'Real, not simulated: the server holds no client key and receives an opaque token. Observations across queries can still reveal the keyword. ' +
        'Its ledger is written by the same function that answers the query, so it records the query observations that this model gives an ' +
        'honest-but-curious server.',
    ),
  );

  let searchVersion = 0;
  let integrityVersion = 0;

  function clearSearchResult(): void {
    clear(clientSide);
    clear(serverSide);
    clear(outcome);
  }

  function retireIntegrity(): void {
    integrityVersion++;
    integrityResult.textContent = 'Use “Test the answer” to check the selected keyword and server behavior.';
  }

  async function doSearch(raw: string): Promise<void> {
    const version = ++searchVersion;
    const keyword = raw.trim().toLowerCase();
    clearSearchResult();
    if (!keyword) {
      outcome.append(
        verdict('info', 'ℹ', 'NOTHING TO SEARCH', 'Type a keyword — try one of the suggestions, or a word that is not in the corpus.'),
      );
      return;
    }

    const { keys } = getState();
    const { token, ids, documents } = await runSearch(keyword);
    const probes: string[] = [];
    for (let i = 0; i <= ids.length; i++) probes.push(toHex(await addressFor(token, i)));

    // Decrypt only what the server actually handed back — the client never
    // reads a body it did not receive as a search result.
    const docs = await Promise.all(
      documents.map(async (d) => ({ id: d.id, ...(await openDocument(keys, d.id, d.blob)) })),
    );

    if (version !== searchVersion) return;
    clientSide.append(
      el(
        'p',
        { class: 'side-title' },
        el('span', { 'aria-hidden': 'true', text: '🔑' }),
        'Client — what you know',
      ),
      el(
        'div',
        { class: 'value-row' },
        el('span', { class: 'value-label', text: 'keyword' }),
        el('span', { class: 'value-bytes', text: keyword }),
      ),
      el(
        'div',
        { class: 'value-row' },
        el('span', { class: 'value-label', text: 'token sent' }),
        el('span', { class: 'value-bytes is-token', text: toHex(token), title: toHex(token) }),
      ),
      el('h4', { text: docs.length > 0 ? 'Decrypted results' : 'No results' }),
      docs.length > 0
        ? el(
            'ul',
            { style: 'margin:.3rem 0 0;padding-left:1.1rem' },
            ...docs.map((d) =>
              el(
                'li',
                { style: 'margin:.25rem 0' },
                el('span', { class: 'mono', text: `${d.id} ` }),
                d.title,
              ),
            ),
          )
        : el('p', {
            class: 'side-note',
            text: 'The client asked for a keyword the index does not contain. The server found no label and returned nothing — it cannot tell an absent keyword from a wrong key.',
          }),
    );

    if (docs.length > 0) {
      clientSide.append(
        el('p', { class: 'side-note' }, badge('ok', '✓', 'every posting authenticated under AES-GCM')),
      );
    }

    serverSide.append(
      el(
        'p',
        { class: 'side-title' },
        el('span', { 'aria-hidden': 'true', text: '👁' }),
        'Server — what it observed',
      ),
      el(
        'div',
        { class: 'value-row' },
        el('span', { class: 'value-label', text: 'received' }),
        el('span', { class: 'value-bytes', text: `32 bytes: ${shortHex(toHex(token), 16)}` }),
      ),
      el(
        'div',
        { class: 'value-row' },
        el('span', { class: 'value-label', text: 'keyword' }),
        el('span', { class: 'value-bytes', text: 'unknown — no key, nothing to invert' }),
      ),
      el(
        'div',
        { class: 'value-row' },
        el('span', { class: 'value-label', text: 'probes' }),
        el('span', {
          class: 'value-bytes',
          text: probes.map((p, i) => `addr_${i}=${p.slice(0, 8)}${i === probes.length - 1 ? ' (miss → stop)' : ''}`).join('\n'),
          style: 'white-space:pre-line',
        }),
      ),
      el(
        'div',
        { class: 'value-row' },
        el('span', { class: 'value-label', text: 'result size' }),
        el('span', { class: 'value-bytes', text: `${ids.length} documents` }),
      ),
      el(
        'div',
        { class: 'value-row' },
        el('span', { class: 'value-label', text: 'documents sent' }),
        el('span', { class: 'value-bytes', text: ids.length > 0 ? ids.join(', ') : '—' }),
      ),
      el('p', {
        class: 'side-note',
        text: 'That last line is the access pattern. It is not an implementation slip — the server has to know which documents to hand over.',
      }),
    );

    // Correctness and integrity are reported separately: the answer is right
    // AND the query was observed. Green for "it worked" would be dishonest.
    if (ids.length > 0) {
      outcome.append(
        verdict(
          'warn',
          '👁',
          'ANSWERED — AND OBSERVED',
          `The server returned the right ${ids.length} documents without receiving "${keyword}" in plaintext. It now also knows that some keyword matches exactly {${ids.join(', ')}} — and it will recognise this token again.`,
        ),
      );
    } else {
      outcome.append(
        verdict(
          'info',
          'ℹ',
          'NO MATCH',
          `The token had no indexed label, so the server returned nothing. It saw this token and a zero result count. It can recognize the same token on a later search. "${keyword}" is not one of the ${KEYWORDS.length} indexed keywords.`,
        ),
      );
    }

    renderLedger();
  }

  function renderLedger(): void {
    clear(ledgerSlot);
    const observations = getState().server.observations();
    ledgerSlot.append(el('h3', { text: `The server’s log — ${observations.length} queries observed` }));
    if (observations.length === 0) {
      ledgerSlot.append(el('p', { class: 'note', text: 'No queries observed yet.' }));
      return;
    }
    ledgerSlot.append(
      scrollRegion(
        'Server query log',
        el(
          'table',
          { class: 'data' },
          el('caption', {}, 'Every column here is derived from the query alone — no keys, no plaintext.'),
          el(
            'thead',
            {},
            el(
              'tr',
              {},
              el('th', { scope: 'col', text: '#' }),
              el('th', { scope: 'col', text: 'token' }),
              el('th', { scope: 'col', text: 'result size' }),
              el('th', { scope: 'col', text: 'documents returned (the access pattern)' }),
            ),
          ),
          el(
            'tbody',
            {},
            ...observations
              .slice()
              .reverse()
              .map((o) =>
                el(
                  'tr',
                  {},
                  el('td', { text: String(o.seq + 1) }),
                  el('td', { class: 'mono', title: o.tokenHex, text: tokenLabel(o.tokenHex) }),
                  el('td', { text: String(o.resultSize) }),
                  el('td', { class: 'mono', text: o.resultIds.join(' ') || '—' }),
                ),
              ),
          ),
        ),
      ),
    );
  }

  integrityBtn.addEventListener('click', () => {
    void (async () => {
      const version = ++integrityVersion;
      clear(integrityResult);
      const keyword = input.value.trim().toLowerCase();
      if (!KEYWORDS.includes(keyword as (typeof KEYWORDS)[number])) {
        integrityResult.append(
          verdict(
            'info',
            'ℹ',
            'USE AN INDEXED KEYWORD',
            'The checkpoint table exists only for this snapshot’s indexed keywords. Choose one of the suggestions so the exercise has a complete answer to compare against.',
          ),
        );
        return;
      }

      const mode = integrityMode.value as QueryReplyMode;
      const { verification, individualAuthentication, returnedIds } =
        await runIntegrityTrial(keyword, mode);
      if (version !== integrityVersion) return;

      if (verification.ok) {
        integrityResult.append(
          verdict(
            'ok',
            '✓',
            'COMPLETE AND CURRENT',
            `All ${verification.actualCount} returned postings authenticated, and the client checkpoint matched the complete encrypted answer for the current snapshot.`,
          ),
        );
        return;
      }

      if (verification.reason === 'count-mismatch') {
        integrityResult.append(
          verdict(
            'warn',
            '⚠',
            'AUTHENTIC BUT INCOMPLETE',
            `The ${returnedIds.length} returned postings all passed AES-GCM authentication, but the client checkpoint expected ${verification.expectedCount}. Per-record authenticity alone did not reveal the omission; the completeness checkpoint did.`,
          ),
        );
        return;
      }

      if (verification.reason === 'stale-snapshot') {
        integrityResult.append(
          verdict(
            'warn',
            '↩',
            'AUTHENTIC BUT STALE',
            `All ${returnedIds.length} returned postings still authenticated, but the answer was labelled for a different snapshot. Freshness requires an independent current snapshot reference, not just valid ciphertexts.`,
          ),
        );
        return;
      }

      integrityResult.append(
        verdict(
          'exposed',
          '✗',
          'FABRICATED ANSWER REJECTED',
          individualAuthentication === 'failed'
            ? 'The server-invented posting failed AES-GCM authentication, and the full-answer checkpoint also disagreed. This is the easy integrity case: a row the server made up has no key behind it, and both protections detect it.'
            : 'The full-answer checkpoint disagreed with the same-size reply. The client rejected the answer.',
        ),
      );
    })();
  });

  searchBtn.addEventListener('click', () => void doSearch(input.value));
  input.addEventListener('input', () => {
    searchVersion++;
    clearSearchResult();
    retireIntegrity();
  });
  integrityMode.addEventListener('change', retireIntegrity);
  input.addEventListener('keydown', (e) => {
    if ((e as KeyboardEvent).key === 'Enter') void doSearch(input.value);
  });
  allBtn.addEventListener('click', () => {
    const version = ++searchVersion;
    clearSearchResult();
    allBtn.disabled = true;
    void runAllQueries().then(() => {
      if (version === searchVersion) {
        outcome.append(verdict('info', 'ℹ', 'BATCH COMPLETE',
          `Searched each of the ${KEYWORDS.length} indexed keywords once. The server log lists the results.`));
      }
    }).finally(() => { allBtn.disabled = false; });
  });
  clearBtn.addEventListener('click', () => {
    searchVersion++;
    clearSearchResult();
    resetLedger();
    renderLedger();
  });

  onChange(renderLedger);
  clear(clientSide);
  clientSide.append(
    el(
      'p',
      { class: 'side-title' },
      el('span', { 'aria-hidden': 'true', text: '🔑' }),
      'Client — what you know',
    ),
    el('p', { class: 'side-note', text: 'Press Search to run a real query.' }),
  );
  serverSide.append(
    el(
      'p',
      { class: 'side-title' },
      el('span', { 'aria-hidden': 'true', text: '👁' }),
      'Server — what it observed',
    ),
    el('p', { class: 'side-note', text: 'Nothing yet.' }),
  );
  integrityResult.append(
    verdict(
      'info',
      'ℹ',
      'TRY A DISHONEST SERVER',
      'Keep the keyword set to “breach”, choose a server behavior, and compare individual posting authentication with completeness and freshness.',
    ),
  );
  renderLedger();

  return section;
}
