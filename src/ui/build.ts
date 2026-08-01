/**
 * Exhibit 1 — the headline mechanism, stepped rather than asserted.
 *
 * Every hex string on screen is the real value the vault was built from:
 * these are `state.steps`, produced by client.ts during buildVault(), not a
 * re-enactment. Stepping walks the derivation one PRF call at a time and shows
 * the resulting row landing in the server's store.
 */
import { el, clear, labelled, panel, scrollRegion, shortHex, verdict } from './dom';
import { getState } from './state';
import { KEYWORDS, documentsFor } from '../sse/corpus';
import type { BuildStep } from '../sse/types';

export function renderBuild(): HTMLElement {
  const { section, body } = panel(
    'EXHIBIT 1',
    'Build the encrypted index',
    'Watch one keyword become an encrypted inverted index, one real PRF call at a time. Nothing here is a re-enactment — these are the exact bytes the server is holding.',
  );

  const select = el(
    'select',
    { id: 'build-keyword', 'aria-describedby': 'build-hint' },
    ...KEYWORDS.map((w) => el('option', { value: w, text: w })),
  ) as HTMLSelectElement;
  select.value = 'breach';

  const stepBtn = el('button', { id: 'build-step', class: 'primary', type: 'button' }, 'Step');
  const allBtn = el('button', { id: 'build-all', type: 'button' }, 'Build this keyword');
  const resetBtn = el('button', { id: 'build-reset', type: 'button' }, 'Reset');

  const controls = el(
    'div',
    { class: 'controls' },
    labelled('Keyword to index', select),
    stepBtn,
    allBtn,
    resetBtn,
  );

  const hint = el('p', {
    id: 'build-hint',
    class: 'note',
    text: 'The client knows the keyword. The server, on the right, only ever receives the two hex columns.',
  });

  const clientSide = el('div', { class: 'side side-client' });
  const serverSide = el('div', { class: 'side side-server' });
  const split = el('div', { class: 'split' }, clientSide, serverSide);

  const status = el('div', {
    id: 'build-status',
    role: 'status',
    'aria-live': 'polite',
    'aria-label': 'Index build progress',
  });

  const verdictSlot = el('div', { id: 'build-verdict' });

  body.append(controls, hint, split, status, verdictSlot);
  body.append(
    el(
      'details',
      { id: 'build-full-index' },
      el('summary', { text: `The server’s complete store — every row for all ${KEYWORDS.length} keywords` }),
      el('p', {
        class: 'note',
        text: 'Postings were handed over in a keyword-independent order. Nothing in this table says which rows belong together, how many keywords exist, or which document any row points to.',
      }),
      renderFullIndex(),
    ),
    el(
      'p',
      { class: 'honesty' },
      'What this shows: labels and ciphertexts are pseudorandom, so the stored index leaks only its total size. ' +
        'What it does not show: the index is static. A real deployment that adds documents later leaks more (see the extension seams at the end).',
    ),
  );

  let cursor = 0;
  let steps: BuildStep[] = [];

  function stepsForKeyword(): BuildStep[] {
    return getState().steps.filter((s) => s.keyword === select.value);
  }

  /** Total substeps: keyword, token, posting key, then address+value per posting. */
  function totalSteps(): number {
    return 3 + steps.length * 2;
  }

  function render(): void {
    clear(clientSide);
    clear(serverSide);
    clear(verdictSlot);

    const w = select.value;
    const first = steps[0];

    clientSide.append(
      el(
        'p',
        { class: 'side-title' },
        el('span', { 'aria-hidden': 'true', text: '🔑' }),
        'Client — holds the keys',
      ),
    );

    clientSide.append(
      valueRow('keyword', w, cursor >= 1, 'plain'),
      el('p', { class: 'step-arrow', text: '↓  t = HMAC-SHA-256(K_prf, "token" ‖ keyword)' }),
      valueRow('search token t', first?.tokenHex ?? '', cursor >= 2, 'token'),
      el('p', { class: 'step-arrow', text: '↓  k = HMAC-SHA-256(K_enc, "posting" ‖ keyword)' }),
      valueRow('posting key k', first?.postingKeyHex ?? '', cursor >= 3, 'plain'),
      cursor >= 3
        ? el('p', {
            class: 'side-note',
            text: 'The token above is the only one of these two that ever leaves the client. The posting key stays here — it is what turns the server’s sealed rows back into document identifiers.',
          })
        : el('span'),
    );

    const built = builtPostings(cursor, steps.length);
    if (built.pending !== null) {
      const s = steps[built.pending]!;
      const showAddress = true;
      const showValue = built.valueShown;
      clientSide.append(
        el('p', { class: 'step-arrow', text: `↓  posting ${s.counter} — document ${s.docId}` }),
        valueRow(`address ${s.counter}`, s.addressHex, showAddress, 'plain'),
        el('p', {
          class: 'step-arrow',
          text: `↓  AES-256-GCM(k, "${s.docId}"), with the address bound in as associated data`,
        }),
        valueRow(`value ${s.counter}`, s.valueHex, showValue, 'plain'),
      );
    }

    serverSide.append(
      el(
        'p',
        { class: 'side-title' },
        el('span', { 'aria-hidden': 'true', text: '🗄️' }),
        'Server — holds only this',
      ),
    );
    const rows = steps.slice(0, built.stored);
    serverSide.append(
      scrollRegion(
        `Encrypted index rows stored for the selected keyword`,
        el(
          'table',
          { class: 'data' },
          el(
            'caption',
            {},
            `${rows.length} of ${steps.length} rows stored`,
          ),
          el(
            'thead',
            {},
            el(
              'tr',
              {},
              el('th', { scope: 'col', text: 'address (label)' }),
              el('th', { scope: 'col', text: 'value (sealed)' }),
            ),
          ),
          el(
            'tbody',
            {},
            ...(rows.length === 0
              ? [
                  el(
                    'tr',
                    {},
                    el('td', { colspan: '2', class: 'note', text: 'nothing stored yet' }),
                  ),
                ]
              : rows.map((s, i) =>
                  el(
                    'tr',
                    { class: i === rows.length - 1 && cursor < totalSteps() ? 'is-new' : '' },
                    el('td', { class: 'mono', title: s.addressHex, text: shortHex(s.addressHex, 10) }),
                    el('td', { class: 'mono', title: s.valueHex, text: shortHex(s.valueHex, 10) }),
                  ),
                )),
          ),
        ),
      ),
      el('p', {
        class: 'side-note',
        text: 'No keyword. No document id. No two rows that look related. The server cannot even tell that these rows share a keyword.',
      }),
    );

    status.textContent =
      cursor === 0
        ? `Ready to index "${w}" — ${steps.length} documents contain it.`
        : cursor >= totalSteps()
          ? `Done: "${w}" is indexed as ${steps.length} rows.`
          : `Step ${cursor} of ${totalSteps()}.`;

    if (cursor >= totalSteps() && steps.length > 0) {
      verdictSlot.append(
        verdict(
          'ok',
          '✓',
          'INDEXED',
          `"${w}" is now ${steps.length} rows the server cannot read. The client can regenerate every one of those addresses from the token alone — and, without the key, so can nobody else.`,
        ),
      );
    }

    stepBtn.disabled = cursor >= totalSteps();
    allBtn.disabled = cursor >= totalSteps();
  }

  function reset(): void {
    steps = stepsForKeyword();
    cursor = 0;
    render();
  }

  stepBtn.addEventListener('click', () => {
    cursor = Math.min(cursor + 1, totalSteps());
    render();
  });
  allBtn.addEventListener('click', () => {
    cursor = totalSteps();
    render();
  });
  resetBtn.addEventListener('click', reset);
  select.addEventListener('change', reset);

  reset();
  return section;
}

/**
 * Which posting is mid-derivation, and how many are fully stored.
 *
 * After the three key-derivation steps, each posting takes two more: reveal
 * its address, then reveal its sealed value — and only that second step puts
 * the row into the server's store.
 */
export function builtPostings(
  cursor: number,
  count: number,
): { stored: number; pending: number | null; valueShown: boolean } {
  if (cursor <= 3 || count === 0) return { stored: 0, pending: null, valueShown: false };
  const into = cursor - 3;
  const pending = Math.min(Math.floor((into - 1) / 2), count - 1);
  return { stored: Math.floor(into / 2), pending, valueShown: into % 2 === 0 };
}

function valueRow(
  label: string,
  value: string,
  shown: boolean,
  kind: 'plain' | 'token',
): HTMLElement {
  return el(
    'div',
    { class: `value-row${shown ? '' : ' is-pending'}` },
    el('span', { class: 'value-label', text: label }),
    el('span', {
      class: `value-bytes${kind === 'token' && shown ? ' is-token' : ''}`,
      text: shown ? value : '— not derived yet —',
      title: shown ? value : '',
    }),
  );
}

function renderFullIndex(): HTMLElement {
  const rows = getState().server.rows();
  return scrollRegion(
    'Complete encrypted index held by the server',
    el(
      'table',
      { class: 'data' },
      el('caption', {}, `${rows.length} rows across ${KEYWORDS.length} keywords and ${new Set(KEYWORDS.flatMap((w) => documentsFor(w))).size} documents`),
      el(
        'thead',
        {},
        el(
          'tr',
          {},
          el('th', { scope: 'col', text: '#' }),
          el('th', { scope: 'col', text: 'address (label)' }),
          el('th', { scope: 'col', text: 'value (sealed)' }),
        ),
      ),
      el(
        'tbody',
        {},
        ...rows.map((r, i) =>
          el(
            'tr',
            {},
            el('td', { text: String(i + 1) }),
            el('td', { class: 'mono', text: shortHex(r.address, 12) }),
            el('td', { class: 'mono', text: shortHex(hex(r.value), 12) }),
          ),
        ),
      ),
    ),
  );
}

function hex(b: Uint8Array): string {
  let out = '';
  for (const x of b) out += x.toString(16).padStart(2, '0');
  return out;
}
