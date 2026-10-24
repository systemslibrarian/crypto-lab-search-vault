/** Exhibit 7 — executable two-keyword conjunctions with a bounded OXT core. */
import {
  ConjunctiveQueryError,
  type ConjunctiveComparison,
  type ConjunctiveLesson,
  type OxtControlPair,
  type PathOramCost,
} from '../oxt/lesson';
/*
 * ConjunctiveQueryError is a runtime import on purpose: only that error class
 * proves parsing stopped before either comparison server received a query.
 */
import { badge, clear, el, labelled, panel, scrollRegion, shortHex, verdict } from './dom';

export function renderConjunctive(lesson: ConjunctiveLesson): HTMLElement {
  const { section, body } = panel(
    'EXHIBIT 7',
    'Two-keyword AND — naïve SSE versus bounded OXT',
    'Run the same conjunction two ways. The naïve client sends two ordinary SSE tokens and intersects two complete lists. OXT sends one s-term lookup plus blinded cross-tokens, then tests exact ristretto255 points without retrieving the x-term list.',
  );

  const queryInput = el('input', {
    id: 'oxt-query',
    type: 'text',
    value: 'breach AND audit',
    autocomplete: 'off',
    spellcheck: 'false',
  }) as HTMLInputElement;
  const runButton = el(
    'button',
    { id: 'oxt-run', class: 'primary', type: 'button' },
    'Compare both constructions',
  ) as HTMLButtonElement;
  const controlsButton = el(
    'button',
    { id: 'oxt-controls', type: 'button' },
    'Run five controlled trace pairs',
  ) as HTMLButtonElement;
  const status = el('div', {
    id: 'oxt-status',
    role: 'status',
    'aria-live': 'polite',
    'aria-label': 'Conjunctive search result',
  });
  const controlsResult = el('div', {
    id: 'oxt-control-result',
    role: 'status',
    'aria-live': 'polite',
    'aria-label': 'OXT controlled trace result',
  });

  let queryGeneration = 0;
  let controlGeneration = 0;
  let queryInFlight = false;

  const resetQueryEvidence = (message = 'No conjunction executed yet.'): void => {
    clear(status);
    status.append(el('p', { class: 'note', text: message }));
  };
  resetQueryEvidence();
  controlsResult.append(
    el('p', {
      class: 'note',
      text: 'No controlled trace pair has run yet. The control uses a fresh OXT server for each pair.',
    }),
  );

  queryInput.addEventListener('input', () => {
    // Retire the pending completion before changing what the field says. A
    // result derived from the old value must never reappear beside new input.
    queryGeneration += 1;
    if (queryInFlight) {
      // WebCrypto promises are not cancellable. Keep this control serialized
      // until the retired operation drains so a second query cannot race it.
      // Any server work the first query already performed remains honest
      // persistent-transcript evidence and is named in the status below.
      runButton.disabled = true;
      runButton.setAttribute('aria-busy', 'true');
      runButton.textContent = 'Finishing retired computation…';
    }
    resetQueryEvidence(
      queryInFlight
        ? 'Input changed. The retired computation may already have reached the isolated servers; wait for it to finish before running the displayed conjunction.'
        : 'Input changed; run the displayed conjunction to create new evidence.',
    );
  });

  runButton.addEventListener('click', () => {
    void (async () => {
      const generation = ++queryGeneration;
      const input = queryInput.value;
      queryInFlight = true;
      runButton.disabled = true;
      runButton.setAttribute('aria-busy', 'true');
      runButton.textContent = 'Computing both real searches…';
      clear(status);
      status.append(el('p', { class: 'note', text: 'Deriving tokens and evaluating the conjunction…' }));
      try {
        const comparison = await lesson.run(input);
        if (generation !== queryGeneration) return;
        renderComparison(status, comparison);
      } catch (error) {
        if (generation !== queryGeneration) return;
        clear(status);
        if (error instanceof ConjunctiveQueryError) {
          status.append(
            verdict(
              'warn',
              '!',
              'QUERY REJECTED BEFORE TRANSMISSION',
              error.message,
            ),
          );
        } else {
          status.append(
            verdict(
              'warn',
              '!',
              'COMPARISON FAILED',
              `The computation did not complete. Do not treat any partial server work as a result. ${errorMessage(error)}`,
            ),
          );
        }
      } finally {
        queryInFlight = false;
        runButton.disabled = false;
        runButton.setAttribute('aria-busy', 'false');
        runButton.textContent = 'Compare both constructions';
      }
    })();
  });

  controlsButton.addEventListener('click', () => {
    void (async () => {
      const generation = ++controlGeneration;
      controlsButton.disabled = true;
      controlsButton.setAttribute('aria-busy', 'true');
      controlsButton.textContent = 'Evaluating controlled traces…';
      clear(controlsResult);
      controlsResult.append(el('p', { class: 'note', text: 'Computing candidate points…' }));
      try {
        const controls = await lesson.runControlPairs();
        if (generation !== controlGeneration) return;
        renderControls(controlsResult, controls);
      } catch (error) {
        if (generation !== controlGeneration) return;
        clear(controlsResult);
        controlsResult.append(verdict('warn', '!', 'CONTROL FAILED', errorMessage(error)));
      } finally {
        if (generation === controlGeneration) {
          controlsButton.disabled = false;
          controlsButton.setAttribute('aria-busy', 'false');
          controlsButton.textContent = 'Run five controlled trace pairs';
        }
      }
    })();
  });

  body.append(
    constructionBoundary(),
    el(
      'div',
      { class: 'controls' },
      labelled('Exactly “keyword AND keyword”', queryInput),
      runButton,
    ),
    status,
    el('h3', { text: 'Measure equality and intersection evidence across queries' }),
    el(
      'p',
      { class: 'note' },
      'These pairs separate repeated s-term lookup from repeated candidate-point evidence. The narrator uses corpus truth only to label why measured point bytes repeated; that truth is never sent in a query.',
    ),
    el('div', { class: 'controls' }, controlsButton),
    controlsResult,
    renderOramComparison(lesson.oram),
    securityBoundary(),
  );

  return section;
}

function constructionBoundary(): HTMLElement {
  return el(
    'div',
    { class: 'honesty' },
    el('strong', { text: 'Construction boundary. ' }),
    'This is a static, two-distinct-keyword teaching adapter of Cash et al.’s OXT equations, not the paper’s optimized TSet. It uses five independent OXT-only keys, a globally shuffled flat addressed TSet, AES-256-GCM identifier ciphertexts, and a sorted exact XSet of canonical RFC 9496 ristretto255 encodings. The client chooses the less frequent term as s (ASCII order breaks ties). Exact membership removes Bloom-filter false positives; it does not transfer the complete OXT proof to this adapter.',
  );
}

function renderComparison(target: HTMLElement, comparison: ConjunctiveComparison): void {
  clear(target);
  const naive = comparison.naive;
  const oxt = comparison.oxt;
  target.append(
    verdict(
      'info',
      '=',
      'SAME PLAINTEXT ANSWER, DIFFERENT TRANSCRIPT',
      `${comparison.input.canonical} returned ${formatIds(oxt.finalResultIds)} by both routes.`,
    ),
    el(
      'div',
      { class: 'leakage-cards' },
      metric('Naïve lookups', String(naive.queryVolume), 'two complete posting lists'),
      metric('OXT server queries', String(oxt.queryVolume), 'one stag plus cross-tokens'),
      metric('OXT TSet rows', String(oxt.sListSize), `one ${oxt.sTerm} list`),
      metric('Exact XSet tests', String(oxt.membershipTests), 'one per s-list row'),
      metric('Final matches', String(oxt.finalResultIds.length), formatIds(oxt.finalResultIds)),
    ),
    el(
      'div',
      { class: 'split' },
      el(
        'section',
        { class: 'side side-client', 'aria-label': 'Naive SSE comparison with client-only labels' },
        el('h3', { class: 'side-title', text: 'Naïve: two ordinary SSE searches' }),
        ...naive.terms.map((term, index) =>
          el(
            'div',
            { class: 'value-row' },
            el('span', { class: 'value-label', text: `Token ${index + 1}, client label: ${term.keyword}` }),
            el(
              'span',
              {
                class: 'value-bytes is-token',
                title: term.tokenHex,
                text: `${shortHex(term.tokenHex)} → ${term.resultSize} [${term.resultIds.join(', ')}] · repeated token: ${term.repeatedToken ? 'yes' : 'no'}`,
              },
            ),
          ),
        ),
        el('p', {
          class: 'side-note',
          text: `The plaintext keyword labels are client/narrator context, not server input. The server returned both full lists; the client intersected them to ${formatIds(naive.finalResultIds)}. The repeat flag is measured against this isolated SSE server’s earlier tokens.`,
        }),
      ),
      el(
        'section',
        { class: 'side side-server', 'aria-label': 'OXT comparison with client-only labels' },
        el('h3', { class: 'side-title', text: 'OXT: one TSet walk plus cross-tests' }),
        valueRow('s role, client label', `${oxt.sTerm} (${oxt.sListSize} rows)`),
        valueRow('x role, client label', oxt.xTerm),
        valueRow('stag sent', shortHex(oxt.stagHex), oxt.stagHex),
        valueRow('x posting list sent', 'no'),
        valueRow('repeated stag', oxt.repeatedLookup ? 'yes' : 'no'),
        valueRow('prior point matches', String(oxt.repeatedCandidateTagHexes.length)),
        el('p', {
          class: 'side-note',
          text: 'The server sees the stable stag, the number of cross-tokens, every candidate point and match position, then the client’s final document-identifier access request. The query sends neither plaintext term nor a separately enumerated x-term posting list or count. This bounded lesson does not model a separate encrypted body store.',
        }),
      ),
    ),
    scrollRegion(
      'OXT exact XSet membership evaluations',
      el(
        'table',
        { class: 'data' },
        el(
          'caption',
          {},
          'For each addressed s-list row, the server computes [y]xtoken and tests the resulting canonical point against exact XSet membership.',
        ),
        el(
          'thead',
          {},
          el(
            'tr',
            {},
            el('th', { scope: 'col', text: 'c' }),
            el('th', { scope: 'col', text: 'xtoken' }),
            el('th', { scope: 'col', text: '[y]xtoken candidate' }),
            el('th', { scope: 'col', text: 'XSet' }),
          ),
        ),
        el(
          'tbody',
          {},
          ...oxt.rows.map((row) =>
            el(
              'tr',
              {},
              el('th', { scope: 'row', text: row.position }),
              el('td', { class: 'mono', title: row.xtokenHex, text: shortHex(row.xtokenHex) }),
              el('td', {
                class: 'mono',
                title: row.candidateTagHex,
                text: shortHex(row.candidateTagHex),
              }),
              el(
                'td',
                {},
                row.matched
                  ? badge('ok', 'Y', 'member')
                  : badge('info', 'N', 'not a member'),
              ),
            ),
          ),
        ),
      ),
    ),
    el(
      'p',
      { class: 'honesty' },
      'The cancellation is executable: y = F_I(id) / F_Z(s,c), xtoken = [F_Z(s,c)F_X(x)]B, so [y]xtoken = [F_I(id)F_X(x)]B. RFC 9496 defines the group encoding and operations; decisional Diffie–Hellman hardness is a separate explicit assumption, not something the RFC proves.',
    ),
  );
}

function renderControls(target: HTMLElement, controls: readonly OxtControlPair[]): void {
  clear(target);
  target.append(
    scrollRegion(
      'Controlled OXT equality and intersection traces',
      el(
        'table',
        { class: 'data' },
        el(
          'caption',
          {},
          'Each row is two searches on a fresh server. Repeated points are byte-for-byte canonical ristretto255 encodings observed in both searches.',
        ),
        el(
          'thead',
          {},
          el(
            'tr',
            {},
            el('th', { scope: 'col', text: 'Control' }),
            el('th', { scope: 'col', text: 'Queries' }),
            el('th', { scope: 'col', text: 'Same stag?' }),
            el('th', { scope: 'col', text: 'Repeated points' }),
            el('th', { scope: 'col', text: 'Narrator check' }),
          ),
        ),
        el(
          'tbody',
          {},
          ...controls.map((control) =>
            el(
              'tr',
              {},
              el('th', { scope: 'row', text: controlLabel(control.kind) }),
              el(
                'td',
                {},
                el('span', { class: 'mono', text: control.firstQuery }),
                el('br'),
                el('span', { class: 'mono', text: control.secondQuery }),
              ),
              el('td', { text: control.repeatedLookup ? 'yes' : 'no' }),
              el('td', { text: String(control.repeatedCandidateTagHexes.length) }),
              el('td', {
                text:
                  control.repeatedDocumentIdsForNarrator.length > 0
                    ? control.repeatedDocumentIdsForNarrator.join(', ')
                    : 'none',
              }),
            ),
          ),
        ),
      ),
    ),
    verdict(
      'warn',
      '!',
      'ZERO REPEATS IS AMBIGUOUS',
      'The shared-x/disjoint-s control produces zero repeated points even though both x-terms are audit. A zero cannot prove that x changed. The different-x/overlapping-s control also produces zero, for a different reason.',
    ),
    el(
      'p',
      { class: 'note' },
      'This is equality/intersection-pattern evidence across searches. It is not fed into the single-keyword IKK attack elsewhere on this page, and it is not a proof that every production OXT transcript has the same leakage.',
    ),
  );
}

function renderOramComparison(cost: PathOramCost): HTMLElement {
  return el(
    'section',
    { 'aria-labelledby': 'h-oxt-oram-comparison' },
    el('h3', { id: 'h-oxt-oram-comparison', text: 'What fixed-volume Path ORAM changes — a derived comparison' }),
    el(
      'div',
      { class: 'leakage-cards' },
      metric('Logical blocks N', String(cost.documentCount), 'one document per block'),
      metric('Tree depth L', String(cost.treeDepth), `${cost.leaves} leaves`),
      metric('Path transfer', String(cost.transfersPerFetch), `${cost.readsPerFetch} read + ${cost.writesPerFetch} write`),
      metric('Padded query', String(cost.paddedTransfers), `${cost.maxPairIntersection} logical fetches`),
    ),
    scrollRegion(
      'Path ORAM fixed-result padding cases',
      el(
        'table',
        { class: 'data' },
        el(
          'caption',
          {},
          `Derived for Z=${cost.bucketSize}: ${cost.bucketsPerPath} buckets on each root-to-leaf path, ${cost.transfersPerFetch} encrypted block transfers per logical fetch.`,
        ),
        el(
          'thead',
          {},
          el(
            'tr',
            {},
            el('th', { scope: 'col', text: 'Real matches' }),
            el('th', { scope: 'col', text: 'Dummy fetches' }),
            el('th', { scope: 'col', text: 'Logical fetches' }),
            el('th', { scope: 'col', text: 'Block transfers' }),
          ),
        ),
        el(
          'tbody',
          {},
          ...cost.paddingCases.map((row) =>
            el(
              'tr',
              {},
              el('th', { scope: 'row', text: row.realResults }),
              el('td', { text: row.dummyFetches }),
              el('td', { text: row.logicalFetches }),
              el('td', { text: row.blockTransfers }),
            ),
          ),
        ),
      ),
    ),
    el(
      'p',
      { class: 'honesty' },
      `This table is arithmetic, not an ORAM execution. It assumes one document per block, N=${cost.documentCount}, Z=${cost.bucketSize}, a client position map and stash, and padding every answer to the corpus maximum of ${cost.maxPairIntersection}. Against a separate, non-colluding, semi-honest storage server, those fixed-shape accesses conceal final document addresses and result volume. They do not hide the OXT search server’s stag, s-list size, membership-test pattern, query volume, equality/intersection evidence, or timing. Recursive position maps, stash overflow, block sizing, active integrity, and network round trips are not modeled; ${cost.paddedTransfers} is a count of encrypted block transfers, not round trips.`,
    ),
  );
}

function securityBoundary(): HTMLElement {
  return el(
    'section',
    { 'aria-labelledby': 'h-oxt-boundary' },
    el('h3', { id: 'h-oxt-boundary', text: 'Security and publication boundary' }),
    el(
      'ul',
      { class: 'nongoals' },
      el('li', {}, 'Only two normalized, known, distinct keywords joined by one AND are accepted. OR, NOT, parentheses, duplicates, and longer expressions are rejected before either comparison server receives a byte.'),
      el('li', {}, 'The TSet is a bounded flat adapter: setup exposes total TSet and XSet sizes, while the first stag query exposes that s-list boundary. The server may retain and link it.'),
      el('li', {}, 'Exact XSet membership avoids probabilistic false positives when this honest-but-curious server executes the lookup. AES-GCM detects changed or relocated identifier ciphertexts, but a malicious server can omit a valid match or falsely include an authentic s-list row that failed the x-term test. These mechanisms prove neither active-server soundness/correctness nor completeness, and the static adapter has no version/freshness proof.'),
      el('li', {}, 'The group is RFC 9496 ristretto255. DDH hardness is assumed explicitly; no pairing-specific SXDH claim is needed or made.'),
      el('li', {}, 'The browser implementation is testable teaching code, not hardened or guaranteed constant-time JavaScript. It models one trusted owner/client and one honest-but-curious search server, not dynamic updates, multiple owners, collusion, or production isolation.'),
    ),
    el(
      'p',
      { class: 'note' },
      'Primary sources: ',
      el('a', { href: 'https://eprint.iacr.org/2013/169' }, 'Cash et al., OXT'),
      '; ',
      el('a', { href: 'https://www.rfc-editor.org/rfc/rfc9496.html' }, 'RFC 9496'),
      '; and ',
      el('a', { href: 'https://people.csail.mit.edu/devadas/pubs/PathORAMJACM.pdf' }, 'Stefanov et al., Path ORAM'),
      '.',
    ),
  );
}

function metric(label: string, value: string, detail: string): HTMLElement {
  return el(
    'div',
    { class: 'score-block' },
    el('div', { class: 'score-label', text: label }),
    el('div', { class: 'score-value', text: value }),
    el('div', { class: 'note', text: detail }),
  );
}

function valueRow(label: string, value: string, title?: string): HTMLElement {
  return el(
    'div',
    { class: 'value-row' },
    el('span', { class: 'value-label', text: label }),
    el('span', { class: 'value-bytes', text: value, title }),
  );
}

function formatIds(ids: readonly string[]): string {
  return ids.length === 0 ? 'no documents' : `[${ids.join(', ')}]`;
}

function controlLabel(kind: OxtControlPair['kind']): string {
  switch (kind) {
    case 'shared-x-overlapping-s':
      return 'same x, overlapping s';
    case 'shared-x-disjoint-s':
      return 'same x, disjoint s';
    case 'different-x-overlapping-s':
      return 'different x, overlapping s';
    case 'repeated-s-different-x':
      return 'same s, different x';
    case 'identical-query':
      return 'identical query';
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
