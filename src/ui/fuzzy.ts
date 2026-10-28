/** Exhibit 9 — executable gram-based fuzzy search and overlap leakage. */
import type {
  FuzzyLessonRun,
  FuzzySearchLesson,
  ThresholdTrace,
} from '../fuzzy/lesson';
import { FuzzyInputError } from '../fuzzy/core';
import { badge, clear, el, labelled, panel, scrollRegion, shortHex, verdict } from './dom';

export function renderFuzzy(lesson: FuzzySearchLesson): HTMLElement {
  const { section, body } = panel(
    'EXHIBIT 9',
    'Fuzzy search — typo recovery leaks a neighborhood',
    'Compare the existing exact SSE route with Li et al.’s deletion-gram listing construction. The server tests real HMAC-SHA-256 trapdoors; the client decrypts candidates and applies the real Levenshtein distance.',
  );

  const query = el('input', {
    id: 'fuzzy-query',
    type: 'text',
    value: 'asudit',
    autocomplete: 'off',
    spellcheck: 'false',
    'aria-describedby': 'fuzzy-input-note',
  }) as HTMLInputElement;
  const threshold = el(
    'select',
    { id: 'fuzzy-threshold', 'aria-describedby': 'fuzzy-input-note' },
    el('option', { value: '0', text: '0 — exact only' }),
    el('option', { value: '1', text: '1 edit' }),
    el('option', { value: '2', text: '2 edits' }),
  ) as HTMLSelectElement;
  threshold.value = '1';
  const runButton = el(
    'button',
    { id: 'fuzzy-run', class: 'primary', type: 'button' },
    'Run exact and fuzzy search',
  ) as HTMLButtonElement;
  const status = el('div', {
    id: 'fuzzy-status',
    role: 'status',
    'aria-live': 'polite',
    'aria-label': 'Fuzzy search comparison result',
  });

  let generation = 0;
  let inFlight = false;

  const resetEvidence = (message = 'No fuzzy comparison executed yet.'): void => {
    clear(status);
    status.append(el('p', { class: 'note', text: message }));
  };
  resetEvidence();

  const retire = (): void => {
    generation += 1;
    if (inFlight) {
      runButton.disabled = true;
      runButton.setAttribute('aria-busy', 'true');
      runButton.textContent = 'Finishing retired computation…';
    }
    resetEvidence(
      inFlight
        ? 'Input changed. The retired WebCrypto work may already have reached an isolated comparison server; wait for it to finish before running the displayed input.'
        : 'Input changed; run the displayed word and threshold to create new evidence.',
    );
  };
  query.addEventListener('input', retire);
  threshold.addEventListener('change', retire);

  runButton.addEventListener('click', () => {
    void (async () => {
      const operation = ++generation;
      const input = query.value;
      const selectedThreshold = Number(threshold.value);
      inFlight = true;
      runButton.disabled = true;
      runButton.setAttribute('aria-busy', 'true');
      runButton.textContent = 'Building trapdoor bundles…';
      clear(status);
      status.append(el('p', { class: 'note', text: 'Running one exact query and three isolated fuzzy-threshold alternatives…' }));
      try {
        const result = await lesson.run(input, selectedThreshold);
        if (operation !== generation) return;
        renderRun(status, result);
      } catch (error) {
        if (operation !== generation) return;
        clear(status);
        status.append(
          error instanceof FuzzyInputError
            ? verdict('warn', '!', 'QUERY REJECTED BEFORE TRANSMISSION', error.message)
            : verdict(
                'warn',
                '!',
                'FUZZY COMPARISON FAILED',
                `The computation did not complete. No partial output is a search result. ${errorMessage(error)}`,
              ),
        );
      } finally {
        inFlight = false;
        runButton.disabled = false;
        runButton.setAttribute('aria-busy', 'false');
        runButton.textContent = 'Run exact and fuzzy search';
      }
    })();
  });

  body.append(
    constructionBoundary(),
    el(
      'div',
      { class: 'controls' },
      labelled('Search word', query),
      labelled('Edit threshold', threshold),
      runButton,
    ),
    el('p', {
      id: 'fuzzy-input-note',
      class: 'note',
      text: 'This bounded lesson accepts 3–12 ASCII letters. Case and outer whitespace are normalized before search; that normalization is not fuzzy matching. One click evaluates d=0, 1, and 2 in isolated alternative indexes so the cost table comes from the current word.',
    }),
    status,
    el(
      'p',
      { class: 'honesty' },
      'Leakage boundary. HMAC hides each gram’s text from a server without the key, but it does not hide deterministic equality among trapdoors, the number of trapdoors in a query, matching-row volume, or final document access. The inference below assumes three prior query labels became known out of band. It establishes one neighborhood link in this run, not universal plaintext recovery and not a claim about every encrypted fuzzy-search scheme.',
    ),
  );

  return section;
}

function constructionBoundary(): HTMLElement {
  return el(
    'div',
    { class: 'honesty' },
    el('strong', { text: 'Construction boundary. ' }),
    'This is a bounded adaptation of Li et al., ePrint 2009/593, §§3.4–6 and Algorithm 2. For each word and d, it HMACs every relative-order-preserving subsequence obtained by deleting at most d characters. The server returns encrypted candidate rows; the client must apply unit-cost insertion/deletion/substitution distance. This exact-map listing adapter is not the paper’s symbol trie, not LSH, and not Damerau–Levenshtein search.',
  );
}

function renderRun(target: HTMLElement, run: FuzzyLessonRun): void {
  clear(target);
  const selected = run.selected;
  const inference = run.inference.inferredAnchor;
  const exactAnchors = run.inference.anchors
    .filter((anchor) => anchor.exactTokenEqual)
    .map((anchor) => anchor.label);
  const addsDistinctNeighbor = inference !== null && !exactAnchors.includes(inference);
  target.append(
    addsDistinctNeighbor
      ? verdict(
          'exposed',
          '!',
          'NEIGHBORHOOD LINKED FROM OPAQUE TOKENS',
          exactAnchors.length === 0
            ? `Exact SSE linked none of the three known anchors, but the d=${run.selectedThreshold} fuzzy bundle overlaps the known “${inference}” bundle. The server learned that relation without receiving “${run.query}”.`
            : `Exact SSE linked only ${formatQuoted(exactAnchors)}, while the d=${run.selectedThreshold} fuzzy bundle uniquely overlaps the distinct known “${inference}” bundle. The server learned that added relation without receiving “${run.query}”.`,
        )
      : inference
        ? verdict(
            'info',
            '=',
            'EXACT QUERY ALREADY LINKED THIS LABEL',
            `The exact token and fuzzy bundle both link “${inference}”. This control shows no distinct neighbor beyond the equality already visible to exact SSE.`,
          )
      : verdict(
          'info',
          '=',
          'NO UNIQUE KNOWN NEIGHBOR IN THIS CONTROL',
          exactAnchors.length === 0
            ? `At d=${run.selectedThreshold}, these observed bytes do not select one uniquely overlapping known anchor. This is a bounded non-inference, not a privacy proof.`
            : `Exact SSE linked ${formatQuoted(exactAnchors)}, but the d=${run.selectedThreshold} fuzzy bytes do not select one unique additional anchor. This is a bounded non-inference, not a privacy proof.`,
        ),
    el(
      'div',
      { id: 'fuzzy-selected-summary', class: 'leakage-cards' },
      metric('Exact SSE results', String(run.exact.resultSize), formatIds(run.exact.resultIds)),
      metric('Fuzzy trapdoors', String(selected.queryTrapdoorHexes.length), `${selected.queryTrapdoorBytes} request bytes`),
      metric('Server candidate rows', String(selected.responseRows), `${selected.responseBytes} response bytes`),
      metric('Filtered keywords', String(selected.finalKeywords.length), formatWords(selected.finalKeywords)),
    ),
    renderExactAndFuzzy(run),
    renderCandidateTable(run),
    renderThresholdTable(run),
    renderInferenceTable(run),
  );
}

function renderExactAndFuzzy(run: FuzzyLessonRun): HTMLElement {
  return el(
    'div',
    {},
    el(
      'div',
      { class: 'split' },
      el(
        'section',
        { class: 'side side-client', 'aria-label': 'Exact SSE baseline' },
        el('h3', { class: 'side-title', text: 'Existing exact SSE route' }),
        valueRow('normalized query', run.query),
        valueRow('one 32-byte token', shortHex(run.exact.tokenHex, 16), run.exact.tokenHex),
        valueRow('result identifiers', formatIds(run.exact.resultIds)),
        el('p', {
          class: 'side-note',
          text: run.exact.resultSize === 0
            ? 'No indexed keyword equals this normalized input. Different exact tokens reveal no similarity relation.'
            : 'The normalized input exactly matched one indexed keyword; the ordinary SSE access pattern remains visible.',
        }),
      ),
      el(
        'section',
        { class: 'side side-server', 'aria-label': 'Gram-based fuzzy server transcript' },
        el('h3', { class: 'side-title', text: `Fuzzy listing route at d=${run.selectedThreshold}` }),
        valueRow('server lookups', String(run.selected.serverLookups)),
        valueRow('matched trapdoors', String(run.selected.matchedTrapdoorHexes.length)),
        valueRow('opaque rows returned', String(run.selected.responseRows)),
        valueRow('final document request', formatIds(run.selected.finalDocumentIds)),
        el('p', {
          class: 'side-note',
          text: 'Only the client/narrator can label grams and candidate keywords. The server sees the right-hand trapdoor bytes, matching encrypted rows, bundle overlap, and final access request.',
        }),
      ),
    ),
    scrollRegion(
      'Current fuzzy query grams and opaque trapdoors',
      el(
        'table',
        { id: 'fuzzy-query-token-table', class: 'data' },
        el('caption', {}, `${run.selected.queryGrams.length} client grams become ${run.selected.queryTrapdoorHexes.length} server-visible trapdoors`),
        el(
          'thead',
          {},
          el('tr', {}, el('th', { scope: 'col', text: 'Client-only gram' }), el('th', { scope: 'col', text: 'Trapdoor sent' }), el('th', { scope: 'col', text: 'Index hit' })),
        ),
        el(
          'tbody',
          {},
          ...run.selected.queryGrams.map((gram, index) => {
            const token = run.selected.queryTrapdoorHexes[index]!;
            const hit = run.selected.matchedTrapdoorHexes.includes(token);
            return el(
              'tr',
              {},
              el('td', { class: 'mono', text: gram }),
              el('td', { class: 'mono', title: token, text: shortHex(token, 12) }),
              el('td', {}, hit ? badge('warn', '!', 'matched row') : badge('ok', '✓', 'no row')),
            );
          }),
        ),
      ),
    ),
  );
}

function renderCandidateTable(run: FuzzyLessonRun): HTMLElement {
  const candidates = run.selected.candidates;
  return el(
    'section',
    { 'aria-labelledby': 'h-fuzzy-candidates' },
    el('h3', { id: 'h-fuzzy-candidates', text: 'Client filtering: a gram hit is only a candidate' }),
    el('p', {
      class: 'note',
      text: 'The keyword and distance columns appear only after client decryption. “False positive” below means a server candidate outside the declared edit threshold; it is removed before the final document request.',
    }),
    candidates.length === 0
      ? verdict('info', '=', 'NO SERVER CANDIDATES', 'No query trapdoor matched this threshold-specific encrypted index.')
      : scrollRegion(
          'Decrypted fuzzy candidates and client filter verdicts',
          el(
            'table',
            { id: 'fuzzy-candidate-table', class: 'data' },
            el('caption', {}, `${candidates.length} unique candidate keyword${candidates.length === 1 ? '' : 's'} after decrypting ${run.selected.responseRows} row${run.selected.responseRows === 1 ? '' : 's'}`),
            el(
              'thead',
              {},
              el('tr', {},
                el('th', { scope: 'col', text: 'Decrypted keyword' }),
                el('th', { scope: 'col', text: 'Matching rows' }),
                el('th', { scope: 'col', text: 'Edit distance' }),
                el('th', { scope: 'col', text: 'Client verdict' }),
              ),
            ),
            el(
              'tbody',
              {},
              ...candidates.map((candidate) =>
                el(
                  'tr',
                  { 'data-keyword': candidate.keyword },
                  el('td', { class: 'mono', text: candidate.keyword }),
                  el('td', { text: String(candidate.matchingRows) }),
                  el('td', { text: String(candidate.distance) }),
                  el('td', {}, candidate.accepted
                    ? badge('ok', '✓', 'within threshold')
                    : badge('alarm', '!', 'false positive — filtered')),
                ),
              ),
            ),
          ),
        ),
  );
}

function renderThresholdTable(run: FuzzyLessonRun): HTMLElement {
  return el(
    'section',
    { 'aria-labelledby': 'h-fuzzy-threshold-ledger' },
    el('h3', { id: 'h-fuzzy-threshold-ledger', text: 'Threshold ledger — real alternative indexes and this query' }),
    el('p', {
      class: 'note',
      text: 'Each row is a separately built alternative index; do not add their storage. Candidate rates classify unique decrypted candidate keywords against a plaintext Levenshtein oracle over all 14 indexed keywords. The two final-document columns are an oracle consistency check, not a measured error rate: the lesson compares the answer after client filtering with the plaintext oracle over all 24 corpus documents and refuses to render a run that disagrees, so they can only ever read 0 over their denominator and show that the check ran. “n/a” means the denominator is zero.',
    }),
    scrollRegion(
      'Fuzzy threshold storage, query cost, and error rates',
      el(
        'table',
        { id: 'fuzzy-threshold-table', class: 'data' },
        el('caption', {}, `Computed for “${run.query}” from three encrypted indexes built in this session`),
        el(
          'thead',
          {},
          el('tr', {},
            el('th', { scope: 'col', text: 'd' }),
            el('th', { scope: 'col', text: 'Stored rows' }),
            el('th', { scope: 'col', text: 'Stored bytes' }),
            el('th', { scope: 'col', text: 'Query tokens / bytes' }),
            el('th', { scope: 'col', text: 'Lookups' }),
            el('th', { scope: 'col', text: 'Response rows / bytes' }),
            el('th', { scope: 'col', text: 'Candidate TP' }),
            el('th', { scope: 'col', text: 'Candidate FP rate' }),
            el('th', { scope: 'col', text: 'Candidate FN rate' }),
            el('th', { scope: 'col', text: 'Final doc FP (oracle check)' }),
            el('th', { scope: 'col', text: 'Final doc FN (oracle check)' }),
          ),
        ),
        el(
          'tbody',
          {},
          ...run.thresholds.map((trace) => thresholdRow(trace, trace.threshold === run.selectedThreshold)),
        ),
      ),
    ),
  );
}

function thresholdRow(trace: ThresholdTrace, selected: boolean): HTMLElement {
  return el(
    'tr',
    {
      'data-threshold': String(trace.threshold),
      'data-selected': selected ? 'true' : 'false',
      class: selected ? 'is-new' : undefined,
    },
    el('th', { scope: 'row', text: String(trace.threshold) }),
    el('td', { text: String(trace.storage.associations) }),
    el('td', { text: String(trace.storage.totalBytes) }),
    el('td', { text: `${trace.queryTrapdoorHexes.length} / ${trace.queryTrapdoorBytes}` }),
    el('td', { text: String(trace.serverLookups) }),
    el('td', { text: `${trace.responseRows} / ${trace.responseBytes}` }),
    el('td', { text: String(trace.candidateTruePositives) }),
    el('td', { text: formatRate(trace.candidateFalsePositiveRate.numerator, trace.candidateFalsePositiveRate.denominator) }),
    el('td', { text: formatRate(trace.candidateFalseNegativeRate.numerator, trace.candidateFalseNegativeRate.denominator) }),
    el('td', { text: formatRate(trace.finalFalsePositiveRate.numerator, trace.finalFalsePositiveRate.denominator) }),
    el('td', { text: formatRate(trace.finalFalseNegativeRate.numerator, trace.finalFalseNegativeRate.denominator) }),
  );
}

function renderInferenceTable(run: FuzzyLessonRun): HTMLElement {
  return el(
    'section',
    { 'aria-labelledby': 'h-fuzzy-inference' },
    el('h3', { id: 'h-fuzzy-inference', text: 'Server control — three labels known out of band' }),
    el('p', {
      class: 'note',
      text: 'The same server previously observed query bundles later labelled audit, lawsuit, and breach by outside context. It compares only retained bytes. Exact-token equality asks whether the words were identical; fuzzy intersection also links different words whose bundles share a trapdoor.',
    }),
    scrollRegion(
      'Known-query anchor overlap evidence',
      el(
        'table',
        { id: 'fuzzy-inference-table', class: 'data' },
        el('caption', {}, `Server-only byte comparison at d=${run.selectedThreshold}`),
        el(
          'thead',
          {},
          el('tr', {},
            el('th', { scope: 'col', text: 'Known label' }),
            el('th', { scope: 'col', text: 'Exact token equal' }),
            el('th', { scope: 'col', text: 'Shared fuzzy tokens' }),
            el('th', { scope: 'col', text: 'Jaccard evidence' }),
          ),
        ),
        el(
          'tbody',
          {},
          ...run.inference.anchors.map((anchor) =>
            el(
              'tr',
              { 'data-anchor': anchor.label },
              el('th', { scope: 'row', text: anchor.label }),
              el('td', {}, anchor.exactTokenEqual ? badge('warn', '!', 'yes') : badge('ok', '✓', 'no')),
              el('td', { text: String(anchor.fuzzyIntersection) }),
              el('td', { text: `${anchor.fuzzyIntersection}/${anchor.fuzzyUnion}` }),
            ),
          ),
        ),
      ),
    ),
  );
}

function metric(label: string, value: string, note: string): HTMLElement {
  return el(
    'div',
    { class: 'score-block' },
    el('div', { class: 'score-label', text: label }),
    el('div', { class: 'score-value', text: value }),
    el('div', { class: 'note', text: note }),
  );
}

function valueRow(label: string, value: string, title?: string): HTMLElement {
  return el(
    'div',
    { class: 'value-row' },
    el('span', { class: 'value-label', text: label }),
    el('span', { class: 'value-bytes', text: value, title: title ?? value }),
  );
}

function formatRate(numerator: number, denominator: number): string {
  if (denominator === 0) return `${numerator}/0 (n/a)`;
  return `${numerator}/${denominator} (${((numerator / denominator) * 100).toFixed(1)}%)`;
}

function formatIds(ids: readonly string[]): string {
  return ids.length === 0 ? 'none' : ids.join(', ');
}

function formatWords(words: readonly string[]): string {
  return words.length === 0 ? 'none' : words.join(', ');
}

function formatQuoted(words: readonly string[]): string {
  return words.map((word) => `“${word}”`).join(', ');
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
