/** Exhibit 10 — multi-user search, KWAP collusion, and split trust. */
import type { MuseLessonRun } from '../muse/lesson';
import { MUSE_SCENARIO } from '../muse/scenario';
import { clear, el, liveRegion, panel, scrollRegion, shortHex, verdict } from './dom';

export function renderMuse(): HTMLElement {
  const { section, body } = panel(
    'EXHIBIT 10',
    'Multi-user search: one known query travels farther than permission',
    'Run one reader/writer authorization graph twice: first through an iterative-testing server that exposes keyword-access-pattern edges, then through a bounded Query-Multiplexer/Data-Host split.',
  );
  const runButton = el('button', {
    id: 'muse-run',
    class: 'primary',
    type: 'button',
    text: 'Run fresh multi-user session',
  });
  const status = liveRegion('Multi-user search result');
  status.id = 'muse-status';
  status.append(el('p', {
    class: 'note',
    text: 'No session executed yet. A run generates fresh reader/writer scalars and a fresh 1024-bit teaching Paillier key.',
  }));
  let generation = 0;

  runButton.addEventListener('click', () => {
    const current = ++generation;
    runButton.setAttribute('aria-busy', 'true');
    runButton.setAttribute('disabled', '');
    runButton.textContent = 'Generating and executing…';
    clear(status);
    status.append(el('p', {
      class: 'note',
      text: 'Generating role keys, executing real BLS12-381 pairings, then evaluating packed Paillier selectors…',
    }));

    void import('../muse/lesson')
      .then(({ MuseLesson }) => MuseLesson.create())
      .then((lesson) => lesson.run())
      .then((run) => {
        if (generation !== current) return;
        renderMuseRun(status, run);
      })
      .catch((error: unknown) => {
        if (generation !== current) return;
        clear(status);
        status.append(verdict(
          'warn',
          '!',
          'SESSION REFUSED',
          error instanceof Error ? error.message : String(error),
        ));
      })
      .finally(() => {
        if (generation !== current) return;
        runButton.removeAttribute('aria-busy');
        runButton.removeAttribute('disabled');
        runButton.textContent = 'Run another fresh session';
      });
  });

  body.append(
    constructionBoundary(),
    renderAuthorizationGraph(),
    el('div', { class: 'controls' }, runButton),
    status,
  );
  return section;
}

function constructionBoundary(): HTMLElement {
  return el(
    'div',
    { class: 'honesty' },
    el('strong', { text: 'Construction boundary. ' }),
    'The pairing equations, zero-sum garbled Bloom filters, AES-GCM result envelopes, and Paillier selector arithmetic execute here. The single-server attack follows Van Rompay–Molva–Önen, PoPETs 2017 §§3–4; the split follows their SCC 2018 §§2–6.3. This browser adapter uses a non-production 1024-bit Paillier modulus and omits the paper’s recursive OT, in-line ZGBF, optimized parameters, network isolation, and full proof. ',
    el(
      'a',
      { href: 'https://petsymposium.org/popets/2017/popets-2017-0034.pdf' },
      'Attack paper',
    ),
    ' · ',
    el(
      'a',
      { href: 'https://eprint.iacr.org/2018/090' },
      'Split-trust paper',
    ),
  );
}

function renderAuthorizationGraph(): HTMLElement {
  return el(
    'section',
    { 'aria-labelledby': 'h-muse-graph' },
    el('h3', { id: 'h-muse-graph', text: 'Declared roles and public authorization graph' }),
    el('p', {
      class: 'note',
      text: 'The teaching oracle shows plaintext index contents so you can check outcomes. Neither server attack API receives this table. The known-query reader can search Clinical A only; the target reader can search all three writers.',
    }),
    scrollRegion(
      'Multi-user search roles and authorizations',
      el(
        'table',
        { id: 'muse-authorization-table', class: 'data' },
        el('caption', {}, 'Omniscient teaching view — not an attacker input'),
        el(
          'thead',
          {},
          el('tr', {},
            el('th', { scope: 'col', text: 'Writer' }),
            el('th', { scope: 'col', text: 'Plaintext keywords' }),
            el('th', { scope: 'col', text: 'Authorized readers' }),
          ),
        ),
        el(
          'tbody',
          {},
          ...MUSE_SCENARIO.writers.map((writer) =>
            el(
              'tr',
              { 'data-writer': writer.id },
              el('th', { scope: 'row', text: `${writer.label} (${writer.id})` }),
              el('td', { class: 'mono', text: writer.keywords.join(', ') }),
              el('td', {
                text: Object.entries(MUSE_SCENARIO.authorizations)
                  .filter(([, writerIds]) => (writerIds as readonly string[]).includes(writer.id))
                  .map(([readerId]) => readerId)
                  .join(', '),
              }),
            ),
          ),
        ),
      ),
    ),
  );
}

function renderMuseRun(target: HTMLElement, run: MuseLessonRun): void {
  clear(target);
  target.append(
    run.singleServer.recoveredTarget && run.singleServer.crossedAuthorizationBoundary
      ? verdict(
          'exposed',
          '!',
          'KNOWN LABEL CROSSED THE AUTHORIZATION GRAPH',
          `The colluding reader disclosed only the label of its own “audit” query, which searched writer-a. Equality edges then labelled ${run.singleServer.targetQuery.queryId} and writer-b’s matching row, even though that reader was never authorized for writer-b.`,
        )
      : verdict(
          'warn',
          '!',
          'EXPECTED EQUALITY PATH WAS NOT RECOVERED',
          'The current transcript did not establish the bounded attack fixture; no recovery claim is made.',
        ),
    renderRejections(run),
    renderSingleServer(run),
    renderSplitTrust(run),
    renderCollusionBoundary(run),
    el(
      'div',
      { class: 'honesty' },
      el('strong', { text: 'What this establishes. ' }),
      'Iterative testing exposes matching-row equality, so one known query can label another reader and data beyond the colluder’s authorization. In the split route, QM learns result length and DH learns routing, but neither alone receives both positivity and writer association. This is a bounded honest-but-curious execution under a QM/DH non-collusion assumption, not a production MUSE security proof.',
    ),
  );
}

function renderRejections(run: MuseLessonRun): HTMLElement {
  return el(
    'section',
    { 'aria-labelledby': 'h-muse-refusals' },
    el('h3', { id: 'h-muse-refusals', text: 'Role and authorization refusals happen before a transcript' }),
    scrollRegion(
      'Rejected multi-user operations',
      el(
        'table',
        { id: 'muse-rejection-table', class: 'data' },
        el('caption', {}, `${run.rejected.length} controlled refusals; each before/after count is equal`),
        el(
          'thead',
          {},
          el('tr', {},
            el('th', { scope: 'col', text: 'Actor' }),
            el('th', { scope: 'col', text: 'Attempt' }),
            el('th', { scope: 'col', text: 'Reason' }),
            el('th', { scope: 'col', text: 'Transcript before → after' }),
          ),
        ),
        el(
          'tbody',
          {},
          ...run.rejected.map((entry) =>
            el(
              'tr',
              {},
              el('th', { scope: 'row', text: entry.actorId }),
              el('td', { text: entry.operation }),
              el('td', { text: entry.reason }),
              el('td', { text: `${entry.transcriptCountBefore} → ${entry.transcriptCountAfter}` }),
            ),
          ),
        ),
      ),
    ),
  );
}

function renderSingleServer(run: MuseLessonRun): HTMLElement {
  const targetNode = `query/${run.singleServer.targetQuery.queryId}`;
  const targetClass = run.singleServer.attack.equivalenceClasses.find((members) =>
    members.includes(targetNode),
  ) ?? [];
  return el(
    'section',
    { 'aria-labelledby': 'h-muse-single-server' },
    el('h3', { id: 'h-muse-single-server', text: 'Single server — iterative testing creates the attack edges' }),
    el('p', {
      class: 'note',
      text: 'The server tests each transformed query against every encrypted row in each authorized index. A match creates one equality edge. The attack below consumes only those edges plus the colluding reader’s declared label for query-1.',
    }),
    scrollRegion(
      'Single-server keyword-access-pattern transcript',
      el(
        'table',
        { id: 'muse-single-transcript', class: 'data' },
        el('caption', {}, `${run.singleServer.transcript.length} accepted queries; no plaintext keyword field`),
        el(
          'thead',
          {},
          el('tr', {},
            el('th', { scope: 'col', text: 'Query node' }),
            el('th', { scope: 'col', text: 'Reader' }),
            el('th', { scope: 'col', text: 'Requested writers' }),
            el('th', { scope: 'col', text: 'Rows tested' }),
            el('th', { scope: 'col', text: 'Matching opaque rows' }),
            el('th', { scope: 'col', text: 'Trapdoor' }),
          ),
        ),
        el(
          'tbody',
          {},
          ...run.singleServer.transcript.map((observation) =>
            el(
              'tr',
              { 'data-query': observation.queryId },
              el('th', { scope: 'row', text: observation.queryId }),
              el('td', { text: observation.readerId }),
              el('td', { text: observation.requestedWriterIds.join(', ') }),
              el('td', { text: String(observation.testedRows) }),
              el('td', {
                class: 'mono',
                text: observation.matches.map((match) => match.rowId).join(', ') || 'none',
              }),
              el('td', {
                class: 'mono',
                title: observation.trapdoorHex,
                text: shortHex(observation.trapdoorHex, 14),
              }),
            ),
          ),
        ),
      ),
    ),
    el(
      'div',
      { id: 'muse-attack-summary', class: 'leakage-cards' },
      metric('Equality edges', String(run.singleServer.attack.equalityEdges.length), 'actual matching-row edges'),
      metric('Target query labelled', run.singleServer.recoveredTarget ? 'yes' : 'no', run.singleServer.targetQuery.queryId),
      metric('Unauthorized writer reached', run.singleServer.crossedAuthorizationBoundary ? 'yes' : 'no', 'writer-b'),
      metric('Changed-query control', run.singleServer.changedTargetStayedUnknown ? 'unknown' : 'labelled', run.singleServer.changedTargetQuery.queryId),
    ),
    scrollRegion(
      'Recovered target equality class',
      el(
        'table',
        { id: 'muse-equivalence-class', class: 'data' },
        el('caption', {}, 'Nodes labelled “audit” from the one known query'),
        el('thead', {}, el('tr', {}, el('th', { scope: 'col', text: 'Equality-class node' }), el('th', { scope: 'col', text: 'Recovered label' }))),
        el(
          'tbody',
          {},
          ...targetClass.map((node) =>
            el('tr', {}, el('th', { scope: 'row', class: 'mono', text: node }), el('td', { text: 'audit' })),
          ),
        ),
      ),
    ),
  );
}

function renderSplitTrust(run: MuseLessonRun): HTMLElement {
  const trace = run.splitTrust.first;
  const actual = trace.reader.writerIds;
  const noErrors = run.splitTrust.falsePositiveWriterIds.length === 0 && run.splitTrust.falseNegativeWriterIds.length === 0;
  return el(
    'section',
    { 'aria-labelledby': 'h-muse-split-trust' },
    el('h3', { id: 'h-muse-split-trust', text: 'Split trust — real pairing, ZGBF and Paillier dataflow' }),
    noErrors
      ? verdict(
          'ok',
          '=',
          'READER RESULT MATCHES THE INDEPENDENT ORACLE',
          `The reader opened ${formatList(actual)}; the separate plaintext oracle expected ${formatList(run.splitTrust.oracleWriterIds)}.`,
        )
      : verdict(
          'warn',
          '!',
          'BOUNDED FILTER ERROR OBSERVED',
          `False positives: ${formatList(run.splitTrust.falsePositiveWriterIds)}. False negatives: ${formatList(run.splitTrust.falseNegativeWriterIds)}. The measured result is shown rather than replaced.`,
        ),
    scrollRegion(
      'Split-trust reader result and independent oracle',
      el(
        'table',
        { id: 'muse-reader-result', class: 'data' },
        el('caption', {}, 'Reader output checked outside both server views'),
        el('thead', {}, el('tr', {}, el('th', { scope: 'col', text: 'Measure' }), el('th', { scope: 'col', text: 'Writer ids' }))),
        el(
          'tbody',
          {},
          resultRow('Reader opened', actual),
          resultRow('Plaintext oracle', run.splitTrust.oracleWriterIds),
          resultRow('False positives', run.splitTrust.falsePositiveWriterIds),
          resultRow('False negatives', run.splitTrust.falseNegativeWriterIds),
        ),
      ),
    ),
    el(
      'div',
      { id: 'muse-split-metrics', class: 'leakage-cards' },
      metric('Paillier modulus', `${trace.parameters.paillierModulusBits} bits`, 'teaching parameter, not production'),
      metric('ZGBF', `${trace.parameters.slots} × ${trace.parameters.shareBytes * 8}-bit`, `${trace.parameters.hashCount} positions per query`),
      metric('QM leakage', String(trace.queryManager.resultLength), 'result length'),
      metric('Repeat preparation', run.splitTrust.freshTrapdoor && run.splitTrust.freshSelectorCiphertexts ? 'fresh bytes' : 'reused bytes', 'xi and selector randomness'),
    ),
    scrollRegion(
      'Query Multiplexer outgoing messages',
      el(
        'table',
        { id: 'muse-qm-message-table', class: 'data' },
        el('caption', {}, 'QM knows which writer each outgoing selector targets'),
        el(
          'thead',
          {},
          el('tr', {},
            el('th', { scope: 'col', text: 'Writer' }),
            el('th', { scope: 'col', text: 'Blinded transformed element' }),
            el('th', { scope: 'col', text: 'Selected positions' }),
            el('th', { scope: 'col', text: 'Paillier selector digest' }),
          ),
        ),
        el(
          'tbody',
          {},
          ...trace.queryManager.messages.map((message) =>
            el(
              'tr',
              { 'data-writer': message.writerId },
              el('th', { scope: 'row', text: message.writerId }),
              hexCell(message.transformedElementHex),
              el('td', { text: message.selectedPositions.join(', ') }),
              hexCell(message.selectorDigestHex),
            ),
          ),
        ),
      ),
    ),
    scrollRegion(
      'Query Multiplexer shuffled responses',
      el(
        'table',
        { id: 'muse-qm-response-table', class: 'data' },
        el('caption', {}, 'QM learns positivity after opening shares, but each response omits writer identity'),
        el(
          'thead',
          {},
          el('tr', {},
            el('th', { scope: 'col', text: 'Response id' }),
            el('th', { scope: 'col', text: 'Zero-sum result' }),
            el('th', { scope: 'col', text: 'Sanitized packed ciphertext' }),
            el('th', { scope: 'col', text: 'Encrypted writer id' }),
          ),
        ),
        el(
          'tbody',
          {},
          ...trace.queryManager.shuffledResponses.map((response) =>
            el(
              'tr',
              { 'data-response': response.responseId, 'data-positive': String(response.positive) },
              el('th', { scope: 'row', class: 'mono', text: response.responseId }),
              el('td', { text: response.positive ? 'positive' : 'negative' }),
              hexCell(response.packedResponseHex),
              hexCell(response.encryptedWriterIdHex),
            ),
          ),
        ),
      ),
    ),
    scrollRegion(
      'Repeated split-trust query bytes',
      el(
        'table',
        { id: 'muse-repeat-table', class: 'data' },
        el('caption', {}, 'Same reader and keyword, fresh xi and fresh Paillier randomness'),
        el('thead', {}, el('tr', {}, el('th', { scope: 'col', text: 'Run' }), el('th', { scope: 'col', text: 'Reader trapdoor' }), el('th', { scope: 'col', text: 'writer-a selector digest' }))),
        el(
          'tbody',
          {},
          repeatRow('first', trace),
          repeatRow('repeat', run.splitTrust.repeat),
        ),
      ),
    ),
  );
}

function renderCollusionBoundary(run: MuseLessonRun): HTMLElement {
  const trace = run.splitTrust.first;
  return el(
    'section',
    { 'aria-labelledby': 'h-muse-collusion-boundary' },
    el('h3', { id: 'h-muse-collusion-boundary', text: 'Non-collusion is an assumption, not a hidden guarantee' }),
    el(
      'div',
      { class: 'split' },
      el(
        'section',
        { class: 'side side-client', 'aria-label': 'Query Multiplexer view' },
        el('h4', { class: 'side-title', text: 'QM alone' }),
        el('p', { text: `Knows ${trace.queryManager.positiveResponseIds.length} positive response id(s) and the result length.` }),
        el('p', { class: 'side-note', text: 'Does not receive response-id → writer routing.' }),
      ),
      el(
        'section',
        { class: 'side side-server', 'aria-label': 'Data Host view' },
        el('h4', { class: 'side-title', text: 'DH alone' }),
        el('p', { text: `Knows routing for ${trace.dataHost.responseRouting.length} response id(s).` }),
        el('p', { class: 'side-note', text: 'Does not hold the Paillier decryption key and does not know which response passed zero-sum checking.' }),
      ),
    ),
    verdict(
      'warn',
      '!',
      'QM + DH COLLUSION RECONSTRUCTS THE ASSOCIATION',
      'Combining the two views below maps each positive response back to a writer. The 2018 construction assumes these two service roles do not collude; this lesson does not erase that assumption.',
    ),
    scrollRegion(
      'Combined Query Multiplexer and Data Host views',
      el(
        'table',
        { id: 'muse-combined-view-table', class: 'data' },
        el('caption', {}, 'Failure boundary — information unavailable to either server alone'),
        el('thead', {}, el('tr', {}, el('th', { scope: 'col', text: 'Response id' }), el('th', { scope: 'col', text: 'DH writer route' }), el('th', { scope: 'col', text: 'QM verdict' }))),
        el(
          'tbody',
          {},
          ...run.splitTrust.combinedViews.map((row) =>
            el(
              'tr',
              { 'data-writer': row.writerId, 'data-positive': String(row.positive) },
              el('th', { scope: 'row', class: 'mono', text: row.responseId }),
              el('td', { text: row.writerId }),
              el('td', { text: row.positive ? 'positive' : 'negative' }),
            ),
          ),
        ),
      ),
    ),
  );
}

function repeatRow(label: string, trace: MuseLessonRun['splitTrust']['first']): HTMLElement {
  const selector = trace.queryManager.messages.find((message) => message.writerId === 'writer-a');
  if (!selector) throw new Error('writer-a selector is missing');
  return el(
    'tr',
    { 'data-run': label },
    el('th', { scope: 'row', text: label }),
    hexCell(trace.queryManager.trapdoorHex),
    hexCell(selector.selectorDigestHex),
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

function hexCell(hex: string): HTMLTableCellElement {
  return el('td', { class: 'mono', title: hex, text: shortHex(hex, 14) });
}

function formatList(values: readonly string[]): string {
  return values.length === 0 ? 'none' : values.join(', ');
}

function resultRow(label: string, values: readonly string[]): HTMLTableRowElement {
  return el(
    'tr',
    { 'data-measure': label.toLowerCase().replaceAll(' ', '-') },
    el('th', { scope: 'row', text: label }),
    el('td', { text: formatList(values) }),
  );
}
