/**
 * Exhibit 7 — public-key encryption with keyword search (PEKS).
 *
 * The pairing implementation is dynamically imported only when the learner
 * asks to build the public-key tags. Search Vault's existing SSE first paint
 * therefore does not pay for BLS12-381.
 */
import { ctEqual, toHex } from '../core/bytes';
import type { PeksKeyPair, PeksTrapdoor } from '../peks/core';
import type { DictionaryAttackResult } from '../peks/dictionary';
import type { PeksSearchResult, PeksServer } from '../peks/server';
import { badge, clear, el, labelled, panel, scrollRegion, shortHex, verdict } from './dom';

const TAG_SPECS = [
  { opaqueRecordId: 'msg-7f2a', keyword: 'audit' },
  { opaqueRecordId: 'msg-19c4', keyword: 'merger' },
  { opaqueRecordId: 'msg-a831', keyword: 'audit' },
  { opaqueRecordId: 'msg-4de0', keyword: 'breach' },
  { opaqueRecordId: 'msg-c602', keyword: 'salary' },
  { opaqueRecordId: 'msg-35bb', keyword: 'audit' },
] as const;

type PeksKeyword = (typeof TAG_SPECS)[number]['keyword'];

interface PeksUiState {
  keyPair: PeksKeyPair;
  server: PeksServer;
  lastKeyword: PeksKeyword | null;
  exposedTrapdoor: PeksTrapdoor | null;
  lastSearch: PeksSearchResult | null;
}

export function renderPeks(): HTMLElement {
  const { section, body } = panel(
    'EXHIBIT 7',
    'Public-key search — and the trapdoor dictionary attack',
    'A sender now builds randomized searchable tags with only the recipient’s public key. The recipient issues a trapdoor, the server runs the public Test algorithm over every tag, and an attacker uses that same public interface to verify bounded keyword guesses offline.',
  );

  const buildBtn = el('button', { id: 'peks-build', class: 'primary', type: 'button' }, 'Generate key and build tags');
  const queryKeyword = el(
    'select',
    { id: 'peks-keyword' },
    ...uniqueKeywords().map((keyword) => el('option', { value: keyword, text: keyword })),
  ) as HTMLSelectElement;
  queryKeyword.value = 'audit';
  const queryBtn = el('button', { id: 'peks-query', type: 'button', disabled: true }, 'Issue trapdoor and search');
  const repeatBtn = el('button', { id: 'peks-repeat', type: 'button', disabled: true }, 'Repeat this query');

  const controls = el(
    'div',
    { class: 'controls' },
    buildBtn,
    labelled('Recipient keyword', queryKeyword),
    queryBtn,
    repeatBtn,
  );

  const buildStatus = el('div', {
    id: 'peks-build-status',
    role: 'status',
    'aria-live': 'polite',
    'aria-label': 'PEKS build status',
  });
  const roles = el('div', { id: 'peks-roles', class: 'peks-roles' });
  const queryResult = el('div', {
    id: 'peks-query-result',
    role: 'status',
    'aria-live': 'polite',
    'aria-label': 'PEKS query result',
  });
  const repeatResult = el('div', {
    id: 'peks-repeat-result',
    role: 'status',
    'aria-live': 'polite',
    'aria-label': 'PEKS repeat-query result',
  });
  const leakage = el('div', { id: 'peks-leakage' });

  const attackMode = el(
    'select',
    { id: 'peks-dictionary-mode' },
    el('option', { value: 'includes', text: 'Target included in candidate list' }),
    el('option', { value: 'excludes', text: 'Target absent from candidate list' }),
  ) as HTMLSelectElement;
  const attackBound = el(
    'select',
    { id: 'peks-dictionary-bound' },
    ...[0, 1, 2, 3, 4, 5, 6].map((n) => el('option', { value: n, text: `${n} guess${n === 1 ? '' : 'es'}` })),
  ) as HTMLSelectElement;
  attackBound.value = '6';
  const attackBtn = el('button', { id: 'peks-attack', class: 'primary', type: 'button', disabled: true }, 'Run bounded offline attack');
  const attackProgress = el('div', {
    id: 'peks-attack-progress',
    class: 'note',
    role: 'status',
    'aria-live': 'polite',
  });
  const attackResult = el('div', {
    id: 'peks-attack-result',
    role: 'status',
    'aria-live': 'polite',
    'aria-label': 'PEKS dictionary attack result',
  });

  body.append(
    constructionNotice(),
    controls,
    buildStatus,
    roles,
    queryResult,
    repeatResult,
    leakage,
    el('h3', { text: 'Offline guessing against the exposed trapdoor' }),
    el('p', {
      class: 'note',
      text:
        'Attacker input is limited to the recipient public key, the captured trapdoor, a candidate list, and a guess bound. For each candidate it creates a fresh legitimate PEKS tag and invokes public Test locally. It receives no recipient secret, target word, plaintext, or privileged server oracle.',
    }),
    el(
      'div',
      { class: 'controls' },
      labelled('Candidate list', attackMode),
      labelled('Maximum guesses', attackBound),
      attackBtn,
    ),
    attackProgress,
    attackResult,
    comparisonTable(),
    limitations(),
  );

  let state: PeksUiState | null = null;
  let operationSequence = 0;
  let activeOperation: {
    readonly token: number;
    readonly button: HTMLButtonElement;
    readonly idleText: string;
    readonly controller: AbortController;
  } | null = null;

  function restoreActiveOperation(abort: boolean): void {
    if (!activeOperation) return;
    if (abort) activeOperation.controller.abort();
    activeOperation.button.setAttribute('aria-busy', 'false');
    activeOperation.button.textContent = activeOperation.idleText;
    activeOperation = null;
  }

  function beginOperation(
    button: HTMLButtonElement,
    busyText: string,
    idleText: string,
  ): { readonly token: number; readonly signal: AbortSignal } {
    // Programmatic events can bypass disabled controls. Superseding the token
    // makes every completion from the retired operation a no-op.
    restoreActiveOperation(true);
    const token = ++operationSequence;
    const controller = new AbortController();
    activeOperation = { token, button, idleText, controller };
    button.setAttribute('aria-busy', 'true');
    button.textContent = busyText;
    syncControls();
    return { token, signal: controller.signal };
  }

  function operationIsCurrent(token: number, snapshot?: PeksUiState): boolean {
    return activeOperation?.token === token && (snapshot === undefined || state === snapshot);
  }

  function endOperation(token: number): void {
    if (activeOperation?.token !== token) return;
    restoreActiveOperation(false);
    syncControls();
  }

  function retireOperation(): void {
    operationSequence += 1;
    restoreActiveOperation(true);
  }

  function syncControls(): void {
    const busy = activeOperation !== null;
    const hasState = state !== null;
    const hasTrapdoor = state !== null && state.exposedTrapdoor !== null && state.lastKeyword !== null;
    buildBtn.disabled = busy;
    queryKeyword.disabled = busy;
    queryBtn.disabled = busy || !hasState;
    repeatBtn.disabled = busy || !hasTrapdoor;
    attackMode.disabled = busy || !hasTrapdoor;
    attackBound.disabled = busy || !hasTrapdoor;
    attackBtn.disabled = busy || !hasTrapdoor;
  }

  function resetQueryEvidence(): void {
    if (!state) return;
    retireOperation();
    state.lastKeyword = null;
    state.exposedTrapdoor = null;
    state.lastSearch = null;
    clear(queryResult);
    clear(repeatResult);
    clear(attackProgress);
    clear(attackResult);
    renderLeakage();
    syncControls();
  }

  async function build(): Promise<void> {
    // Retire all evidence tied to the previous key before the first await. A
    // rebuild must never leave an old trapdoor or attack result actionable
    // beside a new (or failed) key-generation attempt.
    state = null;
    const { token } = beginOperation(
      buildBtn,
      'Building real BLS12-381 tags…',
      'Generate fresh key and rebuild tags',
    );
    resetSlots(buildStatus, roles, queryResult, repeatResult, leakage, attackProgress, attackResult);
    try {
      const [{ generatePeksKeyPair, encryptKeyword }, { PeksServer }] = await Promise.all([
        import('../peks/core'),
        import('../peks/server'),
      ]);
      if (!operationIsCurrent(token)) return;
      const keyPair = generatePeksKeyPair();
      const senderRows = await Promise.all(
        TAG_SPECS.map(async (spec) => ({
          ...spec,
          tag: await encryptKeyword(keyPair.publicKey, spec.keyword),
        })),
      );
      if (!operationIsCurrent(token)) return;
      const server = new PeksServer(
        senderRows.map(({ opaqueRecordId, tag }) => ({ opaqueRecordId, tag })),
      );
      state = { keyPair, server, lastKeyword: null, exposedTrapdoor: null, lastSearch: null };

      const auditTags = senderRows.filter((row) => row.keyword === 'audit');
      const randomized = new Set(auditTags.map((row) => toHex(row.tag.a))).size === auditTags.length;
      buildStatus.append(
        verdict(
          'ok',
          '✓',
          'PUBLIC-KEY TAGS BUILT',
          `${senderRows.length} tags were computed with the recipient public key and real BLS12-381 pairings. In this run, the ${auditTags.length} tags for “audit” have ${randomized ? 'distinct' : 'at least one repeated'} A components. Every sender operation independently sampled fresh r; an A collision is possible but negligible.`,
        ),
      );
      roles.append(
        recipientCard(keyPair),
        senderCard(senderRows),
        serverCard(server),
      );
      renderLeakage();
    } catch (error) {
      if (!operationIsCurrent(token)) return;
      state = null;
      buildStatus.append(
        verdict('exposed', '✗', 'PEKS BUILD FAILED', errorMessage(error)),
      );
      renderLeakage();
    } finally {
      endOperation(token);
    }
  }

  async function search(repeated: boolean): Promise<void> {
    const snapshot = state;
    if (!snapshot) return;
    const keyword = queryKeyword.value as PeksKeyword;
    const previous = snapshot.exposedTrapdoor;
    snapshot.lastKeyword = null;
    snapshot.exposedTrapdoor = null;
    snapshot.lastSearch = null;
    clear(queryResult);
    clear(repeatResult);
    clear(attackProgress);
    clear(attackResult);
    const { token } = beginOperation(
      repeated ? repeatBtn : queryBtn,
      repeated ? 'Repeating query…' : 'Searching all tags…',
      repeated ? 'Repeat this query' : 'Issue trapdoor and search',
    );
    try {
      const { issueTrapdoor } = await import('../peks/core');
      if (!operationIsCurrent(token, snapshot)) return;
      const trapdoor = issueTrapdoor(snapshot.keyPair.secretKey, keyword);
      const result = await snapshot.server.search(trapdoor);
      if (!operationIsCurrent(token, snapshot)) return;
      snapshot.lastKeyword = keyword;
      snapshot.exposedTrapdoor = trapdoor;
      snapshot.lastSearch = result;

      renderSearchResult(keyword, trapdoor, result);
      if (repeated) {
        const equal = previous !== null && ctEqual(previous.bytes, trapdoor.bytes);
        repeatResult.append(
          verdict(
            equal ? 'warn' : 'exposed',
            equal ? '↻' : '✗',
            equal ? 'REPEAT LINKED BYTE-FOR-BYTE' : 'UNEXPECTED TRAPDOOR MISMATCH',
            equal
              ? `The independently issued trapdoor is identical across all ${trapdoor.bytes.length} bytes. The server can link this repeat without knowing the keyword.`
              : 'The same normalized keyword should produce the same trapdoor for this recipient.',
          ),
        );
      }
      renderLeakage();
    } catch (error) {
      if (!operationIsCurrent(token, snapshot)) return;
      queryResult.append(verdict('exposed', '✗', 'PEKS SEARCH FAILED', errorMessage(error)));
      renderLeakage();
    } finally {
      endOperation(token);
    }
  }

  function renderSearchResult(
    keyword: string,
    trapdoor: PeksTrapdoor,
    result: PeksSearchResult,
  ): void {
    clear(queryResult);
    queryResult.append(
      el('h3', { text: 'Recipient trapdoor → server Test' }),
      el(
        'div',
        { class: 'value-row' },
        el('span', { class: 'value-label', text: 'recipient keyword' }),
        el('span', { class: 'value-bytes', text: keyword }),
      ),
      el(
        'div',
        { class: 'value-row' },
        el('span', { class: 'value-label', text: 'trapdoor sent' }),
        el('span', {
          class: 'value-bytes is-token',
          title: toHex(trapdoor.bytes),
          text: `${trapdoor.bytes.length} bytes: ${shortHex(toHex(trapdoor.bytes), 18)}`,
        }),
      ),
      scrollRegion(
        'PEKS Test result for every stored tag',
        el(
          'table',
          { class: 'data', id: 'peks-test-table' },
          el('caption', {}, `${result.tests} public Test evaluations over ${result.tests} stored tags`),
          el(
            'thead',
            {},
            el('tr', {}, el('th', { scope: 'col', text: 'opaque record' }), el('th', { scope: 'col', text: 'Test result' })),
          ),
          el(
            'tbody',
            {},
            ...result.rows.map((row) =>
              el(
                'tr',
                {},
                el('td', { class: 'mono', text: row.opaqueRecordId }),
                el('td', {}, row.matched ? badge('warn', '●', 'MATCH') : badge('info', '○', 'no match')),
              ),
            ),
          ),
        ),
      ),
      verdict(
        'warn',
        '👁',
        'ANSWERED — AND OBSERVED',
        `Test evaluated all ${result.tests} tags and returned ${result.matchedRecordIds.length} opaque records: ${result.matchedRecordIds.join(', ') || 'none'}. That set is the access pattern; its size is volume leakage.`,
      ),
    );
  }

  function renderLeakage(): void {
    clear(leakage);
    leakage.append(
      el('h3', { text: 'Keep three passive leaks separate from active guessing' }),
      el(
        'div',
        { class: 'leakage-cards' },
        leakageCard('Search pattern', 'Equal trapdoor bytes link repeated queries for the same recipient and normalized keyword.'),
        leakageCard('Volume', 'The number of tags that pass Test reveals how many stored records match.'),
        leakageCard('Access pattern', 'The opaque record identifiers that pass Test reveal which records travel together.'),
        leakageCard('Keyword guessing', 'A separate active attack encrypts candidate words with the public key and tests the exposed trapdoor.'),
      ),
    );
    const observations = state?.server.observations() ?? [];
    if (observations.length === 0) {
      leakage.append(el('p', { class: 'note', text: 'No PEKS trapdoor has reached the server yet.' }));
      return;
    }
    leakage.append(
      scrollRegion(
        'PEKS server observation ledger',
        el(
          'table',
          { class: 'data', id: 'peks-ledger' },
          el('caption', {}, `${observations.length} recipient quer${observations.length === 1 ? 'y' : 'ies'} observed; no keyword column exists`),
          el(
            'thead',
            {},
            el(
              'tr',
              {},
              el('th', { scope: 'col', text: '#' }),
              el('th', { scope: 'col', text: 'trapdoor' }),
              el('th', { scope: 'col', text: 'Test calls' }),
              el('th', { scope: 'col', text: 'volume' }),
              el('th', { scope: 'col', text: 'access pattern' }),
            ),
          ),
          el(
            'tbody',
            {},
            ...observations.map((observation) =>
              el(
                'tr',
                {},
                el('td', { text: String(observation.seq + 1) }),
                el('td', {
                  class: 'mono',
                  title: observation.trapdoorHex,
                  text: shortHex(observation.trapdoorHex, 12),
                }),
                el('td', { text: String(observation.tests) }),
                el('td', { text: String(observation.resultSize) }),
                el('td', { class: 'mono', text: observation.matchedRecordIds.join(' ') || '—' }),
              ),
            ),
          ),
        ),
      ),
    );
  }

  async function attack(): Promise<void> {
    const snapshot = state;
    const exposedTrapdoor = snapshot?.exposedTrapdoor;
    const target = snapshot?.lastKeyword;
    if (!snapshot || !exposedTrapdoor || !target) return;
    const candidates = dictionaryFor(target, attackMode.value === 'includes');
    const maxGuesses = Number(attackBound.value);
    const { token, signal } = beginOperation(
      attackBtn,
      'Testing guesses…',
      'Run bounded offline attack',
    );
    clear(attackProgress);
    clear(attackResult);
    try {
      const { runBoundedDictionaryAttack } = await import('../peks/dictionary');
      if (!operationIsCurrent(token, snapshot) || snapshot.exposedTrapdoor !== exposedTrapdoor) return;
      const result = await runBoundedDictionaryAttack(
        {
          publicKey: snapshot.keyPair.publicKey,
          exposedTrapdoor,
          candidates,
          maxGuesses,
        },
        {
          signal,
          afterAttempt: async (attempt) => {
            if (!operationIsCurrent(token, snapshot) || snapshot.exposedTrapdoor !== exposedTrapdoor) return;
            attackProgress.textContent = `Tested ${attempt.candidate}: ${attempt.matched ? 'match' : 'no match'}.`;
            await nextFrame();
          },
        },
      );
      if (!operationIsCurrent(token, snapshot) || snapshot.exposedTrapdoor !== exposedTrapdoor) return;
      renderAttackResult(result);
    } catch (error) {
      if (!operationIsCurrent(token, snapshot) || snapshot.exposedTrapdoor !== exposedTrapdoor) return;
      attackResult.append(verdict('exposed', '✗', 'ATTACK RUN FAILED', errorMessage(error)));
    } finally {
      endOperation(token);
    }
  }

  function renderAttackResult(result: DictionaryAttackResult): void {
    clear(attackResult);
    if (result.status === 'recovered') {
      attackResult.append(
        verdict(
          'exposed',
          '⚠',
          `KEYWORD RECOVERED: “${result.recoveredKeyword}”`,
          `The first passing public Test was guess ${result.attempts.length}, within the bound of ${result.bound}. The recipient private key and message bodies were not recovered.`,
        ),
      );
    } else {
      attackResult.append(
        verdict(
          'info',
          'ℹ',
          'NOT RECOVERED WITHIN THIS BOUND',
          `${result.attempts.length} of at most ${result.bound} guesses were tested. This does not establish security: the target may be absent from the candidate list or beyond the chosen bound.`,
        ),
      );
    }
    if (result.attempts.length === 0) return;
    attackResult.append(
      scrollRegion(
        'Bounded PEKS dictionary attempts',
        el(
          'table',
          { class: 'data', id: 'peks-dictionary-table' },
          el('caption', {}, `${result.attempts.length} fresh public-key tags constructed and tested locally`),
          el(
            'thead',
            {},
            el(
              'tr',
              {},
              el('th', { scope: 'col', text: 'guess' }),
              el('th', { scope: 'col', text: 'fresh tag A' }),
              el('th', { scope: 'col', text: 'public Test' }),
            ),
          ),
          el(
            'tbody',
            {},
            ...result.attempts.map((attempt) =>
              el(
                'tr',
                {},
                el('td', { text: attempt.candidate }),
                el('td', { class: 'mono', title: toHex(attempt.tag.a), text: shortHex(toHex(attempt.tag.a), 12) }),
                el('td', {}, attempt.matched ? badge('alarm', '⚠', 'PASS — recovered') : badge('ok', '✓', 'FAIL')),
              ),
            ),
          ),
        ),
      ),
    );
  }

  buildBtn.addEventListener('click', () => void build());
  queryBtn.addEventListener('click', () => void search(false));
  repeatBtn.addEventListener('click', () => void search(true));
  attackBtn.addEventListener('click', () => void attack());
  queryKeyword.addEventListener('change', resetQueryEvidence);
  attackMode.addEventListener('change', () => {
    retireOperation();
    clear(attackProgress);
    clear(attackResult);
    syncControls();
  });
  attackBound.addEventListener('change', () => {
    retireOperation();
    clear(attackProgress);
    clear(attackResult);
    syncControls();
  });

  buildStatus.append(
    verdict(
      'info',
      'ℹ',
      'NOT BUILT YET',
      'Generate a recipient key before issuing a trapdoor. The BLS12-381 module loads only when you start this exhibit.',
    ),
  );
  renderLeakage();
  syncControls();
  return section;
}

function constructionNotice(): HTMLElement {
  return el(
    'details',
    { id: 'peks-construction' },
    el('summary', { text: 'Construction, correctness equation, and proof boundary' }),
    el(
      'p',
      {},
      'Recipient key: ',
      el('code', { text: 'X = xP₂' }),
      '. Sender tag for keyword w: ',
      el('code', { text: 'A = rP₂, B = H₂(e(H₁(w), rX)) = H₂(e(H₁(w), X)ʳ)' }),
      '. Recipient trapdoor: ',
      el('code', { text: 'T_w = xH₁(w)' }),
      '. Server Test checks ',
      el('code', { text: 'B = H₂(e(T_w, A))' }),
      '.',
    ),
    el('p', {
      class: 'note',
      text:
        'This is an algebra-preserving Type-3 BLS12-381 adaptation of Boneh–Di Crescenzo–Ostrovsky–Persiano (2004): H₁(w) and T_w are in G₁; X and A are in G₂. Bilinearity proves this implementation’s equality. The original paper’s symmetric-pairing BDH security reduction does not automatically transfer; this lab supplies no formal reduction for the adaptation and makes no such claim.',
    }),
    el(
      'p',
      { class: 'note' },
      'H₁ uses RFC 9380 hash-to-curve with a PEKS-specific domain. H₂ is SHA-256 over a domain-separated, length-framed 576-byte noble Fp12 coefficient encoding. That representation is library-defined, not a standardized GT wire format; the current ',
      el('a', { href: 'https://datatracker.ietf.org/doc/draft-irtf-cfrg-pairing-friendly-curves/' }, 'pairing-friendly-curves draft'),
      ' defines no GT encoding. See the ',
      el('a', { href: 'https://web.cs.ucla.edu/~rafail/PUBLIC/61.pdf' }, 'original PEKS paper'),
      ', ',
      el('a', { href: 'https://www.rfc-editor.org/rfc/rfc9380.html' }, 'RFC 9380'),
      ', and the executable pairing background in ',
      el('a', { href: 'https://systemslibrarian.github.io/crypto-lab-ibe-gate/' }, 'IBE Gate'),
      ' and ',
      el('a', { href: 'https://systemslibrarian.github.io/crypto-lab-pairing-gate/' }, 'Pairing Gate'),
      '.',
    ),
  );
}

function recipientCard(keyPair: PeksKeyPair): HTMLElement {
  const publicHex = toHex(keyPair.publicKey.bytes);
  return el(
    'div',
    { class: 'side side-client role-card' },
    el('p', { class: 'side-title', text: 'Recipient' }),
    el('p', { class: 'side-note', text: 'Generates x and publishes X = xP₂.' }),
    el('div', { class: 'value-row' }, el('span', { class: 'value-label', text: 'public X' }), el('span', { class: 'value-bytes', title: publicHex, text: `${keyPair.publicKey.bytes.length} bytes: ${shortHex(publicHex, 14)}` })),
    el('div', { class: 'value-row' }, el('span', { class: 'value-label', text: 'secret x' }), el('span', { class: 'value-bytes', text: 'held here; never rendered or sent' })),
  );
}

function senderCard(
  rows: ReadonlyArray<{ readonly opaqueRecordId: string; readonly keyword: string; readonly tag: { readonly a: Uint8Array; readonly b: Uint8Array } }>,
): HTMLElement {
  return el(
    'div',
    { class: 'side side-client role-card' },
    el('p', { class: 'side-title', text: 'Public sender' }),
    el('p', { class: 'side-note', text: 'Input: public X + keyword only. Samples fresh r for every tag.' }),
    scrollRegion(
      'Sender-side PEKS tag evidence',
      el(
        'table',
        { class: 'data', id: 'peks-sender-table' },
        el('caption', {}, 'The sender knows each keyword while constructing its tag'),
        el('thead', {}, el('tr', {}, el('th', { scope: 'col', text: 'record' }), el('th', { scope: 'col', text: 'keyword' }), el('th', { scope: 'col', text: 'A / B' }))),
        el(
          'tbody',
          {},
          ...rows.map((row) =>
            el(
              'tr',
              {},
              el('td', { class: 'mono', text: row.opaqueRecordId }),
              el('td', { text: row.keyword }),
              el('td', { class: 'mono', title: `${toHex(row.tag.a)} ${toHex(row.tag.b)}`, text: `${shortHex(toHex(row.tag.a), 6)} / ${shortHex(toHex(row.tag.b), 6)}` }),
            ),
          ),
        ),
      ),
    ),
  );
}

function serverCard(server: PeksServer): HTMLElement {
  const records = server.records();
  return el(
    'div',
    { class: 'side side-server role-card' },
    el('p', { class: 'side-title', text: 'Search server' }),
    el('p', { class: 'side-note', text: 'Stores only opaque record id plus (A, B). No keyword or body.' }),
    scrollRegion(
      'PEKS records stored by the server',
      el(
        'table',
        { class: 'data', id: 'peks-server-table' },
        el('caption', {}, `${records.length} randomized tags; zero keyword fields`),
        el('thead', {}, el('tr', {}, el('th', { scope: 'col', text: 'opaque record' }), el('th', { scope: 'col', text: 'A' }), el('th', { scope: 'col', text: 'B' }))),
        el(
          'tbody',
          {},
          ...records.map((record) =>
            el(
              'tr',
              {},
              el('td', { class: 'mono', text: record.opaqueRecordId }),
              el('td', { class: 'mono', title: toHex(record.tag.a), text: shortHex(toHex(record.tag.a), 6) }),
              el('td', { class: 'mono', title: toHex(record.tag.b), text: shortHex(toHex(record.tag.b), 6) }),
            ),
          ),
        ),
      ),
    ),
  );
}

function comparisonTable(): HTMLElement {
  const rows: Array<[string, string, string]> = [
    ['Who can create searchable data?', 'A client holding symmetric index keys.', 'Any sender holding recipient public key X.'],
    ['Who creates a query value?', 'The symmetric-key client computes HMAC token t_w.', 'The recipient computes trapdoor T_w with secret x.'],
    ['Server work here', 'Counter-address lookup: proportional to matches plus final miss.', 'Basic PEKS scan: public Test over every stored tag.'],
    ['Before a query', 'Deterministic index layout is hidden behind secret PRFs.', 'Fresh r randomizes equal-keyword tags; an encoding collision is negligible, not impossible.'],
    ['After a query', 'Token repeats, volume, and matching record ids are visible.', 'Trapdoor repeats, volume, and matching record ids are visible.'],
    ['Guess verification', 'A guessed word cannot reproduce HMAC token without the key.', 'Public encryption + public Test verifies guesses against an exposed trapdoor.'],
  ];
  return el(
    'div',
    {},
    el('h3', { text: 'SSE and PEKS separate the roles differently' }),
    scrollRegion(
      'SSE and PEKS role and leakage comparison',
      el(
        'table',
        { class: 'data', id: 'peks-comparison' },
        el('thead', {}, el('tr', {}, el('th', { scope: 'col', text: '' }), el('th', { scope: 'col', text: 'This lab’s SSE' }), el('th', { scope: 'col', text: 'This PEKS exhibit' }))),
        el('tbody', {}, ...rows.map(([label, sse, peks]) => el('tr', {}, el('th', { scope: 'row', text: label }), el('td', { text: sse }), el('td', { text: peks })))),
      ),
    ),
  );
}

function limitations(): HTMLElement {
  return el(
    'div',
    {},
    el('h3', { text: 'What this PEKS exhibit does not establish' }),
    el(
      'ul',
      { class: 'nongoals' },
      el('li', {}, 'A PEKS tag is not message-body encryption. A deployment must encrypt the body separately.'),
      el('li', {}, 'Recipient, public sender, and server are co-located objects in this one browser tab. The role split is real in code, but there is no network or production process isolation.'),
      el('li', {}, 'Once a trapdoor is issued, the server can retain it and Test both existing and future tags for that keyword.'),
      el('li', {}, 'Public tag creation provides no sender authentication, no proof that a tagged word occurs in a body, and no binding between tag and body.'),
      el('li', {}, 'Test does not prove result completeness or freshness. Exhibit 2’s client-retained SSE checkpoint does not transfer automatically.'),
      el('li', {}, 'A secure channel can prevent an outside eavesdropper from capturing a trapdoor; it cannot stop the search server that receives that trapdoor from guessing.'),
      el('li', {}, 'The construction is computationally rather than perfectly consistent: a hash collision could create a false positive, although SHA-256 makes that negligible here.'),
      el('li', {}, 'The current IRTF pairing-friendly-curves Internet-Draft estimates BLS12-381 near 126-bit security and remains a work in progress. No exact 128-bit claim is made.'),
      el('li', {}, 'This TypeScript/noble browser exercise does not claim hardened constant-time or side-channel-resistant execution. Its digest comparison scans all fixed-length bytes, but the JavaScript runtime offers no hard timing guarantee.'),
      el('li', {}, 'No claim is made for chosen-ciphertext security, sender authentication, conjunctive/fuzzy/dynamic/multi-user search, distribution hiding, or post-quantum security.'),
    ),
    el(
      'p',
      { class: 'honesty' },
      'The bounded dictionary result concerns one exposed trapdoor and one declared candidate list. Success recovers the query word, not x or the message body. Failure means only “not recovered within this bound.” See ',
      el('a', { href: 'https://doi.org/10.1007/11844662_6' }, 'Byun et al. (2006)'),
      ' and the explicit public-PEKS-then-Test attack in ',
      el('a', { href: 'https://www.jstage.jst.go.jp/article/elex/6/5/6_5_237/_pdf' }, 'Rhee, Susilo, and Kim (2009)'),
      ', and the security estimate in the ',
      el('a', { href: 'https://datatracker.ietf.org/doc/draft-irtf-cfrg-pairing-friendly-curves/' }, 'current IRTF draft'),
      '.',
    ),
  );
}

function leakageCard(title: string, text: string): HTMLElement {
  return el('div', { class: 'score-block' }, el('div', { class: 'score-label', text: title }), el('div', { class: 'note', text }));
}

function uniqueKeywords(): PeksKeyword[] {
  return [...new Set(TAG_SPECS.map((spec) => spec.keyword))];
}

function dictionaryFor(target: string, includeTarget: boolean): string[] {
  const distractors = ['budget', 'contract', 'lawsuit', 'bonus', 'patent', 'invoice'].filter(
    (candidate) => candidate !== target,
  );
  return includeTarget
    ? [distractors[0]!, distractors[1]!, target, distractors[2]!, distractors[3]!, distractors[4]!]
    : distractors;
}

function resetSlots(...nodes: HTMLElement[]): void {
  for (const node of nodes) clear(node);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function nextFrame(): Promise<void> {
  return new Promise((resolve) => requestAnimationFrame(() => resolve()));
}
