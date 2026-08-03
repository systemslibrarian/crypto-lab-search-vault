/**
 * Functional coverage for the claims Search Vault makes on screen.
 *
 * The a11y suite drives every exhibit but never reads what it says. These tests
 * assert the load-bearing numbers instead, and — wherever possible — assert
 * them against each other rather than against a constant baked into the test:
 * the build stepper's per-keyword row counts must sum to the store's own total,
 * the search verdict's document set must be the set the server logged, the
 * attack's headline must be the tally of its own per-token table, and the
 * measured latency must be the measured total over the measured run count.
 * A hardcoded expectation would still pass if the page computed nonsense
 * consistently; these do not.
 */
import { expect, test, type Locator, type Page } from '@playwright/test';

const TOTAL_DOCS = 24;
const KEYWORD_COUNT = 14;

const pageErrors = new WeakMap<Page, string[]>();

test.beforeEach(async ({ page }) => {
  const errors: string[] = [];
  pageErrors.set(page, errors);
  page.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`));
  await page.goto('.');
  await expect(page.locator('#build-status')).toBeVisible();
});

test.afterEach(async ({ page }) => {
  // An exhibit that throws mid-render leaves a half-drawn panel that still
  // satisfies most assertions, so uncaught exceptions have to fail loudly.
  expect(pageErrors.get(page) ?? []).toEqual([]);
});

/** The `<section class="panel">` containing a given anchor element. */
function exhibit(page: Page, anchor: string): Locator {
  return page.locator('section.panel').filter({ has: page.locator(anchor) });
}

/** The `.value-bytes` beside a labelled `.value-row`. */
function value(scope: Locator, label: string): Locator {
  return scope.locator(`.value-row:has(.value-label:text-is("${label}"))`).locator('.value-bytes');
}

async function text(locator: Locator): Promise<string> {
  return (await locator.innerText()).replace(/\s+/g, ' ').trim();
}

/** Pull the first capture group, failing with the haystack if it is absent. */
function capture(haystack: string, re: RegExp, what: string): string {
  const m = haystack.match(re);
  expect(m, `${what} not found in: ${haystack}`).not.toBeNull();
  return m![1]!;
}

function num(haystack: string, re: RegExp, what: string): number {
  return Number(capture(haystack, re, what));
}

// ---------------------------------------------------------------------------
// Exhibit 1 — the encrypted index build
// ---------------------------------------------------------------------------

test('exhibit 1: every keyword indexes to its own row count, and the 14 parts sum to the store', async ({
  page,
}) => {
  const ex = exhibit(page, '#build-status');
  const keywords = await page.locator('#build-keyword option').evaluateAll((os) =>
    os.map((o) => (o as HTMLOptionElement).value),
  );
  expect(keywords).toHaveLength(KEYWORD_COUNT);

  let sum = 0;
  for (const keyword of keywords) {
    await page.locator('#build-keyword').selectOption(keyword);
    await page.locator('#build-all').click();

    const verdict = await text(page.locator('#build-verdict'));
    expect(verdict).toContain('INDEXED');
    const rows = num(verdict, /is now (\d+) rows/, `row count for "${keyword}"`);
    expect(rows).toBeGreaterThan(0);

    // Three independent renderings of the same number, plus the actual DOM.
    expect(verdict).toContain(`"${keyword}" is now ${rows} rows`);
    expect(await text(page.locator('#build-status'))).toBe(
      `Done: "${keyword}" is indexed as ${rows} rows.`,
    );
    expect(await text(ex.locator('.side-server caption'))).toBe(`${rows} of ${rows} rows stored`);
    await expect(ex.locator('.side-server tbody tr')).toHaveCount(rows);

    sum += rows;
  }

  await page.locator('#build-full-index').evaluate((d) => ((d as HTMLDetailsElement).open = true));
  const caption = await text(page.locator('#build-full-index caption'));
  const stored = num(caption, /^(\d+) rows across/, 'total stored rows');
  expect(caption).toBe(`${stored} rows across ${KEYWORD_COUNT} keywords and ${TOTAL_DOCS} documents`);

  // The whole is the sum of the parts: one posting per keyword-document pair.
  expect(sum).toBe(stored);
  await expect(page.locator('#build-full-index tbody tr')).toHaveCount(stored);
});

test('exhibit 1: a row reaches the server only after its sealed value is derived', async ({
  page,
}) => {
  const ex = exhibit(page, '#build-status');
  await page.locator('#build-keyword').selectOption('breach');

  const postings = num(
    await text(ex.locator('.side-server caption')),
    /of (\d+) rows stored/,
    'posting count',
  );
  const steps = 3 + postings * 2;

  // No verdict before the build finishes — the page must not claim INDEXED
  // while postings are still pending.
  await expect(page.locator('#build-verdict')).toBeEmpty();
  expect(await text(page.locator('#build-status'))).toBe(
    `Ready to index "breach" — ${postings} documents contain it.`,
  );

  for (let i = 0; i < 3; i++) await page.locator('#build-step').click();
  expect(await text(page.locator('#build-status'))).toBe(`Step 3 of ${steps}.`);
  expect(await text(ex.locator('.side-server caption'))).toBe(`0 of ${postings} rows stored`);
  await expect(ex.locator('.side-server tbody')).toContainText('nothing stored yet');
  await expect(page.locator('#build-verdict')).toBeEmpty();

  // The address alone is not a stored row: the sealed value is still pending.
  await page.locator('#build-step').click();
  expect(await text(ex.locator('.side-server caption'))).toBe(`0 of ${postings} rows stored`);
  await expect(ex.locator('.side-client .value-row.is-pending')).toHaveCount(1);

  await page.locator('#build-step').click();
  expect(await text(ex.locator('.side-server caption'))).toBe(`1 of ${postings} rows stored`);
  await expect(ex.locator('.side-client .value-row.is-pending')).toHaveCount(0);
  await expect(ex.locator('.side-server tbody tr')).toHaveCount(1);

  await page.locator('#build-all').click();
  await expect(page.locator('#build-verdict')).toContainText('INDEXED');
  await expect(ex.locator('.side-server tbody tr')).toHaveCount(postings);
  // Finished means finished: both drivers disable.
  await expect(page.locator('#build-step')).toBeDisabled();
  await expect(page.locator('#build-all')).toBeDisabled();
});

// ---------------------------------------------------------------------------
// Exhibit 2 — search, and what the server writes down
// ---------------------------------------------------------------------------

test('exhibit 2: the verdict, the client results, the access pattern and the ledger name one set', async ({
  page,
}) => {
  const ex = exhibit(page, '#search-outcome');
  await page.locator('#search-input').fill('breach');
  await page.locator('#search-run').click();

  const outcome = page.locator('#search-outcome');
  await expect(outcome).toContainText('ANSWERED — AND OBSERVED');
  const verdict = await text(outcome);

  const claimed = num(verdict, /the right (\d+) documents/, 'claimed result size');
  const claimedIds = capture(verdict, /matches exactly \{([^}]+)\}/, 'claimed document set')
    .split(',')
    .map((s) => s.trim());
  expect(claimedIds).toHaveLength(claimed);
  expect(verdict).toContain('without learning "breach"');

  // What the client decrypted.
  const decrypted = await ex
    .locator('.side-client ul li .mono')
    .evaluateAll((ns) => ns.map((n) => n.textContent!.trim()));
  expect(decrypted).toEqual(claimedIds);
  await expect(ex.locator('.side-client')).toContainText('every posting authenticated under AES-GCM');

  // What the server observed — the access pattern it had to be handed.
  expect(await text(value(ex.locator('.side-server'), 'result size'))).toBe(`${claimed} documents`);
  expect(await text(value(ex.locator('.side-server'), 'documents sent'))).toBe(claimedIds.join(', '));
  expect(await text(value(ex.locator('.side-server'), 'keyword'))).toBe(
    'unknown — no key, nothing to invert',
  );

  // The address walk stops on the first miss: one probe per posting, plus one.
  const probes = await text(value(ex.locator('.side-server'), 'probes'));
  expect(probes.match(/addr_\d+=/g)).toHaveLength(claimed + 1);
  expect(probes).toContain(`addr_${claimed}=`);
  expect(probes).toContain('(miss → stop)');

  // And what went into the ledger.
  expect(await text(page.locator('#search-ledger h3'))).toBe('The server’s log — 1 queries observed');
  const row = page.locator('#search-ledger tbody tr');
  await expect(row).toHaveCount(1);
  expect(await text(row.locator('td').nth(2))).toBe(String(claimed));
  expect(await text(row.locator('td').nth(3))).toBe(claimedIds.join(' '));
});

test('exhibit 2: a keyword outside the index reaches the miss path and names the keyword', async ({
  page,
}) => {
  const ex = exhibit(page, '#search-outcome');
  await page.locator('#search-input').fill('unicorn');
  await page.locator('#search-run').click();

  const outcome = page.locator('#search-outcome');
  await expect(outcome).toContainText('NO MATCH');
  const verdict = await text(outcome);
  expect(verdict).toContain('"unicorn" is not one of the 14 indexed keywords');
  expect(verdict).toContain('the server returned nothing');

  // The failure state is reflected on both sides, not just in the headline.
  await expect(ex.locator('.side-client h4')).toHaveText('No results');
  await expect(ex.locator('.side-client')).toContainText(
    'it cannot tell an absent keyword from a wrong key',
  );
  await expect(ex.locator('.side-client')).not.toContainText('authenticated under AES-GCM');
  expect(await text(value(ex.locator('.side-server'), 'result size'))).toBe('0 documents');
  expect(await text(value(ex.locator('.side-server'), 'documents sent'))).toBe('—');
  // A miss is still a probe the server saw: addr_0 alone, and it missed.
  const probes = await text(value(ex.locator('.side-server'), 'probes'));
  expect(probes.match(/addr_\d+=/g)).toHaveLength(1);
  expect(probes).toContain('(miss → stop)');

  // The zero-result query is logged: the server learned that much.
  expect(await text(page.locator('#search-ledger h3'))).toBe('The server’s log — 1 queries observed');
  const row = page.locator('#search-ledger tbody tr');
  expect(await text(row.locator('td').nth(2))).toBe('0');
  expect(await text(row.locator('td').nth(3))).toBe('—');
});

test('exhibit 2: an empty query is refused and never reaches the server', async ({ page }) => {
  await page.locator('#search-input').fill('   ');
  await page.locator('#search-run').click();

  await expect(page.locator('#search-outcome')).toContainText('NOTHING TO SEARCH');
  expect(await text(page.locator('#search-outcome'))).toContain('Type a keyword');
  expect(await text(page.locator('#search-ledger h3'))).toBe('The server’s log — 0 queries observed');
  await expect(page.locator('#search-ledger')).toContainText('No queries observed yet.');
});

test('exhibit 2: clearing the log empties it and retires every verdict drawn from it', async ({
  page,
}) => {
  // Regression: clearing the server's log used to leave Exhibit 4's
  // "N OF M QUERIES RECONSTRUCTED" and Exhibit 5's scoreboard on screen,
  // asserting a recovery against a ledger the page no longer had — beside a
  // challenge board that had already fallen back to "nothing to work with yet".
  await page.locator('#search-run-all').click();
  await page.locator('#attack-run').click();
  await expect(page.locator('#attack-result')).toContainText('QUERIES RECONSTRUCTED');
  await page.locator('#challenge-machine').click();
  await expect(page.locator('#challenge-outcome')).toContainText('IKK attack');

  await page.locator('#search-clear').click();

  expect(await text(page.locator('#search-ledger h3'))).toBe('The server’s log — 0 queries observed');
  await expect(page.locator('#search-ledger')).toContainText('No queries observed yet.');
  await expect(page.locator('#search-ledger tbody tr')).toHaveCount(0);
  await expect(page.locator('#leak-summary')).toContainText('NOT ENOUGH OBSERVED YET');
  await expect(page.locator('#challenge-board')).toContainText('Nothing to work with yet');

  await expect(page.locator('#attack-result')).not.toContainText('QUERIES RECONSTRUCTED');
  await expect(page.locator('#attack-result table')).toHaveCount(0);
  await expect(page.locator('#attack-result')).toContainText('Press “Run the attack”');
  await expect(page.locator('#challenge-outcome')).toBeEmpty();

  // And the attack now refuses, naming what it lacks.
  await page.locator('#attack-run').click();
  await expect(page.locator('#attack-result')).toContainText('NOTHING TO ATTACK YET');
  expect(await text(page.locator('#attack-result'))).toContain('needs observed queries');
});

// ---------------------------------------------------------------------------
// Exhibit 3 — the leakage profile
// ---------------------------------------------------------------------------

test('exhibit 3: the exposure headline is the page’s own touched/total, and the charts agree', async ({
  page,
}) => {
  await expect(page.locator('#leak-summary')).toContainText('NOT ENOUGH OBSERVED YET');
  await page.locator('#leak-run-all').click();
  await expect(page.locator('#leak-summary')).toContainText('OF THE DATABASE HAS BEEN IN SOME RESULT SET');

  const summary = await text(page.locator('#leak-summary'));
  const pct = num(summary, /(\d+)% OF THE DATABASE/, 'exposure percentage');
  const queries = num(summary, /(\d+) queries,/, 'query count');
  const tokens = num(summary, /(\d+) distinct tokens/, 'distinct token count');
  const touched = num(summary, /(\d+) of \d+ documents named/, 'touched document count');
  const total = num(summary, /\d+ of (\d+) documents named/, 'corpus size');

  expect(total).toBe(TOTAL_DOCS);
  expect(pct).toBe(Math.round((touched / total) * 100));
  expect(touched).toBeLessThanOrEqual(total);

  // The ledger the summary describes is the ledger on screen.
  expect(await text(page.locator('#search-ledger h3'))).toBe(
    `The server’s log — ${queries} queries observed`,
  );
  await expect(page.locator('#search-ledger tbody tr')).toHaveCount(queries);

  // Search pattern: one histogram bar per distinct token, and the per-token
  // query counts partition the total number of queries.
  const bars = page.locator('.histogram li');
  await expect(bars).toHaveCount(tokens);
  const counts = await bars
    .locator('.bar-value')
    .evaluateAll((ns) => ns.map((n) => Number(n.textContent!.match(/(\d+)×/)![1])));
  expect(counts.reduce((a, b) => a + b, 0)).toBe(queries);

  // Access pattern: the graph's own label must match the numbers table under it.
  const graphLabel = await page.locator('.graph-wrap svg').getAttribute('aria-label');
  expect(num(graphLabel!, /: (\d+) observed tokens/, 'graph node count')).toBe(tokens);
  const pairs = num(graphLabel!, /(\d+) pairs whose result sets intersect/, 'graph edge count');
  await expect(page.locator('.graph-wrap svg circle.graph-node')).toHaveCount(tokens);
  await expect(page.locator('.graph-wrap svg line.graph-edge')).toHaveCount(pairs);
  const numbersTable = exhibit(page, '#leak-summary').locator('details table.data tbody tr');
  await expect(numbersTable).toHaveCount(pairs);

  // Document co-occurrence: one row per document that has been named.
  const matrix = exhibit(page, '#leak-summary').locator('table.matrix tbody tr');
  await expect(matrix).toHaveCount(touched);
});

// ---------------------------------------------------------------------------
// Exhibit 4 — the leakage-abuse attack
// ---------------------------------------------------------------------------

/** Parse the attack headline and cross-check it against its own results table. */
async function readAttack(page: Page): Promise<{
  correct: number;
  total: number;
  pct: number;
  pinned: number;
}> {
  const summary = await text(page.locator('#attack-result .verdict'));
  const correct = num(summary, /^(?:\S+ )?(\d+) OF \d+ QUERIES RECONSTRUCTED/, 'recovered count');
  const total = num(summary, /\d+ OF (\d+) QUERIES RECONSTRUCTED/, 'token count');
  const pct = num(summary, /RECONSTRUCTED \((\d+)%\)/, 'recovery percentage');
  const pinned = num(summary, /(\d+) identified by result size alone/, 'count-attack tally');

  expect(pct).toBe(Math.round((correct / total) * 100));

  const rows = page.locator('#attack-result tbody tr');
  await expect(rows).toHaveCount(total);

  const outcomes = await rows
    .locator('td:nth-child(6)')
    .evaluateAll((ns) => ns.map((n) => n.textContent!.trim()));
  const recovered = outcomes.filter((o) => o.includes('— recovered'));
  const held = outcomes.filter((o) => o.includes('— held'));
  // Every token is one or the other, and the headline counts the recovered ones.
  expect(recovered.length + held.length).toBe(total);
  expect(recovered).toHaveLength(correct);

  const methods = await rows
    .locator('td:nth-child(3)')
    .evaluateAll((ns) => ns.map((n) => n.textContent!.trim()));
  expect(methods.filter((m) => m === 'result size')).toHaveLength(pinned);
  expect(methods.every((m) => m === 'result size' || m === 'co-occurrence')).toBe(true);

  return { correct, total, pct, pinned };
}

test('exhibit 4: the headline recovery is the tally of the attack’s own per-token table', async ({
  page,
}) => {
  await page.locator('#attack-observe').click();
  await expect(page.locator('#attack-result table')).toBeVisible();

  const { correct, total, pct } = await readAttack(page);

  // The README's headline claim: with exact background statistics, every query
  // falls. Asserted against the table the page drew, not a constant.
  expect(total).toBe(KEYWORD_COUNT);
  expect(correct).toBe(total);
  expect(pct).toBe(100);

  // The attack's input is the log, and it says how many tokens it started from.
  expect(await text(page.locator('#attack-result .verdict'))).toContain(
    `started from ${total} candidate-compatible opaque tokens`,
  );
  await expect(page.locator('#attack-matrix-details summary')).toContainText(
    `a ${total}×${total} table of token overlaps`,
  );
});

test('exhibit 4: degrading the adversary’s background knowledge degrades recovery', async ({
  page,
}) => {
  await expect(page.locator('#attack-noise-value')).toHaveText('exact');
  await page.locator('#attack-observe').click();
  await expect(page.locator('#attack-result table')).toBeVisible();
  const exact = await readAttack(page);

  await page.locator('#attack-noise').fill('150');
  await page.locator('#attack-noise').dispatchEvent('input');
  await expect(page.locator('#attack-noise-value')).toHaveText('±150%');
  await page.locator('#attack-run').click();
  await expect(page.locator('#attack-result table')).toBeVisible();
  const noisy = await readAttack(page);

  expect(noisy.total).toBe(exact.total);
  expect(noisy.correct).toBeLessThanOrEqual(exact.correct);
});

test('exhibit 4: a zero-result token is excluded, and the exclusion is stated', async ({ page }) => {
  await page.locator('#search-input').fill('unicorn');
  await page.locator('#search-run').click();
  await expect(page.locator('#search-outcome')).toContainText('NO MATCH');
  await page.locator('#attack-observe').click();
  await expect(page.locator('#attack-result table')).toBeVisible();

  const { total } = await readAttack(page);
  const summary = await text(page.locator('#attack-result .verdict'));
  expect(summary).toContain(
    'It excluded 1 zero-result token because no candidate keyword has zero results.',
  );
  // The log has one more distinct token than the attack considered.
  const leak = await text(page.locator('#leak-summary'));
  expect(num(leak, /(\d+) distinct tokens/, 'distinct token count')).toBe(total + 1);
});

// ---------------------------------------------------------------------------
// Exhibit 5 — the learner plays the server
// ---------------------------------------------------------------------------

test('exhibit 5: the score counts exactly the rows it marked, and a wrong guess names the truth', async ({
  page,
}) => {
  // Take ground truth from Exhibit 4's scoring column — the page's own answer
  // key — so the guesses below are known-right and known-wrong by construction.
  await page.locator('#attack-observe').click();
  await expect(page.locator('#attack-result table')).toBeVisible();
  const truth = new Map<string, string>(
    await page.locator('#attack-result tbody tr').evaluateAll((rows) =>
      rows.map((r) => {
        const tds = r.querySelectorAll('td');
        return [
          tds[0]!.textContent!.trim(),
          tds[5]!.textContent!.trim().replace(/^\W+\s*/, '').replace(/ — (recovered|held)$/, ''),
        ] as [string, string];
      }),
    ),
  );

  const rows = page.locator('#challenge-board tbody tr');
  const boardSize = await rows.count();
  expect(boardSize).toBe(KEYWORD_COUNT);

  const labels = await rows
    .locator('td:nth-child(1)')
    .evaluateAll((ns) => ns.map((n) => n.textContent!.trim()));
  expect(new Set(labels)).toEqual(new Set(truth.keys()));

  const rightIdx = [0, 1, 2];
  const wrongIdx = [3, 4];
  for (const i of rightIdx) {
    await rows.nth(i).locator('select').selectOption(truth.get(labels[i]!)!);
  }
  for (const i of wrongIdx) {
    const actual = truth.get(labels[i]!)!;
    const options = await rows.nth(i).locator('select option').evaluateAll((os) =>
      os.map((o) => (o as HTMLOptionElement).value).filter(Boolean),
    );
    await rows.nth(i).locator('select').selectOption(options.find((o) => o !== actual)!);
  }

  await page.locator('#challenge-check').click();
  const outcome = await text(page.locator('#challenge-outcome'));
  const correct = num(outcome, /YOU RECOVERED (\d+) OF \d+/, 'correct count');
  const of = num(outcome, /YOU RECOVERED \d+ OF (\d+)/, 'board size');
  const answered = num(outcome, /(\d+) answered/, 'answered count');
  const alsoCorrect = num(outcome, /\d+ answered, (\d+) correct/, 'restated correct count');

  expect(of).toBe(boardSize);
  expect(correct).toBe(rightIdx.length);
  expect(answered).toBe(rightIdx.length + wrongIdx.length);
  expect(alsoCorrect).toBe(correct);

  // Per-row verdicts must partition the board and match the headline.
  const cells = await page
    .locator('.challenge-verdict')
    .evaluateAll((ns) => ns.map((n) => n.textContent!.replace(/\s+/g, ' ').trim()));
  expect(cells).toHaveLength(boardSize);
  expect(cells.filter((c) => c.includes('right — recovered'))).toHaveLength(correct);
  expect(cells.filter((c) => c.includes('no guess'))).toHaveLength(boardSize - answered);
  const wrong = cells.filter((c) => c.includes('wrong — it was'));
  expect(wrong).toHaveLength(answered - correct);
  // A miss must name the keyword that was actually behind the token.
  for (const i of wrongIdx) {
    const cell = cells[labels.indexOf(labels[i]!)]!;
    expect(cell).toContain(`wrong — it was “${truth.get(labels[i]!)!}”`);
  }

  // The machine scoreboard replays the same board and reports the same total.
  await page.locator('#challenge-machine').click();
  await expect(page.locator('#challenge-outcome')).toContainText('THE PATTERN WAS THE SECRET');
  const blocks = await page
    .locator('.score-block')
    .evaluateAll((ns) =>
      ns.map((n) => [
        n.querySelector('.score-label')!.textContent!.trim(),
        n.querySelector('.score-value')!.textContent!.trim(),
      ]),
    );
  const scores = new Map(blocks as Array<[string, string]>);
  expect(scores.get('You')).toBe(`${correct} / ${boardSize}`);
  // The machine, with exact background knowledge, matches Exhibit 4 exactly.
  const attack = await readAttack(page);
  expect(scores.get('IKK attack')).toBe(`${attack.correct} / ${attack.total}`);
  expect(scores.get('Guessing at random')).toBe(
    `≈ ${(boardSize / KEYWORD_COUNT).toFixed(1)} / ${boardSize}`,
  );
});

test('exhibit 5: with nothing observed the board refuses and its buttons are disabled', async ({
  page,
}) => {
  await expect(page.locator('#challenge-board')).toContainText('Nothing to work with yet');
  await expect(page.locator('#challenge-check')).toBeDisabled();
  await expect(page.locator('#challenge-machine')).toBeDisabled();

  await page.locator('#challenge-observe').click();
  await expect(page.locator('#challenge-board tbody tr')).toHaveCount(KEYWORD_COUNT);
  await expect(page.locator('#challenge-check')).toBeEnabled();
  await expect(page.locator('#challenge-machine')).toBeEnabled();

  // Every board row must state a result size and the documents behind it —
  // that pairing is the leak the exhibit hands the learner.
  const sizes = await page
    .locator('#challenge-board tbody tr td:nth-child(2)')
    .evaluateAll((ns) => ns.map((n) => n.textContent!.trim()));
  for (const cell of sizes) {
    const m = cell.match(/^(\d+) — \{(.+)\}$/);
    expect(m, `unparseable result cell: ${cell}`).not.toBeNull();
    expect(m![2]!.split(',')).toHaveLength(Number(m![1]));
  }
});

// ---------------------------------------------------------------------------
// Exhibit 6 — the measured cost
// ---------------------------------------------------------------------------

test('exhibit 6: the per-search figure is the measured total over the measured runs', async ({
  page,
}) => {
  const before = num(
    await text(page.locator('#search-ledger h3')),
    /— (\d+) queries observed/,
    'ledger size before',
  );
  expect(before).toBe(0);

  await page.locator('#compare-measure').click();
  await expect(page.locator('#compare-measurement')).toContainText('MS PER SEARCH');
  const readout = await text(page.locator('#compare-measurement'));

  const perSearch = Number(capture(readout, /([\d.]+) MS PER SEARCH/, 'per-search latency'));
  const runs = num(readout, /(\d+) real searches/, 'run count');
  const total = Number(capture(readout, /in ([\d.]+) ms total/, 'total elapsed'));

  expect(runs).toBe(50);
  expect(perSearch).toBeGreaterThan(0);
  // Both figures are rounded for display; they still have to be the same number.
  expect(Math.abs(perSearch - total / runs)).toBeLessThan(0.02);

  // "Those 50 queries also just went into the server's log."
  expect(await text(page.locator('#search-ledger h3'))).toBe(
    `The server’s log — ${before + runs} queries observed`,
  );
  await expect(page.locator('#search-ledger tbody tr')).toHaveCount(before + runs);
});
