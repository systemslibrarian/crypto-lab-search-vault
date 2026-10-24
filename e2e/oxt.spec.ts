/** Browser-derived acceptance claims for Exhibit 7's bounded OXT lesson. */
import { expect, test, type Locator, type Page } from '@playwright/test';

const pageErrors = new WeakMap<Page, string[]>();

test.beforeEach(async ({ page }) => {
  const errors: string[] = [];
  pageErrors.set(page, errors);
  page.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`));
  page.on('console', (message) => {
    if (message.type() === 'error') errors.push(`console.error: ${message.text()}`);
  });
  await page.goto('.');
  await expect(page.locator('#oxt-run')).toBeVisible();
});

test.afterEach(async ({ page }) => {
  expect(pageErrors.get(page) ?? []).toEqual([]);
});

function metric(page: Page, label: string): Locator {
  return page
    .locator('#oxt-status .score-block')
    .filter({ has: page.locator(`.score-label:text-is("${label}")`) });
}

async function run(page: Page, query: string): Promise<void> {
  await page.locator('#oxt-query').fill(query);
  await page.locator('#oxt-run').click();
  await expect(page.locator('#oxt-status')).toContainText(
    'SAME PLAINTEXT ANSWER, DIFFERENT TRANSCRIPT',
  );
}

test('valid conjunction: both real routes agree and every displayed count has row evidence', async ({
  page,
}) => {
  await expect(page.locator('#oxt-query')).toHaveValue('breach AND audit');
  await expect(page.locator('#oxt-status')).toContainText('No conjunction executed yet.');
  await run(page, 'breach AND audit');

  const naiveLookups = Number(await metric(page, 'Naïve lookups').locator('.score-value').innerText());
  const oxtQueries = Number(await metric(page, 'OXT server queries').locator('.score-value').innerText());
  const tsetRows = Number(await metric(page, 'OXT TSet rows').locator('.score-value').innerText());
  const exactTests = Number(await metric(page, 'Exact XSet tests').locator('.score-value').innerText());
  const finalMatches = Number(await metric(page, 'Final matches').locator('.score-value').innerText());
  expect(naiveLookups).toBe(2);
  expect(oxtQueries).toBe(1);
  expect(tsetRows).toBe(4);
  expect(exactTests).toBe(tsetRows);
  expect(finalMatches).toBe(2);

  const naiveRows = page.locator(
    '#oxt-status [aria-label="Naive SSE comparison with client-only labels"] .value-row',
  );
  await expect(naiveRows).toHaveCount(2);
  const tokens = await naiveRows.locator('.value-bytes').evaluateAll((nodes) =>
    nodes.map((node) => node.getAttribute('title')),
  );
  expect(tokens).toHaveLength(2);
  expect(tokens[0]).toMatch(/^[0-9a-f]{64}$/);
  expect(tokens[1]).toMatch(/^[0-9a-f]{64}$/);
  expect(tokens[0]).not.toBe(tokens[1]);
  await expect(naiveRows.nth(0)).toContainText('[d02, d13, d15, d22]');
  await expect(naiveRows.nth(1)).toContainText('[d02, d06, d14, d19, d21, d22]');
  expect(await naiveRepeatFlags(page)).toEqual(['no', 'no']);

  const membershipRows = page.locator('#oxt-status table.data tbody tr');
  await expect(membershipRows).toHaveCount(tsetRows);
  const markedMembers = await membershipRows
    .locator('td:last-child')
    .evaluateAll((cells) => cells.filter((cell) => cell.textContent?.includes('member') && !cell.textContent?.includes('not a member')).length);
  expect(markedMembers).toBe(finalMatches);
  const wirePoints = await membershipRows.evaluateAll((rows) =>
    rows.map((row) => ({
      xtoken: row.querySelector('td:nth-child(2)')!.getAttribute('title'),
      candidate: row.querySelector('td:nth-child(3)')!.getAttribute('title'),
    })),
  );
  for (const row of wirePoints) {
    expect(row.xtoken).toMatch(/^[0-9a-f]{64}$/);
    expect(row.candidate).toMatch(/^[0-9a-f]{64}$/);
  }
  await expect(page.locator('#oxt-status')).toContainText('[d02, d22]');
  await expect(
    page.locator(
      '#oxt-status [aria-label="OXT comparison with client-only labels"] .value-row:has(.value-label:text-is("x posting list sent")) .value-bytes',
    ),
  ).toHaveText('no');
});

test('reversed operands select identical s/x roles and emit identical OXT bytes', async ({ page }) => {
  await run(page, 'breach AND audit');
  const first = await transcriptBytes(page);
  expect(await naiveRepeatFlags(page)).toEqual(['no', 'no']);

  await page.locator('#oxt-query').fill('audit AND breach');
  await expect(page.locator('#oxt-status table')).toHaveCount(0);
  await expect(page.locator('#oxt-status')).toContainText('Input changed; run the displayed conjunction');
  await page.locator('#oxt-run').click();
  await expect(page.locator('#oxt-status')).toContainText(
    'SAME PLAINTEXT ANSWER, DIFFERENT TRANSCRIPT',
  );
  const reverse = await transcriptBytes(page);
  expect(await naiveRepeatFlags(page)).toEqual(['yes', 'yes']);

  expect(reverse.sTerm).toBe(first.sTerm);
  expect(reverse.xTerm).toBe(first.xTerm);
  expect(reverse.stag).toBe(first.stag);
  expect(reverse.xtokens).toEqual(first.xtokens);
  expect(reverse.candidates).toEqual(first.candidates);
  expect(reverse.outcomes).toEqual(first.outcomes);
  expect(reverse.result).toBe(first.result);
});

test('invalid grammar clears prior evidence and produces no plausible transcript', async ({ page }) => {
  await run(page, 'breach AND audit');
  for (const [input, message] of [
    ['audit OR breach', 'OR is not supported'],
    ['audit AND audit', 'must be distinct'],
    ['audit AND breach AND salary', 'exactly two terms'],
    ['audit AND unicorn', 'Not in this fixed index'],
    ['(audit) AND breach', 'Parentheses are not supported'],
  ] as const) {
    await page.locator('#oxt-query').fill(input);
    await expect(page.locator('#oxt-status table')).toHaveCount(0);
    await expect(page.locator('#oxt-status .score-block')).toHaveCount(0);
    await page.locator('#oxt-run').click();
    await expect(page.locator('#oxt-status')).toContainText('QUERY REJECTED BEFORE TRANSMISSION');
    await expect(page.locator('#oxt-status')).toContainText(message);
    await expect(page.locator('#oxt-status table')).toHaveCount(0);
  }
});

test('a crypto execution error never claims pre-transmission grammar rejection', async ({ page }) => {
  await page.evaluate(() => {
    Object.defineProperty(crypto.subtle, 'sign', {
      configurable: true,
      value: async () => {
        throw new Error('synthetic crypto failure');
      },
    });
  });
  await page.locator('#oxt-run').click();
  await expect(page.locator('#oxt-status')).toContainText('COMPARISON FAILED');
  await expect(page.locator('#oxt-status')).toContainText(
    'Do not treat any partial server work as a result.',
  );
  await expect(page.locator('#oxt-status')).not.toContainText(
    'QUERY REJECTED BEFORE TRANSMISSION',
  );
  await expect(page.locator('#oxt-run')).toBeEnabled();
});

test('five controlled traces distinguish stag equality from candidate-point repetition', async ({
  page,
}) => {
  await page.locator('#oxt-controls').click();
  const rows = page.locator('#oxt-control-result table tbody tr');
  await expect(rows).toHaveCount(5);

  const evidence = await rows.evaluateAll((items) =>
    items.map((row) => {
      const cells = row.querySelectorAll('th,td');
      return Array.from(cells, (cell) =>
        (cell as HTMLElement).innerText.replace(/\s+/g, ' ').trim(),
      );
    }),
  );
  expect(evidence).toEqual([
    ['same x, overlapping s', 'breach AND audit subpoena AND audit', 'no', '3', 'd13, d15, d22'],
    ['same x, disjoint s', 'patent AND audit harassment AND audit', 'no', '0', 'none'],
    ['different x, overlapping s', 'breach AND audit subpoena AND lawsuit', 'no', '0', 'none'],
    ['same s, different x', 'breach AND audit breach AND lawsuit', 'yes', '0', 'none'],
    ['identical query', 'breach AND audit breach AND audit', 'yes', '4', 'd02, d13, d15, d22'],
  ]);
  await expect(page.locator('#oxt-control-result')).toContainText('ZERO REPEATS IS AMBIGUOUS');
  await expect(page.locator('#oxt-control-result')).toContainText(
    'zero cannot prove that x changed',
  );
});

test('Path ORAM comparison derives fixed transfer counts and labels its boundary', async ({ page }) => {
  const panel = page.locator('section.panel').filter({ has: page.locator('#oxt-query') });
  const values = await panel.locator('section[aria-labelledby="h-oxt-oram-comparison"] .score-value').allTextContents();
  expect(values).toEqual(['24', '5', '48', '144']);

  const rows = await panel
    .locator('section[aria-labelledby="h-oxt-oram-comparison"] table tbody tr')
    .evaluateAll((items) =>
      items.map((row) => Array.from(row.querySelectorAll('th,td'), (cell) => Number(cell.textContent))),
    );
  expect(rows).toEqual([
    [0, 3, 3, 144],
    [1, 2, 3, 144],
    [2, 1, 3, 144],
    [3, 0, 3, 144],
  ]);
  await expect(panel).toContainText('separate, non-colluding, semi-honest storage server');
  await expect(panel).toContainText('not round trips');
  await expect(panel).toContainText('do not hide the OXT search server’s stag');
});

test('editing input during async crypto retires the old completion', async ({ page }) => {
  await page.evaluate(() => {
    const subtle = crypto.subtle as unknown as Record<
      string,
      (...args: unknown[]) => Promise<ArrayBuffer>
    >;
    const original = subtle.sign!.bind(crypto.subtle);
    Object.defineProperty(crypto.subtle, 'sign', {
      configurable: true,
      value: async (...args: unknown[]) => {
        await new Promise((resolve) => setTimeout(resolve, 30));
        return original(...args);
      },
    });
  });

  await page.locator('#oxt-run').click();
  await expect(page.locator('#oxt-run')).toHaveAttribute('aria-busy', 'true');
  await page.locator('#oxt-query').fill('audit AND subpoena');
  await expect(page.locator('#oxt-status')).toContainText(
    'The retired computation may already have reached the isolated servers',
  );
  await expect(page.locator('#oxt-run')).toBeDisabled();
  await expect(page.locator('#oxt-run')).toHaveAttribute('aria-busy', 'true');
  await expect(page.locator('#oxt-run')).toBeEnabled();
  await expect(page.locator('#oxt-run')).toHaveAttribute('aria-busy', 'false');
  await expect(page.locator('#oxt-status')).toContainText(
    'The retired computation may already have reached the isolated servers',
  );
  await expect(page.locator('#oxt-status')).not.toContainText(
    'SAME PLAINTEXT ANSWER, DIFFERENT TRANSCRIPT',
  );
  await expect(page.locator('#oxt-status table')).toHaveCount(0);
});

async function transcriptBytes(page: Page): Promise<{
  sTerm: string;
  xTerm: string;
  stag: string | null;
  xtokens: Array<string | null>;
  candidates: Array<string | null>;
  outcomes: string[];
  result: string;
}> {
  const server = page.locator('#oxt-status [aria-label="OXT comparison with client-only labels"]');
  const rowValue = (label: string): Locator =>
    server.locator(`.value-row:has(.value-label:text-is("${label}")) .value-bytes`);
  const rows = page.locator('#oxt-status table.data tbody tr');
  return {
    sTerm: await rowValue('s role, client label').innerText(),
    xTerm: await rowValue('x role, client label').innerText(),
    stag: await rowValue('stag sent').getAttribute('title'),
    xtokens: await rows.locator('td:nth-child(2)').evaluateAll((cells) =>
      cells.map((cell) => cell.getAttribute('title')),
    ),
    candidates: await rows.locator('td:nth-child(3)').evaluateAll((cells) =>
      cells.map((cell) => cell.getAttribute('title')),
    ),
    outcomes: await rows.locator('td:nth-child(4)').allTextContents(),
    result: await metric(page, 'Final matches').innerText(),
  };
}

async function naiveRepeatFlags(page: Page): Promise<string[]> {
  return page
    .locator('#oxt-status [aria-label="Naive SSE comparison with client-only labels"] .value-bytes')
    .evaluateAll((nodes) =>
      nodes.map((node) => node.textContent?.match(/repeated token: (yes|no)/)?.[1] ?? 'missing'),
    );
}
