/** Browser-derived acceptance claims for Exhibit 9's fuzzy-search lesson. */
import { expect, test, type Locator, type Page } from '@playwright/test';

const KEYWORDS = [
  'acquisition',
  'audit',
  'bonus',
  'breach',
  'contract',
  'harassment',
  'invoice',
  'layoff',
  'lawsuit',
  'merger',
  'patent',
  'resign',
  'salary',
  'subpoena',
] as const;

const pageErrors = new WeakMap<Page, string[]>();

test.beforeEach(async ({ page }) => {
  const errors: string[] = [];
  pageErrors.set(page, errors);
  page.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`));
  page.on('console', (message) => {
    if (message.type() === 'error') errors.push(`console.error: ${message.text()}`);
  });
  await page.goto('.');
  await expect(page.locator('#fuzzy-run')).toBeVisible();
});

test.afterEach(async ({ page }) => {
  expect(pageErrors.get(page) ?? []).toEqual([]);
});

async function run(page: Page, word: string, threshold: 0 | 1 | 2): Promise<void> {
  await page.locator('#fuzzy-query').fill(word);
  await page.locator('#fuzzy-threshold').selectOption(String(threshold));
  await page.locator('#fuzzy-run').click();
  await expect(page.locator('#fuzzy-run')).toBeEnabled();
}

test('arrival and one-edit search compare real exact and fuzzy routes', async ({ page }) => {
  await expect(page.locator('#fuzzy-query')).toHaveValue('asudit');
  await expect(page.locator('#fuzzy-threshold')).toHaveValue('1');
  await expect(page.locator('#fuzzy-status')).toContainText('No fuzzy comparison executed yet.');

  await run(page, 'asudit', 1);
  await expect(page.locator('#fuzzy-status')).toContainText(
    'NEIGHBORHOOD LINKED FROM OPAQUE TOKENS',
  );
  await expect(valueFor(page, 'Exact SSE baseline', 'result identifiers')).toHaveText('none');
  await expect(valueFor(page, 'Gram-based fuzzy server transcript', 'final document request'))
    .toHaveText('d02, d06, d14, d19, d21, d22');

  const expectedGrams = deletionGrams('asudit', 1);
  const tokenRows = page.locator('#fuzzy-query-token-table tbody tr');
  await expect(tokenRows).toHaveCount(expectedGrams.length);
  expect(await tokenRows.locator('td:nth-child(1)').allTextContents()).toEqual(expectedGrams);
  const fullTokens = await tokenRows.locator('td:nth-child(2)').evaluateAll((cells) =>
    cells.map((cell) => cell.getAttribute('title')),
  );
  expect(fullTokens.every((token) => /^[0-9a-f]{64}$/.test(token ?? ''))).toBe(true);
  expect(new Set(fullTokens).size).toBe(fullTokens.length);
  expect(
    (await tokenRows.locator('td:nth-child(3)').allTextContents())
      .filter((value) => value.includes('matched row')),
  ).toHaveLength(1);

  const candidate = page.locator('#fuzzy-candidate-table tbody tr');
  await expect(candidate).toHaveCount(1);
  expect(await compactRows(candidate)).toEqual([
    ['audit', '1', '1', 'within threshold'],
  ]);

  const inference = page.locator('#fuzzy-inference-table tbody tr');
  expect(await compactRows(inference)).toEqual([
    ['audit', 'no', '1', '1/12'],
    ['lawsuit', 'no', '0', '0/15'],
    ['breach', 'no', '0', '0/14'],
  ]);
});

test('threshold ledger is independently consistent with the corpus and current query', async ({ page }) => {
  await run(page, 'asudit', 1);
  const rows = page.locator('#fuzzy-threshold-table tbody tr');
  await expect(rows).toHaveCount(3);

  for (const threshold of [0, 1, 2] as const) {
    const row = page.locator(
      `#fuzzy-threshold-table tbody tr[data-threshold="${threshold}"]`,
    );
    await expect(row).toHaveCount(1);
    const cells = await compactCells(row);
    const queryGrams = deletionGrams('asudit', threshold);
    const storedRows = KEYWORDS.reduce(
      (total, keyword) => total + deletionGrams(keyword, threshold).length,
      0,
    );
    const candidates = KEYWORDS.filter((keyword) =>
      intersects(queryGrams, deletionGrams(keyword, threshold)),
    );
    const truth = KEYWORDS.filter((keyword) => levenshtein('asudit', keyword) <= threshold);
    const truePositives = candidates.filter((keyword) => truth.includes(keyword)).length;
    const falsePositives = candidates.filter((keyword) => !truth.includes(keyword)).length;
    const falseNegatives = truth.filter((keyword) => !candidates.includes(keyword)).length;
    const responseRows = KEYWORDS.reduce(
      (total, keyword) => total + intersectionSize(queryGrams, deletionGrams(keyword, threshold)),
      0,
    );

    expect(Number(cells[1])).toBe(storedRows);
    expect(Number(cells[2])).toBeGreaterThan(storedRows * 32);
    expect(cells[3]).toBe(`${queryGrams.length} / ${queryGrams.length * 32}`);
    expect(Number(cells[4])).toBe(queryGrams.length);
    expect(Number(cells[5]!.split('/')[0]!.trim())).toBe(responseRows);
    expect(Number(cells[6])).toBe(truePositives);
    expect(cells[7]).toBe(rate(falsePositives, KEYWORDS.length - truth.length));
    expect(cells[8]).toBe(rate(falseNegatives, truth.length));
    expect(cells[9]).toMatch(/^0\/\d+ \(0\.0%\)$/);
    expect(cells[10]).toMatch(truth.length === 0 ? /^0\/0 \(n\/a\)$/ : /^0\/\d+ \(0\.0%\)$/);
    expect(await row.getAttribute('data-selected')).toBe(threshold === 1 ? 'true' : 'false');
  }
});

test('threshold two exposes a gram collision but filters it before document release', async ({ page }) => {
  await run(page, 'asudit', 2);
  const rows = page.locator('#fuzzy-candidate-table tbody tr');
  await expect(rows).toHaveCount(2);
  expect(await compactRows(rows)).toEqual([
    ['audit', '6', '1', 'within threshold'],
    ['lawsuit', '1', '3', 'false positive — filtered'],
  ]);
  await expect(valueFor(page, 'Gram-based fuzzy server transcript', 'final document request'))
    .toHaveText('d02, d06, d14, d19, d21, d22');
  const thresholdRow = page.locator('#fuzzy-threshold-table tbody tr[data-threshold="2"]');
  const cells = await compactCells(thresholdRow);
  expect(cells.slice(6)).toEqual([
    '1',
    '1/13 (7.7%)',
    '0/1 (0.0%)',
    '0/18 (0.0%)',
    '0/6 (0.0%)',
  ]);
});

test('threshold zero remains exact and makes no neighborhood inference', async ({ page }) => {
  await run(page, 'asudit', 0);
  await expect(page.locator('#fuzzy-status')).toContainText(
    'NO UNIQUE KNOWN NEIGHBOR IN THIS CONTROL',
  );
  await expect(page.locator('#fuzzy-query-token-table tbody tr')).toHaveCount(1);
  await expect(page.locator('#fuzzy-candidate-table')).toHaveCount(0);
  await expect(page.locator('#fuzzy-status')).toContainText('NO SERVER CANDIDATES');
  expect(
    await page.locator('#fuzzy-inference-table tbody tr td:nth-child(3)').allTextContents(),
  ).toEqual(['0', '0', '0']);
});

test('an exact known anchor is not mislabeled as added fuzzy-neighborhood leakage', async ({
  page,
}) => {
  await run(page, 'audit', 1);
  await expect(page.locator('#fuzzy-status')).toContainText(
    'EXACT QUERY ALREADY LINKED THIS LABEL',
  );
  await expect(page.locator('#fuzzy-status')).toContainText(
    'no distinct neighbor beyond the equality already visible to exact SSE',
  );
  await expect(page.locator('#fuzzy-status')).not.toContainText(
    'NEIGHBORHOOD LINKED FROM OPAQUE TOKENS',
  );
});

test('invalid input clears old evidence and is rejected before transmission', async ({ page }) => {
  await run(page, 'asudit', 1);
  await expect(page.locator('#fuzzy-threshold-table')).toBeVisible();
  await page.locator('#fuzzy-query').fill('au*dit');
  await expect(page.locator('#fuzzy-threshold-table')).toHaveCount(0);
  await expect(page.locator('#fuzzy-status')).toContainText('Input changed; run the displayed word');
  await page.locator('#fuzzy-run').click();
  await expect(page.locator('#fuzzy-status')).toContainText('QUERY REJECTED BEFORE TRANSMISSION');
  await expect(page.locator('#fuzzy-status')).toContainText('ASCII letters a–z only');
  await expect(page.locator('#fuzzy-status table')).toHaveCount(0);
  await expect(page.locator('#fuzzy-run')).toBeEnabled();
});

test('changing only the threshold retires evidence tied to the old bundle', async ({ page }) => {
  await run(page, 'asudit', 1);
  await page.locator('#fuzzy-threshold').selectOption('2');
  await expect(page.locator('#fuzzy-status')).toContainText('Input changed; run the displayed word');
  await expect(page.locator('#fuzzy-query-token-table')).toHaveCount(0);
  await expect(page.locator('#fuzzy-candidate-table')).toHaveCount(0);
  await expect(page.locator('#fuzzy-inference-table')).toHaveCount(0);
});

test('editing input during WebCrypto work cannot restore a stale result', async ({ page }) => {
  await page.evaluate(() => {
    const subtle = crypto.subtle as unknown as Record<
      string,
      (...args: unknown[]) => Promise<ArrayBuffer>
    >;
    const original = subtle.sign!.bind(crypto.subtle);
    Object.defineProperty(crypto.subtle, 'sign', {
      configurable: true,
      value: async (...args: unknown[]) => {
        await new Promise((resolve) => setTimeout(resolve, 5));
        return original(...args);
      },
    });
  });
  await page.locator('#fuzzy-run').click();
  await expect(page.locator('#fuzzy-run')).toHaveAttribute('aria-busy', 'true');
  await page.locator('#fuzzy-query').fill('lawsuit');
  await expect(page.locator('#fuzzy-status')).toContainText('retired WebCrypto work');
  await expect(page.locator('#fuzzy-run')).toBeDisabled();
  await expect(page.locator('#fuzzy-run')).toBeEnabled();
  await expect(page.locator('#fuzzy-status')).toContainText('retired WebCrypto work');
  await expect(page.locator('#fuzzy-status')).not.toContainText(
    'NEIGHBORHOOD LINKED FROM OPAQUE TOKENS',
  );
  await expect(page.locator('#fuzzy-status table')).toHaveCount(0);
});

function valueFor(page: Page, region: string, label: string): Locator {
  return page
    .locator(`section[aria-label="${region}"]`)
    .locator(`.value-row:has(.value-label:text-is("${label}")) .value-bytes`);
}

function deletionGrams(word: string, threshold: number): string[] {
  const out = new Set<string>();
  const visit = (removed: number[], remaining: number, start: number): void => {
    if (remaining === 0) {
      out.add([...word].filter((_, index) => !removed.includes(index)).join(''));
      return;
    }
    for (let index = start; index <= word.length - remaining; index++) {
      visit([...removed, index], remaining - 1, index + 1);
    }
  };
  for (let removed = 0; removed <= threshold; removed++) visit([], removed, 0);
  return [...out].sort();
}

function levenshtein(left: string, right: string): number {
  const table = Array.from({ length: left.length + 1 }, () =>
    Array<number>(right.length + 1).fill(0),
  );
  for (let row = 0; row <= left.length; row++) table[row]![0] = row;
  for (let column = 0; column <= right.length; column++) table[0]![column] = column;
  for (let row = 1; row <= left.length; row++) {
    for (let column = 1; column <= right.length; column++) {
      table[row]![column] = Math.min(
        table[row - 1]![column]! + 1,
        table[row]![column - 1]! + 1,
        table[row - 1]![column - 1]! + (left[row - 1] === right[column - 1] ? 0 : 1),
      );
    }
  }
  return table[left.length]![right.length]!;
}

function intersectionSize(left: readonly string[], right: readonly string[]): number {
  const rightSet = new Set(right);
  return left.filter((value) => rightSet.has(value)).length;
}

function intersects(left: readonly string[], right: readonly string[]): boolean {
  return intersectionSize(left, right) > 0;
}

function rate(numerator: number, denominator: number): string {
  if (denominator === 0) return `${numerator}/0 (n/a)`;
  return `${numerator}/${denominator} (${((numerator / denominator) * 100).toFixed(1)}%)`;
}

async function compactRows(rows: Locator): Promise<string[][]> {
  return rows.evaluateAll((items) =>
    items.map((row) =>
      Array.from(row.querySelectorAll('th,td'), (cell) =>
        (cell.textContent ?? '').replace(/\s+/g, ' ').trim().replace(/^[✓!]\s*/, ''),
      ),
    ),
  );
}

async function compactCells(row: Locator): Promise<string[]> {
  return (await compactRows(row))[0]!;
}
