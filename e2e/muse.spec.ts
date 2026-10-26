/** Browser-derived acceptance claims for Exhibit 10's multi-user search lesson. */
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
  await expect(page.locator('#muse-run')).toBeVisible();
});

test.afterEach(async ({ page }) => {
  expect(pageErrors.get(page) ?? []).toEqual([]);
});

async function run(page: Page): Promise<void> {
  await page.locator('#muse-run').click();
  await expect(page.locator('#muse-run')).toHaveText('Run another fresh session', {
    timeout: 60_000,
  });
  await expect(page.locator('#muse-status')).toContainText(
    'KNOWN LABEL CROSSED THE AUTHORIZATION GRAPH',
  );
}

test('arrival labels the construction boundary and separates the teaching oracle', async ({
  page,
}) => {
  await expect(page.locator('#muse-status')).toContainText('No session executed yet.');
  await expect(page.locator('#muse-status table')).toHaveCount(0);
  await expect(page.locator('#muse-run')).toBeEnabled();

  const panel = page.locator('section.panel').filter({ has: page.locator('#muse-run') });
  await expect(panel).toContainText('non-production 1024-bit Paillier modulus');
  await expect(panel).toContainText('omits the paper’s recursive OT');
  await expect(panel.getByRole('link', { name: 'Attack paper' })).toHaveAttribute(
    'href',
    'https://petsymposium.org/popets/2017/popets-2017-0034.pdf',
  );
  await expect(panel.getByRole('link', { name: 'Split-trust paper' })).toHaveAttribute(
    'href',
    'https://eprint.iacr.org/2018/090',
  );

  expect(await compactRows(page.locator('#muse-authorization-table tbody tr'))).toEqual([
    ['Clinical A (writer-a)', 'audit, budget', 'reader-known, reader-target'],
    ['Legal B (writer-b)', 'audit, lawsuit', 'reader-target'],
    ['Security C (writer-c)', 'breach, forensic', 'reader-target'],
  ]);
  await expect(page.locator('#muse-authorization-table caption')).toContainText(
    'not an attacker input',
  );
});

test('role and authorization failures leave no partial server transcript', async ({ page }) => {
  await run(page);
  const rows = await compactRows(page.locator('#muse-rejection-table tbody tr'));
  expect(rows).toHaveLength(3);
  expect(rows.map((row) => row.slice(0, 2))).toEqual([
    ['reader-known', 'upload writer index'],
    ['writer-a', 'issue reader query'],
    ['reader-known', 'search writer-b'],
  ]);
  expect(rows[0]![2]).toContain('does not hold the writer role');
  expect(rows[1]![2]).toContain('does not hold the reader role');
  expect(rows[2]![2]).toContain('not authorized for writer-b');
  for (const row of rows) {
    const [before, after] = row[3]!.split('→').map((value) => Number(value.trim()));
    expect(after).toBe(before);
  }
  await expect(page.locator('#muse-rejection-table caption')).toContainText(
    'each before/after count is equal',
  );
});

test('one colluding label propagates only along actual iterative-test equality edges', async ({
  page,
}) => {
  await run(page);
  const transcript = await compactRows(page.locator('#muse-single-transcript tbody tr'));
  expect(transcript).toHaveLength(3);

  // Derive the matching encrypted-row ids from the page's independent plaintext
  // teaching oracle instead of trusting the attack headline.
  const oracle = await page.locator('#muse-authorization-table tbody tr').evaluateAll((rows) =>
    rows.map((row) => {
      const cells = row.querySelectorAll('th,td');
      const writer = row.getAttribute('data-writer')!;
      const keywords = (cells[1]!.textContent ?? '').split(',').map((value) => value.trim());
      return { writer, keywords };
    }),
  );
  const auditRows = oracle.flatMap(({ writer, keywords }) => {
    const position = keywords.indexOf('audit');
    return position < 0 ? [] : [`${writer}:row-${position + 1}`];
  });
  expect(auditRows).toEqual(['writer-a:row-1', 'writer-b:row-1']);

  expect(transcript[0]!.slice(0, 5)).toEqual([
    'query-1',
    'reader-known',
    'writer-a',
    '2',
    'writer-a:row-1',
  ]);
  expect(transcript[1]!.slice(0, 5)).toEqual([
    'query-2',
    'reader-target',
    'writer-a, writer-b, writer-c',
    '6',
    auditRows.join(', '),
  ]);
  expect(transcript[2]!.slice(0, 5)).toEqual([
    'query-3',
    'reader-target',
    'writer-a, writer-b, writer-c',
    '6',
    'writer-c:row-1',
  ]);

  const recovered = await page
    .locator('#muse-equivalence-class tbody tr th')
    .allTextContents();
  expect(recovered.map((value) => value.trim()).sort()).toEqual([
    'query/query-1',
    'query/query-2',
    'row/writer-a:row-1',
    'row/writer-b:row-1',
  ]);
  await expect(metric(page, 'Target query labelled')).toContainText('yes');
  await expect(metric(page, 'Unauthorized writer reached')).toContainText('yes');
  await expect(metric(page, 'Changed-query control')).toContainText('unknown');
});

test('split route agrees with the oracle and neither server view alone joins writer to positivity', async ({
  page,
}) => {
  await run(page);
  const result = new Map(
    (await compactRows(page.locator('#muse-reader-result tbody tr'))).map((row) => [
      row[0]!,
      row[1]!,
    ]),
  );
  expect(result.get('Plaintext oracle')).toBe('writer-a, writer-b');
  expect(result.get('False negatives')).toBe('none');

  const list = (value: string | undefined): string[] =>
    !value || value === 'none' ? [] : value.split(',').map((item) => item.trim());
  const opened = list(result.get('Reader opened')).sort();
  const oracle = list(result.get('Plaintext oracle')).sort();
  const falsePositives = list(result.get('False positives')).sort();
  const falseNegatives = list(result.get('False negatives')).sort();
  expect(falseNegatives).toEqual(oracle.filter((writer) => !opened.includes(writer)));
  expect(falsePositives).toEqual(opened.filter((writer) => !oracle.includes(writer)));
  expect(opened).toEqual([...oracle, ...falsePositives].sort());

  const messages = page.locator('#muse-qm-message-table tbody tr');
  await expect(messages).toHaveCount(3);
  for (const row of await compactRows(messages)) {
    const positions = row[2]!.split(',').map((value) => Number(value.trim()));
    expect(positions).toHaveLength(3);
    expect(new Set(positions).size).toBe(3);
    expect(positions.every((position) => position >= 0 && position < 64)).toBe(true);
  }

  const responses = page.locator('#muse-qm-response-table tbody tr');
  await expect(responses).toHaveCount(3);
  const positives = page.locator('#muse-qm-response-table tbody tr[data-positive="true"]');
  await expect(positives).toHaveCount(opened.length);
  await expect(page.locator('#muse-qm-response-table thead')).not.toContainText('Writer');

  const combinedPositiveWriters = await page
    .locator('#muse-combined-view-table tbody tr[data-positive="true"]')
    .evaluateAll((rows) => rows.map((row) => row.getAttribute('data-writer')!).sort());
  expect(combinedPositiveWriters).toEqual(opened);
  await expect(page.locator('#muse-status')).toContainText(
    'QM + DH COLLUSION RECONSTRUCTS THE ASSOCIATION',
  );
  await expect(page.locator('#muse-status')).toContainText(
    'bounded honest-but-curious execution',
  );
});

test('repeating one split query produces fresh trapdoor and selector bytes', async ({ page }) => {
  await run(page);
  const rows = page.locator('#muse-repeat-table tbody tr');
  await expect(rows).toHaveCount(2);
  const full = await rows.evaluateAll((items) =>
    items.map((row) => {
      const cells = row.querySelectorAll('th,td');
      return {
        label: cells[0]!.textContent!.trim(),
        trapdoor: cells[1]!.getAttribute('title')!,
        selector: cells[2]!.getAttribute('title')!,
      };
    }),
  );
  expect(full.map((row) => row.label)).toEqual(['first', 'repeat']);
  for (const row of full) {
    expect(row.trapdoor).toMatch(/^[0-9a-f]{96}$/);
    expect(row.selector).toMatch(/^[0-9a-f]{64}$/);
  }
  expect(full[0]!.trapdoor).not.toBe(full[1]!.trapdoor);
  expect(full[0]!.selector).not.toBe(full[1]!.selector);
  await expect(metric(page, 'Repeat preparation', '#muse-split-metrics')).toContainText(
    'fresh bytes',
  );
});

test('a key-generation failure is reported without leaving the control locked', async ({ page }) => {
  await page.evaluate(() => {
    Object.defineProperty(crypto.subtle, 'generateKey', {
      configurable: true,
      value: async () => {
        throw new Error('synthetic Paillier key-generation failure');
      },
    });
  });
  await page.locator('#muse-run').click();
  await expect(page.locator('#muse-status')).toContainText('SESSION REFUSED');
  await expect(page.locator('#muse-status')).toContainText(
    'synthetic Paillier key-generation failure',
  );
  await expect(page.locator('#muse-run')).toBeEnabled();
  await expect(page.locator('#muse-run')).toHaveText('Run another fresh session');
  await expect(page.locator('#muse-status table')).toHaveCount(0);
});

function metric(page: Page, label: string, root = '#muse-attack-summary'): Locator {
  return page
    .locator(`${root} .score-block`)
    .filter({ has: page.locator(`.score-label:text-is("${label}")`) });
}

async function compactRows(rows: Locator): Promise<string[][]> {
  return rows.evaluateAll((items) =>
    items.map((row) =>
      Array.from(row.querySelectorAll('th,td'), (cell) =>
        (cell.textContent ?? '').replace(/\s+/g, ' ').trim().replace(/^[=✓!]\s*/, ''),
      ),
    ),
  );
}
