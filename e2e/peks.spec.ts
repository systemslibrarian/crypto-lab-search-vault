/** Browser-derived acceptance claims for Exhibit 7's real PEKS computation. */
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
  await expect(page.locator('#peks-build')).toBeVisible();
});

test.afterEach(async ({ page }) => {
  expect(pageErrors.get(page) ?? []).toEqual([]);
});

async function build(page: Page): Promise<void> {
  await page.locator('#peks-build').click();
  await expect(page.locator('#peks-build-status')).toContainText('PUBLIC-KEY TAGS BUILT');
  await expect(page.locator('#peks-query')).toBeEnabled();
}

async function query(page: Page, keyword = 'audit'): Promise<void> {
  await page.locator('#peks-keyword').selectOption(keyword);
  await page.locator('#peks-query').click();
  await expect(page.locator('#peks-query-result')).toContainText('ANSWERED — AND OBSERVED');
}

function compactText(locator: Locator): Promise<string> {
  return locator.innerText().then((value) => value.replace(/\s+/g, ' ').trim());
}

function capture(haystack: string, expression: RegExp, label: string): string {
  const match = haystack.match(expression);
  expect(match, `${label} missing from: ${haystack}`).not.toBeNull();
  return match![1]!;
}

test('PEKS build: public-key-only sender creates randomized tags and server stores no keywords', async ({
  page,
}) => {
  await expect(page.locator('#peks-build-status')).toContainText('NOT BUILT YET');
  await expect(page.locator('#peks-query')).toBeDisabled();
  await expect(page.locator('#peks-repeat')).toBeDisabled();
  await expect(page.locator('#peks-dictionary-mode')).toBeDisabled();
  await expect(page.locator('#peks-dictionary-bound')).toBeDisabled();
  await expect(page.locator('#peks-attack')).toBeDisabled();
  await build(page);

  const senderRows = page.locator('#peks-sender-table tbody tr');
  const serverRows = page.locator('#peks-server-table tbody tr');
  const count = await senderRows.count();
  expect(count).toBeGreaterThan(0);
  await expect(serverRows).toHaveCount(count);
  await expect(page.locator('#peks-build-status')).toContainText(
    `${count} tags were computed with the recipient public key`,
  );

  const senderIds = await senderRows.locator('td:nth-child(1)').allTextContents();
  const serverIds = await serverRows.locator('td:nth-child(1)').allTextContents();
  expect(serverIds).toEqual(senderIds);
  await expect(page.locator('#peks-server-table thead')).not.toContainText('keyword');
  await expect(page.locator('#peks-roles .side-server')).toContainText('No keyword or body');
  await expect(page.locator('#peks-roles .side-server')).not.toContainText('audit');
  await expect(page.locator('#peks-roles .side-server')).not.toContainText('merger');
  await expect(page.locator('#peks-roles')).toContainText('held here; never rendered or sent');

  const serverTags = await serverRows.evaluateAll((rows) =>
    rows.map((row) => {
      const cells = row.querySelectorAll('td');
      return {
        a: cells[1]!.getAttribute('title')!,
        b: cells[2]!.getAttribute('title')!,
      };
    }),
  );
  for (const tag of serverTags) {
    expect(tag.a).toMatch(/^[0-9a-f]{192}$/);
    expect(tag.b).toMatch(/^[0-9a-f]{64}$/);
  }

  // Take the repeated word from the sender's own evidence, then compare the
  // full A bytes held by the server. No fixed record count or tag is assumed.
  const senderEvidence = await senderRows.evaluateAll((rows) =>
    rows.map((row) => {
      const cells = row.querySelectorAll('td');
      return { id: cells[0]!.textContent!.trim(), keyword: cells[1]!.textContent!.trim() };
    }),
  );
  const repeated = senderEvidence.find(
    (entry, index, all) => all.findIndex((other) => other.keyword === entry.keyword) !== index,
  )!.keyword;
  const repeatedIds = senderEvidence.filter((entry) => entry.keyword === repeated).map((entry) => entry.id);
  const repeatedA = serverTags.filter((_, index) => repeatedIds.includes(serverIds[index]!.trim())).map((tag) => tag.a);
  expect(new Set(repeatedA).size).toBe(repeatedA.length);
});

test('PEKS build failure leaves every dependent control disabled', async ({ page }) => {
  await page.evaluate(() => {
    Object.defineProperty(globalThis.crypto, 'getRandomValues', {
      configurable: true,
      value: () => {
        throw new Error('synthetic RNG failure');
      },
    });
  });
  await page.locator('#peks-build').click();
  await expect(page.locator('#peks-build-status')).toContainText('PEKS BUILD FAILED');
  await expect(page.locator('#peks-build-status')).toContainText('synthetic RNG failure');
  await expect(page.locator('#peks-build')).toBeEnabled();
  await expect(page.locator('#peks-query')).toBeDisabled();
  await expect(page.locator('#peks-repeat')).toBeDisabled();
  await expect(page.locator('#peks-dictionary-mode')).toBeDisabled();
  await expect(page.locator('#peks-dictionary-bound')).toBeDisabled();
  await expect(page.locator('#peks-attack')).toBeDisabled();
});

test('PEKS search: Test row count, marked matches, verdict, and ledger derive from one scan', async ({
  page,
}) => {
  await build(page);
  await query(page, 'audit');

  const stored = await page.locator('#peks-server-table tbody tr').count();
  const testRows = page.locator('#peks-test-table tbody tr');
  await expect(testRows).toHaveCount(stored);
  expect(await compactText(page.locator('#peks-test-table caption'))).toBe(
    `${stored} public Test evaluations over ${stored} stored tags`,
  );

  const marked = await testRows.evaluateAll((rows) =>
    rows
      .filter((row) => row.querySelector('td:nth-child(2)')!.textContent!.includes('MATCH'))
      .map((row) => row.querySelector('td:nth-child(1)')!.textContent!.trim()),
  );
  const verdictText = await compactText(page.locator('#peks-query-result .verdict'));
  const claimedTests = Number(capture(verdictText, /evaluated all (\d+) tags/, 'Test count'));
  const claimedMatches = Number(capture(verdictText, /returned (\d+) opaque records/, 'match count'));
  const claimedIds = capture(verdictText, /opaque records: ([^.]+)\./, 'matched ids')
    .split(',')
    .map((id) => id.trim());
  expect(claimedTests).toBe(stored);
  expect(claimedMatches).toBe(marked.length);
  expect(claimedIds).toEqual(marked);

  const ledger = page.locator('#peks-ledger tbody tr');
  await expect(ledger).toHaveCount(1);
  expect(await compactText(ledger.locator('td').nth(2))).toBe(String(stored));
  expect(await compactText(ledger.locator('td').nth(3))).toBe(String(marked.length));
  expect(await compactText(ledger.locator('td').nth(4))).toBe(marked.join(' '));
});

test('PEKS repeat: independently issued trapdoors are byte-identical and linkable in the ledger', async ({
  page,
}) => {
  await build(page);
  await query(page, 'audit');
  const trapdoor = await page
    .locator('#peks-query-result .value-row:has(.value-label:text-is("trapdoor sent")) .value-bytes')
    .getAttribute('title');
  expect(trapdoor).toMatch(/^[0-9a-f]{96}$/);

  await page.locator('#peks-repeat').click();
  await expect(page.locator('#peks-repeat-result')).toContainText('REPEAT LINKED BYTE-FOR-BYTE');
  await expect(page.locator('#peks-repeat-result')).toContainText('all 48 bytes');
  const repeated = await page
    .locator('#peks-query-result .value-row:has(.value-label:text-is("trapdoor sent")) .value-bytes')
    .getAttribute('title');
  expect(repeated).toBe(trapdoor);

  const ledgerTrapdoors = await page
    .locator('#peks-ledger tbody tr td:nth-child(2)')
    .evaluateAll((cells) => cells.map((cell) => cell.getAttribute('title')));
  expect(ledgerTrapdoors).toEqual([trapdoor, trapdoor]);
});

test('PEKS offline attack: headline is the first passing public Test row', async ({ page }) => {
  await build(page);
  await query(page, 'audit');
  await page.locator('#peks-dictionary-mode').selectOption('includes');
  await page.locator('#peks-dictionary-bound').selectOption('6');
  await page.locator('#peks-attack').click();
  await expect(page.locator('#peks-attack-result')).toContainText('KEYWORD RECOVERED');

  const rows = page.locator('#peks-dictionary-table tbody tr');
  const attempts = await rows.count();
  expect(attempts).toBeGreaterThan(0);
  const outcomes = await rows.locator('td:nth-child(3)').allTextContents();
  expect(outcomes.slice(0, -1).every((value) => value.includes('FAIL'))).toBe(true);
  expect(outcomes.at(-1)).toContain('PASS — recovered');

  const guessed = (await rows.last().locator('td').first().innerText()).trim();
  expect(guessed).toBe(await page.locator('#peks-keyword').inputValue());
  const summary = await compactText(page.locator('#peks-attack-result .verdict'));
  expect(summary).toContain(`KEYWORD RECOVERED: “${guessed}”`);
  expect(Number(capture(summary, /was guess (\d+)/, 'attempt number'))).toBe(attempts);
  expect(Number(capture(summary, /bound of (\d+)/, 'bound'))).toBe(6);
});

test('PEKS bounded miss: absent and zero-guess cases never claim security', async ({ page }) => {
  await build(page);
  await query(page, 'audit');
  await page.locator('#peks-dictionary-mode').selectOption('excludes');
  await page.locator('#peks-dictionary-bound').selectOption('4');
  await page.locator('#peks-attack').click();
  await expect(page.locator('#peks-attack-result')).toContainText('NOT RECOVERED WITHIN THIS BOUND');
  await expect(page.locator('#peks-dictionary-table tbody tr')).toHaveCount(4);
  await expect(page.locator('#peks-attack-result')).toContainText(
    'This does not establish security: the target may be absent',
  );
  await expect(page.locator('#peks-attack-result')).not.toContainText('KEYWORD RECOVERED');
  await expect(page.locator('#peks-dictionary-table')).not.toContainText('PASS — recovered');

  await page.locator('#peks-dictionary-bound').selectOption('0');
  await page.locator('#peks-attack').click();
  await expect(page.locator('#peks-attack-result')).toContainText('NOT RECOVERED WITHIN THIS BOUND');
  await expect(page.locator('#peks-attack-result')).toContainText(
    '0 of at most 0 guesses were tested. This does not establish security',
  );
  await expect(page.locator('#peks-dictionary-table tbody tr')).toHaveCount(0);
});

test('changing the recipient keyword retires evidence tied to the old trapdoor', async ({ page }) => {
  await build(page);
  await query(page, 'audit');
  await expect(page.locator('#peks-repeat')).toBeEnabled();
  await expect(page.locator('#peks-attack')).toBeEnabled();

  await page.locator('#peks-keyword').selectOption('merger');
  await expect(page.locator('#peks-query-result')).toBeEmpty();
  await expect(page.locator('#peks-repeat-result')).toBeEmpty();
  await expect(page.locator('#peks-attack-result')).toBeEmpty();
  await expect(page.locator('#peks-repeat')).toBeDisabled();
  await expect(page.locator('#peks-attack')).toBeDisabled();
  // Historical server leakage remains honestly visible; it is not erased by a
  // recipient-side selection change.
  await expect(page.locator('#peks-ledger tbody tr')).toHaveCount(1);
});

test('a mid-attack keyword change invalidates the stale operation and its verdict', async ({ page }) => {
  await build(page);
  await query(page, 'audit');
  await page.locator('#peks-dictionary-mode').selectOption('excludes');
  await page.locator('#peks-dictionary-bound').selectOption('6');
  await page.locator('#peks-attack').click();
  await expect(page.locator('#peks-attack-progress')).toContainText('Tested');

  // Pairing work yields between guesses. Every PEKS control is locked while
  // that async operation owns the learner-visible evidence slots. Capture all
  // states in one browser turn so sequential assertions cannot outlive it.
  const locked = await page.evaluate(() =>
    [
      'peks-build',
      'peks-keyword',
      'peks-query',
      'peks-repeat',
      'peks-dictionary-mode',
      'peks-dictionary-bound',
      'peks-attack',
    ].map((id) => (document.getElementById(id) as HTMLButtonElement | HTMLSelectElement).disabled),
  );
  expect(locked).toEqual([true, true, true, true, true, true, true]);

  // A scripted DOM event can bypass native disabled-control interaction. It
  // must invalidate the in-flight generation just as decisively as a normal
  // post-operation selection change.
  await page.locator('#peks-keyword').evaluate((node) => {
    const select = node as HTMLSelectElement;
    select.value = 'merger';
    select.dispatchEvent(new Event('change', { bubbles: true }));
  });
  // The cancellation signal stops before another expensive guess. The extra
  // interval is a conservative late-result oracle: removing either the abort
  // or the final generation guard makes a stale verdict appear here on CI.
  await page.waitForTimeout(1_000);

  await expect(page.locator('#peks-keyword')).toHaveValue('merger');
  await expect(page.locator('#peks-query-result')).toBeEmpty();
  await expect(page.locator('#peks-repeat-result')).toBeEmpty();
  await expect(page.locator('#peks-attack-progress')).toBeEmpty();
  await expect(page.locator('#peks-attack-result')).toBeEmpty();
  await expect(page.locator('#peks-build')).toBeEnabled();
  await expect(page.locator('#peks-keyword')).toBeEnabled();
  await expect(page.locator('#peks-query')).toBeEnabled();
  await expect(page.locator('#peks-repeat')).toBeDisabled();
  await expect(page.locator('#peks-dictionary-mode')).toBeDisabled();
  await expect(page.locator('#peks-dictionary-bound')).toBeDisabled();
  await expect(page.locator('#peks-attack')).toBeDisabled();
  await expect(page.locator('#peks-attack')).toHaveText('Run bounded offline attack');
  await expect(page.locator('#peks-attack')).toHaveAttribute('aria-busy', 'false');
  // The completed query genuinely reached the server before the local attack;
  // cancelling attacker work must neither invent nor erase that observation.
  await expect(page.locator('#peks-ledger tbody tr')).toHaveCount(1);
});

test('rebuilding retires every verdict and control tied to the previous key', async ({ page }) => {
  await build(page);
  await query(page, 'audit');
  await page.locator('#peks-attack').click();
  await expect(page.locator('#peks-attack-result')).toContainText('KEYWORD RECOVERED');
  const oldPublicKey = await page
    .locator('#peks-roles .value-row:has(.value-label:text-is("public X")) .value-bytes')
    .getAttribute('title');

  await page.locator('#peks-build').click();
  // The click handler retires old state before its first dynamic/import/hash
  // await, so stale evidence is gone even while fresh pairings are in flight.
  await expect(page.locator('#peks-query-result')).toBeEmpty();
  await expect(page.locator('#peks-repeat-result')).toBeEmpty();
  await expect(page.locator('#peks-attack-result')).toBeEmpty();

  await expect(page.locator('#peks-build-status')).toContainText('PUBLIC-KEY TAGS BUILT');
  await expect(page.locator('#peks-query')).toBeEnabled();
  await expect(page.locator('#peks-repeat')).toBeDisabled();
  await expect(page.locator('#peks-dictionary-mode')).toBeDisabled();
  await expect(page.locator('#peks-dictionary-bound')).toBeDisabled();
  await expect(page.locator('#peks-attack')).toBeDisabled();
  await expect(page.locator('#peks-leakage')).toContainText(
    'No PEKS trapdoor has reached the server yet.',
  );
  await expect(page.locator('#peks-ledger')).toHaveCount(0);
  const freshPublicKey = await page
    .locator('#peks-roles .value-row:has(.value-label:text-is("public X")) .value-bytes')
    .getAttribute('title');
  expect(freshPublicKey).not.toBe(oldPublicKey);
});
