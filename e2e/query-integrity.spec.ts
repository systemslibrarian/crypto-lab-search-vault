import { expect, test } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#integrity-run')).toBeVisible();
});

test('query integrity: the honest current answer verifies', async ({ page }) => {
  await page.locator('#search-input').fill('breach');
  await page.locator('#integrity-mode').selectOption('honest');
  await page.locator('#integrity-run').click();

  const result = page.locator('#integrity-result');
  await expect(result).toContainText('COMPLETE AND CURRENT');
  await expect(result).toContainText('returned postings authenticated');
  await expect(result).toContainText('current snapshot');
});

test('query integrity: omission stays individually authentic but fails completeness', async ({ page }) => {
  await page.locator('#search-input').fill('breach');
  await page.locator('#integrity-mode').selectOption('omit');
  await page.locator('#integrity-run').click();

  const result = page.locator('#integrity-result');
  await expect(result).toContainText('AUTHENTIC BUT INCOMPLETE');
  await expect(result).toContainText('passed AES-GCM authentication');
  await expect(result).toContainText('Per-record authenticity alone did not reveal the omission');
});

test('query integrity: a fabricated posting is rejected independently', async ({ page }) => {
  await page.locator('#search-input').fill('breach');
  await page.locator('#integrity-mode').selectOption('fabricate');
  await page.locator('#integrity-run').click();

  const result = page.locator('#integrity-result');
  await expect(result).toContainText('FABRICATED ANSWER REJECTED');
  await expect(result).toContainText('failed AES-GCM authentication');
  await expect(result).toContainText('full-answer checkpoint also disagreed');
});

test('query integrity: a valid old answer fails freshness', async ({ page }) => {
  await page.locator('#search-input').fill('breach');
  await page.locator('#integrity-mode').selectOption('stale');
  await page.locator('#integrity-run').click();

  const result = page.locator('#integrity-result');
  await expect(result).toContainText('AUTHENTIC BUT STALE');
  await expect(result).toContainText('returned postings still authenticated');
  await expect(result).toContainText('independent current snapshot reference');
});

test('query integrity: unindexed input is refused rather than inventing a checkpoint', async ({ page }) => {
  await page.locator('#search-input').fill('unicorn');
  await page.locator('#integrity-run').click();

  const result = page.locator('#integrity-result');
  await expect(result).toContainText('USE AN INDEXED KEYWORD');
  await expect(result).toContainText('checkpoint table exists only for this snapshot');
});

test('editing the keyword or server behavior retires the old verdict', async ({ page }) => {
  const integrity = page.locator('#integrity-result');
  await page.locator('#integrity-run').click();
  await expect(integrity).toContainText('COMPLETE AND CURRENT');
  await page.locator('#integrity-mode').selectOption('stale');
  await expect(integrity).not.toContainText('COMPLETE AND CURRENT');
  await page.locator('#search-run').click();
  await expect(page.locator('#search-outcome')).toContainText('ANSWERED — AND OBSERVED');
  await page.locator('#search-input').fill('new library keyword');
  await expect(page.locator('#search-outcome')).toBeEmpty();
  await page.locator('#integrity-run').click();
  await expect(integrity).toContainText('USE AN INDEXED KEYWORD');
});

test('the once-per-keyword batch logs each token exactly once', async ({ page }) => {
  await page.locator('#search-run-all').click();
  await expect(page.locator('#search-outcome')).toContainText('BATCH COMPLETE');
  const tokens = await page.locator('#search-ledger tbody tr td:nth-child(2)')
    .evaluateAll(cells => cells.map(cell => cell.getAttribute('title')));
  expect(tokens).toHaveLength(14);
  expect(new Set(tokens).size).toBe(tokens.length);
});

test('an integrity check that finishes after an edit stays retired', async ({ page }) => {
  const delayed = page.locator('#integrity-result');
  await page.evaluate(() => {
    // The honest breach fixture has four encrypted postings. Wait for the old
    // trial to open all four before asserting that its verdict stayed retired.
    const decrypt = crypto.subtle.decrypt.bind(crypto.subtle);
    let opened = 0;
    crypto.subtle.decrypt = async (...args) => {
      const value = await decrypt(...args);
      if (++opened === 4) {
        crypto.subtle.decrypt = decrypt;
        setTimeout(() => { document.body.dataset.oldTrialFinished = 'true'; }, 0);
      }
      return value;
    };
    const original = crypto.subtle.digest.bind(crypto.subtle);
    crypto.subtle.digest = async (algorithm, data) => {
      crypto.subtle.digest = original;
      document.body.dataset.digestPending = 'true';
      await new Promise<void>(resolve => document.addEventListener('finish-test-digest',
        () => resolve(), { once: true }));
      return original(algorithm, data);
    };
  });
  await page.locator('#integrity-run').click();
  await expect(page.locator('body')).toHaveAttribute('data-digest-pending', 'true');
  await page.locator('#search-input').fill('unindexed library word');
  await page.evaluate(() => document.dispatchEvent(new Event('finish-test-digest')));
  await page.locator('#integrity-run').click();
  await expect(delayed).toContainText('USE AN INDEXED KEYWORD');
  await expect(page.locator('body')).toHaveAttribute('data-old-trial-finished', 'true');
  await expect(delayed).not.toContainText('COMPLETE AND CURRENT');
});
