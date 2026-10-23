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
