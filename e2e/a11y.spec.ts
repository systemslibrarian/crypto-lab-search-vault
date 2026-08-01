import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function settle(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{animation:none!important;transition:none!important}`,
  });
  await page.evaluate(() => {
    document.querySelectorAll('details').forEach((d) => ((d as HTMLDetailsElement).open = true));
  });
}

/**
 * Drive every exhibit into its richest post-interaction state. Axe only checks
 * what is in the DOM, so each dynamic region — the stepper's final verdict, the
 * populated ledger, the three leakage charts, the attack's per-token table with
 * both "recovered" and "held" badges, the challenge scoreboard, and the timing
 * readout — has to be on screen before the scan.
 */
async function driveMain(page: Page): Promise<void> {
  // Exhibit 1 — step partway, then finish the build.
  await page.locator('#build-keyword').selectOption('contract');
  await page.locator('#build-step').click();
  await page.locator('#build-step').click();
  await page.locator('#build-all').click();
  await expect(page.getByText('INDEXED', { exact: true })).toBeVisible();

  // Exhibit 2 — one real search, then a full round so the ledger fills.
  await page.locator('#search-input').fill('breach');
  await page.locator('#search-run').click();
  await expect(page.getByText('ANSWERED — AND OBSERVED')).toBeVisible();
  await page.locator('#search-run-all').click();

  // Exhibit 3 — the three leakage views.
  await page.locator('#leak-run-all').click();
  await expect(page.getByRole('heading', { name: 'Query frequency — the search pattern' })).toBeVisible();
  await expect(page.locator('.graph-wrap svg')).toBeVisible();

  // Exhibit 4 — degrade the adversary's knowledge so the results table shows
  // both a recovered token and a token that held.
  await page.locator('#attack-noise').fill('60');
  await page.locator('#attack-run').click();
  await expect(page.locator('#attack-result table')).toBeVisible();

  // Exhibit 5 — answer some tokens, score them, then run the machine.
  await page.locator('#challenge-observe').click();
  const guesses = page.locator('#challenge-board select');
  await guesses.nth(0).selectOption('audit');
  await guesses.nth(1).selectOption('salary');
  await page.locator('#challenge-check').click();
  await expect(page.getByText(/YOU RECOVERED \d+ OF \d+/)).toBeVisible();
  await page.locator('#challenge-machine').click();
  await expect(page.getByText('THE PATTERN WAS THE SECRET')).toBeVisible();

  // Exhibit 6 — the measured latency readout.
  await page.locator('#compare-measure').click();
  await expect(page.getByText(/MS PER SEARCH/)).toBeVisible();

  await settle(page);
}

/**
 * The other branch of every conditional render: the empty states and the
 * miss path. These are separate DOM, so they need their own scan.
 */
async function driveEdges(page: Page): Promise<void> {
  await page.locator('#search-input').fill('unicorn');
  await page.locator('#search-run').click();
  await expect(page.getByText('NO MATCH')).toBeVisible();

  await page.locator('#search-clear').click();
  await expect(page.getByText('No queries observed yet.')).toBeVisible();
  await expect(page.getByText('NOT ENOUGH OBSERVED YET')).toBeVisible();

  await page.locator('#attack-run').click();
  await expect(page.getByText('NOTHING TO ATTACK YET')).toBeVisible();

  await settle(page);
}

async function scan(page: Page): Promise<void> {
  const { violations } = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  expect(
    violations.map((v) => ({
      id: v.id,
      impact: v.impact,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
    })),
  ).toEqual([]);
}

async function toLight(page: Page): Promise<void> {
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
}

test('no WCAG A/AA violations — dark theme, every exhibit driven', async ({ page }) => {
  await page.goto('.');
  await driveMain(page);
  await scan(page);
});

test('no WCAG A/AA violations — light theme, every exhibit driven', async ({ page }) => {
  await page.goto('.');
  await toLight(page);
  await driveMain(page);
  await scan(page);
});

test('no WCAG A/AA violations — dark theme, empty and miss states', async ({ page }) => {
  await page.goto('.');
  await driveEdges(page);
  await scan(page);
});

test('no WCAG A/AA violations — light theme, empty and miss states', async ({ page }) => {
  await page.goto('.');
  await toLight(page);
  await driveEdges(page);
  await scan(page);
});
