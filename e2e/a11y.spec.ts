import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches: the arrival state, where nine
 * regions are empty prompts and two controls ship disabled; the skip link
 * focused; the intro glossary opened through its summary; the index build
 * STEPPED, so the pending value rows and the accent-tinted row landing in the
 * server's store are both measured, then completed to the INDEXED verdict, then
 * reset by changing keyword; all three search outcomes — answered-and-observed,
 * no-match, and the empty query; the whole keyword set queried once, then a
 * skewed realistic round; the three leakage views including the SVG overlap
 * graph and both heatmaps; the attack run with exact background knowledge and
 * again with it degraded to 150% error, which is the only route to "held" rows
 * beside "recovered" ones; the challenge board guessed, checked, machine-scored
 * and cleared; 50 real searches timed; and finally the teardown cascade, where
 * clearing the server's log re-renders four other exhibits back to their
 * prompts. Every one of those states is scanned, in both themes, at desktop and
 * phone width.
 *
 * See `gate.ts` for why nothing is injected into the page, why no `<details>` is
 * opened from script, why the theme is seeded rather than toggled, why the lab's
 * defaults are asserted rather than assumed, and why `violations` is not the
 * whole oracle — including what `border-contrast.spec.ts` was actually
 * measuring.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });
}
