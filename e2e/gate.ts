import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Five rules govern everything here, each one a correction of a specific thing
 * the two specs this replaces did.
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The old `settle()` pushed
 *     `animation:none!important; transition:none!important` through
 *     `addStyleTag`, which BYPASSES `styles.css`'s own
 *     `@media (prefers-reduced-motion: reduce)` block instead of exercising it.
 *     The two are not interchangeable: an injected rule cannot fail, whereas the
 *     stylesheet's block is a thing that can be edited wrongly, and the whole
 *     point of a gate is to notice when it is. `boot` asks for the preference
 *     and ASSERTS it took effect.
 *
 *  2. IT FORCE-OPENED EVERY DISCLOSURE FROM SCRIPT. The same `settle()` ran
 *     `document.querySelectorAll('details').forEach(d => d.open = true)`. This
 *     page has six: the intro glossary, the server's complete store, the
 *     overlap-as-numbers table, the attack's input matrix, the challenge's
 *     background knowledge and the scope panel's extension seams. Setting
 *     `.open` bypasses the `<summary>` that is a reader's only route to them,
 *     and — worse here than in most labs — TWO of those six do not EXIST until
 *     the drive has produced observations, so opening "every" `<details>` opened
 *     whichever subset happened to be rendered at the moment it ran. This gate
 *     clicks each summary and asserts the disclosure opened.
 *
 *  3. IT SCANNED ONCE PER DRIVE, AT ONE VIEWPORT. `driveMain()` walked all six
 *     exhibits — stepping the build, searching, running every keyword, drawing
 *     the leakage views, running the attack at 60% noise, scoring the challenge,
 *     timing 50 searches — and then scanned ONCE, at the end. Every state it
 *     built was overwritten by the next click before anything measured it. The
 *     arrival state, where nine of the page's regions are empty prompts and two
 *     buttons ship disabled, was never scanned at all: `driveMain` is called
 *     immediately after `goto`. This gate scans after every one of 30 steps, in
 *     {dark, light} x {1280, 380}.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE, and the companion spec that was
 *     meant to cover the gap did not. `border-contrast.spec.ts` measured
 *     `#app select, #app input[type='text']` — which is EXACTLY the selector
 *     list `--control-border` is applied to, and correctly applied to. Pointing
 *     a 1.4.11 check only at the place a rule is already kept is the same as not
 *     having it. Before this pass `grep -c` put `var(--border)` at 15 uses
 *     against `var(--control-border)` at 1, and `#app button` — every button on
 *     the page — was in the first group, measuring 1.46:1 in dark and 1.43:1 in
 *     light while the spec reported green. That spec has been deleted rather
 *     than repaired: `auditControlBoundaries` below queries every control-shaped
 *     element in `#app`, in both themes, at 27 driven states, and resolves
 *     `color-mix()` through a canvas rather than a regex that throws on it.
 *
 *  5. IT HAD NO REFLOW ORACLE and never opened a phone-width viewport, in a page
 *     built out of `grid-template-columns: 1fr 1fr` splits, three-column
 *     histogram rows and square heatmaps whose side grows with the number of
 *     observed tokens.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 *
 * This page cannot currently be in that shape, and the assertion is what makes
 * that a measurement rather than a reading: `styles.css` declares no
 * `@keyframes` and no `animation` property anywhere, and its reduced-motion
 * block sets only `animation: none` and `transition: none`. The check runs in
 * every state regardless, because all of those are properties of the current
 * stylesheet rather than of the page, and this is the cheapest place to catch
 * the first exception.
 *
 * `aria-hidden` subtrees are excluded. The cost of that exclusion is stated
 * plainly: text removed from the accessibility tree AND painted at zero opacity
 * is not checked here — which on this page means the verdict and badge glyphs,
 * each of which sits beside the words that carry its meaning (see the header of
 * `contrast.ts`).
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. A renderer that throws halfway through leaves an earlier state on
 * screen, and a gate that scans that state reports green for a page that is
 * broken. Attach before `boot`, assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark: the shared bar.
 *
 * Unlike most labs in this fleet, the hero here is NOT inside `<main>` —
 * `index.html` puts `<header class="cl-hero">` directly inside the `<div
 * id="app">`, with `<main id="exhibits">` as its sibling. A `<header>` implies
 * `banner` unless it is scoped inside sectioning content, and a `<div>` is not
 * sectioning content, so the hero WOULD be a second banner. What prevents it is
 * `index.html`'s `dedupeBanner()`, which rewrites its role to `group` on
 * DOMContentLoaded. That is a script, and a script can fail; asserting the
 * OUTCOME rather than either mechanism catches it either way.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page — including the
 * lab's DEFAULTS, which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page.
 *
 * The theme is seeded through `localStorage` rather than by clicking the toggle,
 * which also pins down a real failure mode: `index.html`'s anti-flash script
 * reads `localStorage.getItem('theme')` and the shared bar's toggle writes
 * `localStorage.setItem('theme', …)`. If those keys drift apart the theme
 * silently stops persisting, and this boot fails on `data-theme` rather than
 * quietly scanning dark twice. It also removes a real ordering hazard from the
 * old spec, which reached the light theme by CLICKING the toggle after `goto` —
 * so every light-theme scan measured a page that had been repainted mid-life
 * rather than one that loaded that way.
 *
 * The defaults are asserted at length because THIS LAB SHIPS EMPTY BUT LOOKS
 * BUILT. `initState()` really does build the vault before anything renders, so
 * every hex value on screen is genuine from first paint — but the server's
 * ledger is empty, so nine regions are prompts, the leakage exhibit is a single
 * "not enough observed yet" verdict, and two challenge buttons ship `disabled`.
 * That is the state every reader arrives in, and the gate this replaces called
 * `driveMain()` on the line after `goto` and never once measured it.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the whole
  // test timeout and reports nothing useful. 20s turns that silent hang into a
  // named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
  await assertSingleBanner(page);

  // The reduced-motion block's visible consequence, asserted rather than
  // assumed. `.cl-btn` declares `transition: background .15s, border-color
  // .15s, color .15s` in the shared header's inline <style>; the only thing that
  // can zero it is `styles.css`'s `@media (prefers-reduced-motion: reduce)`
  // block. If the emulation were a no-op this reads `0.15s`.
  expect(
    await page.evaluate(
      () => getComputedStyle(document.querySelector('.cl-btn')!).transitionDuration
    ),
    "reduced motion must cancel the shared bar's transitions"
  ).toBe('0s');

  // `main()` is async — it awaits `initState()`, which does real WebCrypto — so
  // a navigation that resolves proves nothing at all about what is on screen.
  await expect(page.locator('#exhibits > section.panel')).toHaveCount(8);
  await expect(page.locator('#app .cl-hero-title')).toHaveText('Search Vault');

  // ── Exhibit 1 defaults ───────────────────────────────────────────────────
  await expect(page.locator('#build-keyword')).toHaveValue('breach');
  await expect(page.locator('#build-step')).toBeEnabled();
  await expect(page.locator('#build-status')).toHaveText(/^Ready to index "breach"/);
  // Nothing stored yet, and the verdict slot is empty until the build completes.
  await expect(page.locator('#build-verdict')).toBeEmpty();
  await expect(page.getByText('nothing stored yet')).toBeVisible();

  // ── Exhibit 2 defaults: a prefilled box and an EMPTY ledger ──────────────
  await expect(page.locator('#search-input')).toHaveValue('breach');
  await expect(page.locator('#search-outcome')).toBeEmpty();
  await expect(page.getByText('No queries observed yet.')).toBeVisible();

  // ── Exhibit 3: no observations, so one verdict and no charts ─────────────
  await expect(page.getByText('NOT ENOUGH OBSERVED YET')).toBeVisible();
  await expect(page.locator('#leak-views')).toBeEmpty();

  // ── Exhibit 4: the slider ships at zero, i.e. perfect knowledge ──────────
  await expect(page.locator('#attack-noise')).toHaveValue('0');
  await expect(page.locator('#attack-noise-value')).toHaveText('exact');
  await expect(page.locator('#attack-input')).toBeEmpty();
  await expect(page.locator('#attack-result')).toContainText('Press “Run the attack”');

  // ── Exhibit 5: two controls ship DISABLED until a log exists ─────────────
  await expect(page.locator('#challenge-check')).toBeDisabled();
  await expect(page.locator('#challenge-machine')).toBeDisabled();
  await expect(page.locator('#challenge-observe')).toBeEnabled();
  await expect(page.locator('#challenge-outcome')).toBeEmpty();

  // ── Exhibit 6: nothing measured yet ──────────────────────────────────────
  await expect(page.locator('#compare-measurement')).toBeEmpty();

  // Four disclosures exist on arrival — the intro glossary, the server's
  // complete store, the challenge's background knowledge and the scope panel's
  // extension seams. The other two (the overlap-as-numbers table and the
  // attack's input matrix) do not EXIST until there are observations, which is
  // precisely why the old gate's `querySelectorAll('details').forEach(d =>
  // d.open = true)` opened a different set depending on when it ran. Asserting
  // the count is what makes "open this disclosure" mean something later.
  await expect(page.locator('#exhibits details')).toHaveCount(4);
  await expect(page.locator('details[open]')).toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this page is
 * the shape that breaks it: `.split` is `grid-template-columns: 1fr 1fr`, and a
 * bare `1fr` track takes its automatic minimum from its item's MIN-CONTENT, so
 * one long unbreakable value in either column sizes the whole page. The hex
 * columns are the obvious candidate; `.value-bytes` sets `word-break: break-all`
 * precisely to defuse it. Each wide table is meant to scroll inside its own
 * `.scroll-region`; the assertion here is that none of them scrolls the
 * DOCUMENT.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. This page
    // has a decoy behind every one of its ten `.scroll-region`s.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1). If
 * it holds no focusable content it needs `tabindex="0"`, so it becomes a focus
 * target arrow keys can then scroll.
 *
 * `dom.ts`'s `scrollRegion()` already builds every one with `role="region"`,
 * `tabindex="0"` and an `aria-label`, and it is the only route by which a wide
 * table gets onto this page. The assertion stays because the helper is a
 * convention rather than an enforcement, and because the content inside those
 * regions is the evidence for everything the page claims — the encrypted store,
 * the query ledger, the co-occurrence matrices, the attack's per-token results
 * and the challenge board.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * Anything focusable must show WHERE the focus is (WCAG 2.4.7).
 *
 * This is here because `scrollRegion()` hands out `tabindex="0"` freely — ten
 * regions on a fully driven page — and elsewhere in this sweep one such pass
 * made seven regions focusable and left every one of them without a focus
 * indicator, a defect introduced by the fix for another defect.
 *
 * THE `page.keyboard.press('Tab')` BELOW IS THE WHOLE CHECK, not tidying.
 * Chromium only matches `:focus-visible` on a programmatic `focus()` once its
 * heuristic has seen a keyboard interaction, so an unprimed run measures plain
 * `:focus` and reports every correctly-styled region as unstyled. Measured in
 * the sibling repo of this sweep: unprimed, `matches(':focus-visible')` is
 * false and the computed outline style is `none`; after one real Tab it is true
 * and the outline resolves to the declared colour, identical to tabbing there
 * for real. An oracle that cannot tell "no focus ring" from "wrong kind of
 * focus" invents defects.
 */
export async function expectFocusVisible(page: Page, label: string): Promise<void> {
  await page.keyboard.press('Tab');
  const missing = await page.evaluate(() => {
    const snap = (el: Element): string => {
      const cs = getComputedStyle(el);
      return [cs.outlineStyle, cs.outlineWidth, cs.outlineColor, cs.boxShadow, cs.border].join('|');
    };
    const out: string[] = [];
    const active = document.activeElement;
    // Blur first. Without this the element that ALREADY holds focus is snapped
    // with its ring up, focused again (no change), and reported as having no
    // indicator.
    (active as HTMLElement | null)?.blur?.();
    for (const el of Array.from(
      document.querySelectorAll<HTMLElement>('[tabindex]:not([tabindex="-1"])')
    )) {
      if (!el.checkVisibility?.()) continue;
      const before = snap(el);
      el.focus();
      const after = snap(el);
      el.blur();
      if (before === after) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    if (active instanceof HTMLElement) active.focus();
    return Array.from(new Set(out));
  });
  expect(missing, `focusable elements with no visible focus indicator in state: ${label}`).toEqual(
    []
  );
}

/**
 * SC 1.4.11 (non-text contrast) for interactive controls: a control's boundary
 * has to be perceivable against what surrounds it.
 *
 * This is `border-contrast.spec.ts`'s check, kept because it was right, with its
 * AIM corrected — and the correction is the point. That spec queried
 * `#app select, #app input[type='text']`, which is exactly the selector list
 * `styles.css` applies `--control-border` to, and correctly applies it to. It
 * therefore measured the one place the rule was already kept and passed, every
 * time, while `#app button` — every button on this page — drew its edge from
 * `--border`, a SURFACE divider used fifteen times for panel outlines, table
 * rules and the footer hairline, and was never measured against anything. The
 * same self-confirming shape has now been found in a dozen repos in this sweep.
 *
 * The old spec was also arithmetically incomplete in a way that matters here: it
 * compared the border against the element's OWN FILL only. A control whose
 * border is invisible against the PANEL behind it is just as undelineated, and a
 * solid button with no border at all — which is what `button.primary` is — has
 * no border to compare and would score 1:1 on that rule despite being perfectly
 * distinguishable.
 *
 * So a control passes if EITHER
 *   - its fill differs from the surface behind it (how `button.primary` works:
 *     an `--accent` fill on a `--surface` panel), or
 *   - it has a border that stands out from the surface behind it AND from its
 *     own fill (how a `<select>` works: a `--surface-2` fill with a drawn edge).
 * so the score is `max(fill-vs-outside, min(border-vs-outside, border-vs-fill))`.
 *
 * Two deliberate exclusions:
 *  - `disabled` controls. WCAG exempts inactive components, and this page ships
 *    `#challenge-check` and `#challenge-machine` disabled until a log exists.
 *  - anything outside `#app`. The shared top bar is not this lab's to change —
 *    every repo in the fleet carries a byte-identical copy — and its `.cl-btn`
 *    boundary is measured and ratcheted by `nontext.ts` instead, then reported
 *    upward. Written down here so the exclusion is a decision, not an oversight.
 */
export async function auditControlBoundaries(
  page: Page
): Promise<Array<{ sel: string; ratio: number }>> {
  return page.evaluate(() => {
    type C = { r: number; g: number; b: number; a: number };
    // Resolve through a canvas rather than a regex: this palette is full of
    // `color-mix()`, which `getComputedStyle` reports unchanged and which a
    // regex reads as null — landing the walk on the wrong backdrop. The spec
    // this replaces used a `match(/[\d.]+/g)` regex and THREW on any value it
    // could not parse, which is why it could only ever have been pointed at the
    // two selectors whose colours happen to be plain hex.
    const cv = document.createElement('canvas');
    cv.width = cv.height = 1;
    const ctx = cv.getContext('2d', { willReadFrequently: true })!;
    const parse = (s: string): C => {
      if (!s) return { r: 0, g: 0, b: 0, a: 0 };
      ctx.clearRect(0, 0, 1, 1);
      ctx.fillStyle = '#000';
      ctx.fillStyle = s;
      const a = ctx.fillStyle;
      ctx.fillStyle = '#fff';
      ctx.fillStyle = s;
      if (a !== ctx.fillStyle) return { r: 0, g: 0, b: 0, a: 0 };
      ctx.clearRect(0, 0, 1, 1);
      ctx.fillStyle = s;
      ctx.fillRect(0, 0, 1, 1);
      const d = ctx.getImageData(0, 0, 1, 1).data;
      return { r: d[0], g: d[1], b: d[2], a: d[3] / 255 };
    };
    const over = (fg: C, bg: C): C => {
      const a = fg.a + bg.a * (1 - fg.a);
      if (a === 0) return { r: 0, g: 0, b: 0, a: 0 };
      return {
        r: (fg.r * fg.a + bg.r * bg.a * (1 - fg.a)) / a,
        g: (fg.g * fg.a + bg.g * bg.a * (1 - fg.a)) / a,
        b: (fg.b * fg.a + bg.b * bg.a * (1 - fg.a)) / a,
        a,
      };
    };
    const lum = (c: C): number => {
      const f = (v: number): number => {
        const s = v / 255;
        return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
      };
      return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
    };
    const ratio = (a: C, b: C): number => {
      const la = lum(a);
      const lb = lum(b);
      return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
    };
    const backdrop = (start: Element | null): C => {
      const stack: C[] = [];
      for (let n = start; n; n = n.parentElement) {
        const c = parse(getComputedStyle(n).backgroundColor);
        if (c.a > 0) {
          stack.push(c);
          if (c.a >= 1) break;
        }
      }
      let out: C = { r: 255, g: 255, b: 255, a: 1 };
      for (let i = stack.length - 1; i >= 0; i--) out = over(stack[i], out);
      return out;
    };
    const describe = (el: Element): string => {
      const cls = el.getAttribute('class');
      return (
        el.tagName.toLowerCase() +
        (el.id ? `#${el.id}` : '') +
        (cls ? `.${cls.trim().split(/\s+/).join('.')}` : '')
      );
    };

    const out: Array<{ sel: string; ratio: number }> = [];
    const app = document.getElementById('app');
    if (!app) return out;
    app
      .querySelectorAll<HTMLElement>("button, select, textarea, input[type='text']")
      .forEach((el) => {
        const r = el.getBoundingClientRect();
        if (r.width === 0 || r.height === 0) return;
        if ((el as HTMLButtonElement).disabled) return;
        if (el.closest('[hidden]')) return;
        const cs = getComputedStyle(el);
        const outside = backdrop(el.parentElement);
        const fillRaw = parse(cs.backgroundColor);
        const fill = fillRaw.a > 0 ? over(fillRaw, outside) : outside;
        const byFill = ratio(fill, outside);
        let byBorder = 1;
        if (parseFloat(cs.borderTopWidth) > 0 && cs.borderTopStyle !== 'none') {
          const border = over(parse(cs.borderTopColor), fill);
          byBorder = Math.min(ratio(border, outside), ratio(border, fill));
        }
        out.push({
          sel: describe(el),
          ratio: Math.round(Math.max(byFill, byBorder) * 100) / 100,
        });
      });
    return out;
  });
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run. It
 * is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the committed
 * workflow, and a run with it set prints every finding as it happens and then
 * fails at the end, so a green collection run cannot be mistaken for a green
 * gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function soft(fn: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return fn();
  try {
    await fn();
  } catch (e) {
    record(String(e).slice(0, 6000));
  }
}

/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast, and
 * the arithmetic text walk cannot reach a control's boundary or a `::before`
 * glyph, because a pseudo-element is not an element and owns no text node.
 *
 * The backlog is real, so this does not block on it — but a check that merely
 * logs is not a gate. So it ratchets: anything NOT in the baseline fails,
 * anything in the baseline that got WORSE fails, and anything in the baseline
 * that has been FIXED fails until its entry is deleted. That last rule is what
 * stops the allowlist becoming a permanent exemption.
 *
 * It is called from `scan()`, at every driven state. That placement is the whole
 * point: in the reference gate this pattern came from it was reachable only from
 * inside an `if (!COLLECTING) return …` guard, so it never executed in a strict
 * run and every "no new non-text failures" claim was vacuous.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(
        `NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`
      );
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(
        `NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`
      );
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(`WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`);
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Nine assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures, plus three landmark
 *    best-practice rules `withTags` does not run on its own.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those ratios
 *    arithmetically — which matters more here than in most labs, since every
 *    verdict surface and both heatmaps are `color-mix(in oklab, …)` that axe
 *    declines to resolve. Everything else in that bucket is a real result axe
 *    simply could not finish — including `aria-prohibited-attr`, which is where
 *    an `aria-label` on a role-less element hides, a defect that never reaches
 *    the violations array at all. That one is live in shape here: `dom.ts` hands
 *    out `aria-label` from four different helpers (`scrollRegion`, `liveRegion`,
 *    the SVG figure, the challenge selects), and each is legal only because of a
 *    role that is easy to drop by accident.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - non-text contrast for interactive controls — SC 1.4.11; see
 *    `auditControlBoundaries`.
 *  - the 1.4.11 / generated-content ratchet over the whole page, shared bar
 *    included.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - a visible focus indicator on everything given `tabindex` — WCAG 2.4.7.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  // TWO axe runs, deliberately, and this is not a style choice.
  //
  // `AxeBuilder.withTags()` and `AxeBuilder.withRules()` both write the same
  // `options.runOnly` field, so the second call SILENTLY REPLACES the first —
  // the axe-core/playwright source says so in as many words on `withRules`
  // ("Cannot be used with AxeBuilder#withTags"). Chained as
  // `.withTags(TAGS).withRules([...landmark rules])`, axe therefore runs those
  // few best-practice rules and NOT ONE WCAG RULE, while a green result reads
  // exactly like a full A/AA pass. For scale, `withTags(TAGS)` selects 69 of
  // axe-core 4.12's 105 rule definitions; the chained form executes 4.
  //
  // Running the two sets separately and merging is the only way to have both.
  // The landmark rules are still wanted because they are best-practice rather
  // than WCAG-tagged, so `withTags` alone does not reach them — and this page
  // has the exact shape they catch: a shared sticky `<header role="banner">`
  // above a `<div id="app">` holding a second `<header class="cl-hero">` beside
  // `<main id="exhibits">`.
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const landmarks = await new AxeBuilder({ page })
    .withRules(['landmark-no-duplicate-banner', 'landmark-unique', 'landmark-one-main'])
    .analyze();
  const results = {
    violations: [...wcag.violations, ...landmarks.violations],
    incomplete: [...wcag.incomplete, ...landmarks.incomplete],
  };

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  const boundaries = await auditControlBoundaries(page);
  expect(boundaries.length, `no controls found to measure in state: ${label}`).toBeGreaterThan(0);
  const undelineated = Array.from(
    new Set(boundaries.filter((b) => b.ratio < 3).map((b) => `${b.ratio}:1 ${b.sel}`))
  );
  softExpect(undelineated, `control boundaries under 3:1 (SC 1.4.11) in state: ${label}`, []);

  await soft(() => expectNoNewNonTextFailures(page, label));
  await soft(() => expectScrollersReachable(page, label));
  await soft(() => expectFocusVisible(page, label));
  await soft(() => expectNoHorizontalOverflow(page, label));
}

// ── The drive ───────────────────────────────────────────────────────────────

/**
 * Open one `<details>` by clicking its `<summary>`, and assert it opened.
 *
 * Never `d.open = true`. The gate this replaces did exactly that to every
 * disclosure on the page, which both bypasses the only affordance a reader has
 * and — because three of this page's five disclosures do not exist until there
 * are observations — silently opened a different set on every run.
 */
async function openDetails(page: Page, summaryText: string | RegExp): Promise<void> {
  const summary = page.locator('#exhibits details > summary').filter({ hasText: summaryText });
  await expect(summary).toHaveCount(1);
  await summary.click();
  await expect(summary.locator('xpath=..')).toHaveAttribute('open', '');
}

/** Run one search through the real control path and wait for the outcome. */
async function search(page: Page, keyword: string): Promise<void> {
  await page.locator('#search-input').fill(keyword);
  await page.locator('#search-run').click();
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Six things shape this drive:
 *
 *  - THE ARRIVAL STATE IS SCANNED FIRST. Nine regions on this page are empty
 *    prompts until a query has been observed, and two buttons ship `disabled`.
 *    That is the first thing every reader sees, and the gate this replaces
 *    called `driveMain()` on the line after `goto`, so it never measured it.
 *
 *  - THE BUILD IS STEPPED, NOT JUMPED. Exhibit 1's state machine has 3 + 2n
 *    substeps, and the interesting renderings are in the middle: a `.value-row`
 *    that is still `is-pending`, and the `tr.is-new` accent-tinted row that only
 *    exists while the store is still filling. Pressing "Build this keyword" goes
 *    straight past both, which is what the old drive did.
 *
 *  - EVERY VERDICT TONE. The four `.verdict-*` classes each paint their own ink
 *    on an 8% mix of themselves, so each is a different composite and none of
 *    them is measured by measuring another. `ok` is the INDEXED banner, `warn`
 *    is ANSWERED — AND OBSERVED, `info` is NO MATCH and the latency readout, and
 *    `exposed` is the attack landing. All four are driven.
 *
 *  - BOTH ENDS OF THE ATTACK. At 0% background-knowledge error the attack
 *    recovers nearly everything (an `exposed` verdict and a table full of
 *    `badge-alarm` "recovered" rows); dragged to 150% it recovers little, which
 *    is the only route to `badge-ok` "held" rows sitting beside them. The old
 *    drive ran 60% once.
 *
 *  - THE TEARDOWN, WHICH IS ITS OWN STATE. Clearing the server's log does not
 *    just empty Exhibit 2: `onChange` re-renders the leakage views back to a
 *    single verdict, drops the attack's stale result, blanks the challenge
 *    scoreboard and re-disables two buttons. That cascade is the branch where a
 *    stale readout would survive next to an emptied panel, and it is scanned.
 *
 *  - NO FIXED TIMEOUTS. Every exhibit here is real WebCrypto, and every one has
 *    a DOM completion signal — a verdict appearing, a row count, a button
 *    returning from `disabled`. The drive waits on those.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  // The skip link is reached BEFORE anything else, and that ordering is
  // load-bearing rather than stylistic. `expectFocusVisible` — which every
  // `scan` runs — focuses and blurs each `tabindex` element in turn, and
  // Chromium's sequential focus navigation starting point follows the last blur.
  // After one scan, `Tab` resumes from the middle of the document rather than
  // from the top, and this assertion would fail for a page whose skip link is
  // perfectly fine.
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('skip link focused');

  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await scanAt('first paint, every exhibit an empty prompt');

  await openDetails(page, /six words you need/);
  await scanAt('the intro glossary open');

  // ── Exhibit 1: the build, stepped ───────────────────────────────────────
  await page.locator('#build-step').click();
  await expect(page.locator('#build-status')).toHaveText(/^Step 1 of/);
  await scanAt('build step 1 — the keyword revealed, everything else pending');

  await page.locator('#build-step').click();
  await page.locator('#build-step').click();
  await expect(page.locator('#build-status')).toHaveText(/^Step 3 of/);
  await scanAt('build step 3 — token and posting key derived, store still empty');

  await page.locator('#build-step').click();
  await page.locator('#build-step').click();
  // Exactly one row has landed, and it carries the `is-new` accent tint.
  await expect(page.locator('#build-status')).toHaveText(/^Step 5 of/);
  await expect(page.locator('.side-server tbody tr.is-new')).toHaveCount(1);
  await scanAt('build step 5 — the first sealed row lands, tinted as new');

  await page.locator('#build-all').click();
  await expect(page.getByText('INDEXED', { exact: true })).toBeVisible();
  await expect(page.locator('#build-step')).toBeDisabled();
  await expect(page.locator('#build-all')).toBeDisabled();
  await scanAt('build complete — the INDEXED verdict, two controls now disabled');

  await openDetails(page, /complete store/);
  await scanAt("the server's complete store open");

  // Changing the keyword resets the machine, which is the only route back to
  // step 0 with the disclosure still open.
  await page.selectOption('#build-keyword', 'salary');
  await expect(page.locator('#build-status')).toHaveText(/^Ready to index "salary"/);
  await expect(page.locator('#build-step')).toBeEnabled();
  await scanAt('build reset by changing keyword');

  // ── Exhibit 2: search, all three outcomes ───────────────────────────────
  await search(page, 'breach');
  await expect(page.getByText('ANSWERED — AND OBSERVED')).toBeVisible();
  await expect(page.locator('#search-ledger tbody tr')).toHaveCount(1);
  await scanAt('one real search — answered and observed');

  await search(page, 'unicorn');
  await expect(page.getByText('NO MATCH')).toBeVisible();
  await scanAt('a keyword that is not in the index — no match');

  await search(page, '');
  await expect(page.getByText('NOTHING TO SEARCH')).toBeVisible();
  await scanAt('an empty query — nothing to search');

  await page.locator('#search-input').fill('breach');
  await page.locator('#search-run-all').click();
  await expect(page.locator('#search-ledger tbody tr').first()).toBeVisible();
  await expect(page.locator('#leak-views')).not.toBeEmpty();
  await scanAt('every keyword queried once — the flat log');

  // ── Exhibit 3: the three leakage views ──────────────────────────────────
  await expect(
    page.getByRole('heading', { name: 'Query frequency — the search pattern' })
  ).toBeVisible();
  await expect(page.locator('.graph-wrap svg')).toBeVisible();
  await expect(page.locator('table.matrix')).not.toHaveCount(0);
  await scanAt('leakage views drawn from a flat log');

  await openDetails(page, /same graph as numbers/);
  await scanAt('the overlap graph as a table');

  await page.locator('#leak-run-all').click();
  // The realistic round is 33 queries on top of what is already logged; the
  // completion signal is the flat-log warning disappearing.
  await expect(page.getByText(/queried the same number of times/)).toHaveCount(0);
  await expect(page.getByText(/OF THE DATABASE HAS BEEN IN SOME RESULT SET/)).toBeVisible();
  await scanAt('a realistic, skewed round observed');

  // ── Exhibit 4: the attack, at both ends of the noise slider ─────────────
  await openDetails(page, /entire input/);
  await scanAt("the attack's input matrix open");

  await page.locator('#attack-run').click();
  await expect(page.locator('#attack-result table')).toBeVisible();
  await expect(page.locator('#attack-result .badge-alarm').first()).toBeVisible();
  await scanAt('the attack run with exact background knowledge');

  await page.locator('#attack-noise').fill('150');
  await expect(page.locator('#attack-noise-value')).toHaveText('±150%');
  await page.locator('#attack-run').click();
  await expect(page.locator('#attack-result table')).toBeVisible();
  await scanAt("the attack run with the adversary's knowledge degraded");

  // ── Exhibit 5: the challenge, scored both ways ──────────────────────────
  await expect(page.locator('#challenge-check')).toBeEnabled();
  const guesses = page.locator('#challenge-board select');
  await expect(guesses.first()).toBeVisible();
  await guesses.nth(0).selectOption('audit');
  await guesses.nth(1).selectOption('salary');
  await scanAt('two guesses entered on the challenge board');

  await page.locator('#challenge-check').click();
  await expect(page.getByText(/YOU RECOVERED \d+ OF \d+/)).toBeVisible();
  // Both verdict badges appear on the same board: one right, one wrong.
  await expect(page.locator('.challenge-verdict .badge').first()).toBeVisible();
  await scanAt('the challenge checked — per-token verdict badges');

  await page.locator('#challenge-machine').click();
  await expect(page.getByText('THE PATTERN WAS THE SECRET')).toBeVisible();
  await expect(page.locator('.score-block')).toHaveCount(3);
  await scanAt('the machine scored beside you — three score blocks');

  await openDetails(page, /background knowledge/);
  await scanAt('the background-knowledge table open');

  await page.locator('#challenge-clear').click();
  await expect(page.locator('#challenge-outcome')).toBeEmpty();
  await scanAt('guesses cleared, scoreboard withdrawn');

  // ── Exhibit 6: the measured latency ─────────────────────────────────────
  await page.locator('#compare-measure').click();
  await expect(page.getByText(/MS PER SEARCH/)).toBeVisible();
  await scanAt('50 searches timed in this browser');

  // ── The teardown cascade ────────────────────────────────────────────────
  // Clearing the log re-renders four other exhibits through `onChange`. The
  // branch worth measuring is the one where a stale readout could survive next
  // to an emptied panel.
  await page.locator('#search-clear').click();
  await expect(page.getByText('No queries observed yet.')).toBeVisible();
  await expect(page.getByText('NOT ENOUGH OBSERVED YET')).toBeVisible();
  await expect(page.locator('#attack-result')).toContainText('Press “Run the attack”');
  await expect(page.locator('#challenge-check')).toBeDisabled();
  await expect(page.locator('#challenge-machine')).toBeDisabled();
  await scanAt('the log cleared — every dependent exhibit back to its prompt');

  // And the attack's own empty-state verdict, which is a different rendering
  // from the prompt paragraph above it.
  await page.locator('#attack-run').click();
  await expect(page.getByText('NOTHING TO ATTACK YET')).toBeVisible();
  await scanAt('the attack run with nothing to attack');
}
