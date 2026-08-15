/**
 * Known WCAG 1.4.11 / generated-content findings in this lab, captured through
 * the gate's own path so the baseline and the check cannot disagree.
 *
 * THIS FILE IS A TO-DO LIST, NOT A SET OF EXEMPTIONS. The gate ratchets on it:
 *   - a finding NOT listed here fails the run, so a regression cannot land;
 *   - a listed finding whose ratio gets WORSE fails, so the list cannot rot;
 *   - a listed finding that no longer appears ALSO fails, so a fixed entry must
 *     be deleted and the file can only shrink toward empty.
 * The last rule is what stops an allowlist becoming a permanent exemption.
 *
 * `unverified: true` marks an absolutely-positioned pseudo-element. It can paint
 * outside its host and the oracle measures it against the host's backdrop, so
 * that ratio is NOT trustworthy — hand-measure before acting on it.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {
  // What the live oracle finds, over {dark, light} x {1280, 380} and every one
  // of the 27 states the drive builds, is exactly these two — both in the SHARED
  // Crypto Lab top bar, and neither one this repo's to fix.
  //
  // `.cl-btn` draws its edge as
  // `1px solid color-mix(in srgb, var(--accent, #35d6bb) 38%, transparent)` over
  // the bar's fixed `#0b1512`. This lab defines `--accent: #14b8a6`, so the
  // composited edge resolves to that teal at 38%: 2.09:1 against the bar,
  // IDENTICALLY IN BOTH THEMES, because the bar is always dark and the theme
  // does not move it. `--accent` is deliberately NOT darkened for the light
  // theme for exactly this reason — doing so would have pushed this number to
  // about 1.48:1 while fixing a button inside `#app`, which is why the light
  // theme got a separate `--accent-solid` instead. The bar's markup and CSS are
  // a byte-identical copy carried by every repo in the fleet, and `CLAUDE.md` is
  // explicit that a change every lab should get is a reviewed fleet-wide pass
  // and never an overwrite driven from one repo. So it is measured here,
  // ratcheted here, and reported upward.
  //
  // Everything inside `#app` — the hero, all eight exhibit panels and the
  // footer — is audited with no exemption, and after this pass comes back clean.
  'control-boundary|a.cl-btn': { ratio: 2.09, required: 3, unverified: false },
};
