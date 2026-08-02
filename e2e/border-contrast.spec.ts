import { expect, test } from '@playwright/test';

type Rgb = [number, number, number];

function rgb(value: string): Rgb {
  const channels = value.match(/[\d.]+/g)?.map(Number);
  if (!channels || channels.length < 3) throw new Error(`Unsupported color: ${value}`);
  return [channels[0], channels[1], channels[2]];
}

function luminance(channels: Rgb): number {
  const [r, g, b] = channels.map((channel) => {
    const value = channel / 255;
    return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(a: Rgb, b: Rgb): number {
  const [lighter, darker] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (lighter + 0.05) / (darker + 0.05);
}

for (const theme of ['dark', 'light'] as const) {
  test(`form control boundaries retain 3:1 contrast in ${theme} theme`, async ({ page }) => {
    await page.goto('.');
    await page.evaluate((value) => {
      document.documentElement.dataset.theme = value;
    }, theme);

    const controls = page.locator("#app select, #app input[type='text']");
    expect(await controls.count()).toBeGreaterThan(0);
    const styles = await controls.evaluateAll((elements) =>
      elements.map((element) => {
        const style = getComputedStyle(element);
        return [style.borderTopColor, style.backgroundColor] as const;
      }),
    );

    for (const [border, fill] of styles) {
      expect(contrast(rgb(border), rgb(fill))).toBeGreaterThanOrEqual(3);
    }
  });
}
