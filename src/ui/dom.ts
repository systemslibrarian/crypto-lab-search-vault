/** Minimal DOM helpers. No framework — the exhibits are small and explicit. */

type Attrs = Record<string, string | number | boolean | undefined>;
type Child = Node | string | null | undefined;

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  applyAttrs(node, attrs);
  append(node, children);
  return node;
}

export function svgEl(tag: string, attrs: Attrs = {}, ...children: Child[]): SVGElement {
  const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
  applyAttrs(node, attrs);
  append(node, children);
  return node;
}

function applyAttrs(node: Element, attrs: Attrs): void {
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === false) continue;
    if (k === 'class') node.setAttribute('class', String(v));
    else if (k === 'text') node.textContent = String(v);
    else node.setAttribute(k, v === true ? '' : String(v));
  }
}

function append(node: Element, children: Child[]): void {
  for (const c of children) {
    if (c === null || c === undefined) continue;
    node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  }
}

export function clear(node: Element): void {
  while (node.firstChild) node.removeChild(node.firstChild);
}

/** A standard exhibit shell: numbered label, heading, lede, and a body. */
export function panel(num: string, heading: string, lede: string): {
  section: HTMLElement;
  body: HTMLElement;
} {
  const body = el('div');
  const section = el(
    'section',
    { class: 'panel', 'aria-labelledby': `h-${slug(heading)}` },
    el('span', { class: 'panel-num', text: num }),
    el('h2', { id: `h-${slug(heading)}`, text: heading }),
    el('p', { class: 'panel-lede', text: lede }),
    body,
  );
  return { section, body };
}

export function slug(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
}

/** A scrollable region axe will accept: focusable, labelled, and a landmark. */
export function scrollRegion(label: string, ...children: Child[]): HTMLElement {
  return el(
    'div',
    { class: 'scroll-region', tabindex: '0', role: 'region', 'aria-label': label },
    ...children,
  );
}

/** Verdict block — always icon + text + colour, never colour alone. */
export function verdict(
  tone: 'ok' | 'exposed' | 'info' | 'warn',
  icon: string,
  title: string,
  detail: string,
): HTMLElement {
  return el(
    'div',
    { class: `verdict verdict-${tone}` },
    el('span', { class: 'verdict-icon', 'aria-hidden': 'true', text: icon }),
    el(
      'div',
      { class: 'verdict-body' },
      el('div', { class: 'verdict-title', text: title }),
      el('div', { text: detail }),
    ),
  );
}

export function badge(
  tone: 'ok' | 'alarm' | 'warn' | 'info',
  icon: string,
  label: string,
): HTMLElement {
  return el(
    'span',
    { class: `badge badge-${tone}` },
    el('span', { 'aria-hidden': 'true', text: icon }),
    label,
  );
}

/** A live region for asynchronous results (WCAG 4.1.3). */
export function liveRegion(label: string): HTMLElement {
  return el('div', { role: 'status', 'aria-live': 'polite', 'aria-label': label });
}

export function labelled(labelText: string, control: HTMLElement): HTMLElement {
  const id = control.id || `c-${slug(labelText)}`;
  control.id = id;
  return el(
    'div',
    { class: 'control-group' },
    el('label', { for: id, text: labelText }),
    control,
  );
}

/** Shorten a hex string for display without ever implying truncated bytes are
 *  the whole value — the full value stays in the title attribute. */
export function shortHex(hex: string, keep = 12): string {
  return hex.length <= keep * 2 ? hex : `${hex.slice(0, keep)}…${hex.slice(-4)}`;
}
