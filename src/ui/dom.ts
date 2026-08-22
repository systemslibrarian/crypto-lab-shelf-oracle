/** Small DOM helpers. No framework; every panel builds its own nodes. */

type Attrs = Record<string, string | number | boolean | undefined>;
type Child = Node | string | null | undefined | Child[];

/**
 * Create an element with attributes and children.
 *
 * Attributes are set through `setAttribute` rather than assigned as properties,
 * so `aria-*` and `role` land where a screen reader and axe can see them. A
 * `false` or `undefined` value omits the attribute entirely — which matters for
 * `hidden` and `disabled`, where the presence of the attribute is the state.
 */
export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  children: Child = null
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === false) continue;
    node.setAttribute(key, value === true ? '' : String(value));
  }
  append(node, children);
  return node;
}

export function append(parent: Node, children: Child): void {
  if (children === null || children === undefined) return;
  if (Array.isArray(children)) {
    for (const child of children) append(parent, child);
    return;
  }
  parent.appendChild(typeof children === 'string' ? document.createTextNode(children) : children);
}

export function clear(node: Element): void {
  while (node.firstChild) node.removeChild(node.firstChild);
}

/** A card section with a heading. */
export function card(heading: string, children: Child): HTMLElement {
  return el('section', { class: 'card' }, [el('h3', {}, heading), children]);
}

/** A verdict box. Icon, words and colour together — never colour alone. */
export function verdict(
  tone: 'pass' | 'fail' | 'alarm' | 'info',
  text: Child,
  options: { live?: boolean } = {}
): HTMLElement {
  const glyph = { pass: '✓', fail: '✕', alarm: '⚠', info: '·' }[tone];
  return el(
    'div',
    {
      class: `verdict verdict-${tone}`,
      role: options.live ? 'status' : undefined,
      'aria-live': options.live ? 'polite' : undefined,
    },
    [el('span', { class: 'verdict-icon', 'aria-hidden': 'true' }, glyph), el('div', {}, text)]
  );
}

/** A definition list of labelled readouts. */
export function kv(rows: Array<[string, Child]>): HTMLElement {
  const list = el('dl', { class: 'kv' });
  for (const [term, value] of rows) {
    append(list, el('dt', {}, term));
    append(list, el('dd', {}, value));
  }
  return list;
}

/**
 * A scrollable region. WCAG 2.1.1 needs a keyboard route into anything that
 * scrolls, so it gets `tabindex="0"`, a `role` and a name — all three, because
 * an unnamed `role="region"` is reported as an unlabelled landmark.
 */
export function scroller(label: string, children: Child): HTMLElement {
  return el('div', { class: 'table-wrap', tabindex: '0', role: 'group', 'aria-label': label }, children);
}

export function disclose(summary: string, children: Child, open = false): HTMLElement {
  return el('details', { class: 'disclose', open }, [el('summary', {}, summary), children]);
}

/** Bytes with a unit, for the cost tables. */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MiB`;
}

/** Milliseconds with a sensible number of digits. */
export function formatMs(ms: number): string {
  if (ms < 1) return `${ms.toFixed(2)} ms`;
  if (ms < 100) return `${ms.toFixed(1)} ms`;
  return `${Math.round(ms)} ms`;
}

/** Yield to the browser so a long computation can paint a progress line. */
export function nextFrame(): Promise<void> {
  return new Promise((resolve) => {
    requestAnimationFrame(() => resolve());
  });
}
