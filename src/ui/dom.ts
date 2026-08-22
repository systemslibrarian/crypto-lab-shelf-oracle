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

/**
 * A verdict box. Icon, words and colour together — never colour alone.
 *
 * NO `role="status"` HERE, deliberately. Every panel rebuilds its whole subtree
 * on render, so a live region created inside that subtree is a BRAND NEW node
 * with its content already in place — and a screen reader announces changes to a
 * region that was already present, not the arrival of a region that already has
 * text in it. Marking these live would have looked like coverage and announced
 * nothing. Announcements go through `panelStatus`, one persistent region per
 * panel that outlives every render.
 */
export function verdict(tone: 'pass' | 'fail' | 'alarm' | 'info', text: Child): HTMLElement {
  const glyph = { pass: '✓', fail: '✕', alarm: '⚠', info: '·' }[tone];
  return el('div', { class: `verdict verdict-${tone}` }, [
    el('span', { class: 'verdict-icon', 'aria-hidden': 'true' }, glyph),
    el('div', {}, text),
  ]);
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

/**
 * The one live region per panel, and the one thing that survives a re-render.
 *
 * `main.ts` creates a `<p class="live-status" role="status" aria-live="polite">`
 * inside each tabpanel ONCE, before any renderer touches it, and the render
 * container is a sibling that gets cleared. So the region is present in the
 * accessibility tree from first paint and every later write to it is a genuine
 * live update rather than a new node nobody is listening to.
 *
 * It is visible, not visually hidden: the text it carries — how many records are
 * folded, what a retrieval decided, which failure code fired — is exactly what a
 * sighted reader wants at the top of the panel too, and a visually-hidden
 * announcer is a second copy of the truth that can drift from the first.
 */
export function panelStatus(panel: HTMLElement, text: string): void {
  const region = panel.querySelector('.live-status');
  if (region && region.textContent !== text) region.textContent = text;
}

/**
 * Re-render a panel without throwing the keyboard reader back to the top.
 *
 * Every panel rebuilds its subtree from scratch, which destroys the element the
 * reader was standing on — so pressing Enter on a shelf item, or on Fold one
 * record, moved focus to `<body>` and left them re-tabbing from the start of the
 * document. This records enough to find the same control again after the
 * rebuild, and restores focus to it if it still exists.
 *
 * Identity is `data-role` first (stable across renders by design), then
 * `data-index` within the same class, then nothing — a control that genuinely
 * went away does not get focus forced somewhere arbitrary.
 */
export function withFocusRestored(root: HTMLElement, render: () => void): void {
  const active = document.activeElement as HTMLElement | null;
  const inside = !!active && root.contains(active) && active !== root;
  const role = inside ? active.dataset.role : undefined;
  const index = inside ? active.dataset.index : undefined;
  const cls = inside ? active.className : undefined;

  render();

  if (!inside) return;
  let target: HTMLElement | null = null;
  if (role) target = root.querySelector(`[data-role="${attr(role)}"]`);
  else if (index !== undefined && cls) {
    target = root.querySelector(`.${CSS.escape(cls.split(/\s+/)[0])}[data-index="${attr(index)}"]`);
  }
  if (target && typeof target.focus === 'function') target.focus({ preventScroll: true });
}

/**
 * Escape a string for use inside a QUOTED attribute-selector value.
 *
 * NOT `CSS.escape`, which escapes identifiers: it turns the index `11` into
 * `\31 1`, and `[data-index="\31 1"]` matches nothing. Inside quotes only the
 * quote character and the backslash need escaping.
 */
function attr(value: string): string {
  return value.replace(/["\\]/g, '\\$&');
}
