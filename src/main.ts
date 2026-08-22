import './style.css';
import { el, withFocusRestored } from './ui/dom';
import { Lab } from './ui/state';
import { renderShelf } from './ui/shelf';
import { renderServerView, resetServerView } from './ui/serverview';
import { renderFold, resetFold } from './ui/fold';
import { renderVersus, resetVersus } from './ui/versus';
import { renderNoise, resetNoise } from './ui/noise';
import { renderScope, resetScope } from './ui/scope';

/**
 * The shell: six tabs, one lab state, and a rule about when panels rebuild.
 *
 * Panels render LAZILY — a tab that has never been opened has an empty panel —
 * and every mounted panel re-renders when the lab's parameters change. That
 * matters more than it sounds: a query built at one modulus is meaningless at
 * another, so every panel that holds one throws it away on a parameter change
 * rather than showing a stale ciphertext beside a new parameter set.
 */

type PanelId = 'shelf' | 'server' | 'fold' | 'versus' | 'noise' | 'scope';

const RENDERERS: Record<PanelId, (root: HTMLElement, lab: Lab) => void> = {
  shelf: renderShelf,
  server: renderServerView,
  fold: renderFold,
  versus: renderVersus,
  noise: renderNoise,
  scope: renderScope,
};

/**
 * Panels that cache a query or a measurement taken under specific parameters.
 *
 * The reason travels with the invalidation so each panel can PRINT why its
 * result went away. A verdict that disappears silently is indistinguishable
 * from one that was never produced, and this page's whole subject is telling
 * those two apart.
 */
function invalidateCaches(reason: string): void {
  resetServerView(reason);
  resetFold(reason);
  resetVersus(reason);
  resetNoise(reason);
  resetScope(reason);
}

async function boot(): Promise<void> {
  const lab = await Lab.create();
  const tabs = Array.from(document.querySelectorAll<HTMLButtonElement>('.tab-btn'));
  const mounted = new Set<PanelId>();

  const stale = new Set<PanelId>();

  const panelFor = (id: PanelId): HTMLElement => {
    const node = document.getElementById(`panel-${id}`);
    if (!node) throw new Error(`missing panel: ${id}`);
    return node;
  };

  /**
   * The panel's render target, and its ONE live region.
   *
   * The live region is created once, before any renderer runs, and lives OUTSIDE
   * the container that gets cleared — because a `role="status"` node that is
   * built fresh on every render, with its text already inside it, announces
   * nothing at all. It has to be present first and change afterwards.
   */
  const bodyFor = (id: PanelId): HTMLElement => {
    const panel = panelFor(id);
    let body = panel.querySelector<HTMLElement>('.panel-body');
    if (!body) {
      panel.appendChild(el('p', { class: 'live-status', role: 'status', 'aria-live': 'polite' }));
      body = el('div', { class: 'panel-body' });
      panel.appendChild(body);
    }
    return body;
  };

  const render = (id: PanelId): void => {
    const panel = panelFor(id);
    withFocusRestored(panel, () => RENDERERS[id](bodyFor(id), lab));
    stale.delete(id);
  };

  const activate = (id: PanelId): void => {
    for (const tab of tabs) {
      const isTarget = tab.dataset.panel === id;
      tab.setAttribute('aria-selected', isTarget ? 'true' : 'false');
      if (isTarget) tab.removeAttribute('tabindex');
      else tab.setAttribute('tabindex', '-1');
      const panel = panelFor(tab.dataset.panel as PanelId);
      if (isTarget) panel.removeAttribute('hidden');
      else panel.setAttribute('hidden', '');
    }
    if (!mounted.has(id)) {
      mounted.add(id);
      render(id);
    } else if (stale.has(id)) {
      // Re-rendered on ARRIVAL, not on the parameter change itself. Rebuilding a
      // hidden panel would encrypt a fresh sixty-four-ciphertext query for a
      // reader who is looking at something else — tens of milliseconds of
      // schoolbook polynomial arithmetic, on the main thread, for no pixels.
      render(id);
    }
  };

  for (const tab of tabs) {
    tab.addEventListener('click', () => activate(tab.dataset.panel as PanelId));
    // Arrow-key navigation is what the ARIA tabs pattern expects; without it a
    // keyboard reader can reach the list but not move inside it.
    tab.addEventListener('keydown', (event) => {
      const index = tabs.indexOf(tab);
      let next = -1;
      if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
      else if (event.key === 'ArrowLeft') next = (index - 1 + tabs.length) % tabs.length;
      else if (event.key === 'Home') next = 0;
      else if (event.key === 'End') next = tabs.length - 1;
      if (next < 0) return;
      event.preventDefault();
      activate(tabs[next].dataset.panel as PanelId);
      tabs[next].focus();
    });
  }

  lab.subscribe((change) => {
    invalidateCaches(change);
    // Mark every mounted panel stale, but re-render only the one on screen.
    // Rebuilding a hidden panel would encrypt a fresh sixty-four-ciphertext
    // query for a reader who is looking at something else.
    for (const id of mounted) stale.add(id);
    const open = tabs.find((t) => t.getAttribute('aria-selected') === 'true');
    if (open) render(open.dataset.panel as PanelId);
  });

  activate('shelf');
}

void boot();
