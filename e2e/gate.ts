import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };
/**
 * A HEADROOM probe, deliberately narrower than the 320 CSS px WCAG 1.4.10 asks
 * for. Scanning AT 320 does not work: a sibling lab in this batch shipped a
 * defect whose min-content floor was 318px, so it fit at 320 and failed at 380
 * only once Linux font metrics in CI inflated it — a single-width check cannot
 * see a floor sitting just under that width. 280 asserts the floor is low
 * enough that no font-metric delta can push it back over 320.
 */
export const REFLOW = { width: 280, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Five rules govern everything here, and each one corrects something the gate
 * this replaces did:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The old spec pushed
 *     `animation:none!important; transition:none!important` through
 *     `addStyleTag`. That BYPASSES this lab's own
 *     `@media (prefers-reduced-motion: reduce)` block instead of exercising it,
 *     so the one rendering a reduced-motion reader actually gets — every
 *     `.btn`, `.tab-btn`, `.shelf-item`, `.ct-tile` and `.meter-fill`
 *     transition cancelled by the stylesheet's own rule — was never once the
 *     rendering that got scanned. This gate sets the
 *     preference through `emulateMedia`, asserts from inside the page that it
 *     took effect (`test.use({ reducedMotion })` silently does nothing on
 *     Playwright 1.61.1), and injects nothing.
 *
 *  2. IT FORCED EVERY PANEL VISIBLE FROM SCRIPT. The old drive stripped every
 *     `[hidden]` attribute and set every `<details>.open` by JS before its only
 *     scan. Stripping `hidden` puts all six tabpanels on screen AT ONCE — a
 *     rendering no reader can reach and axe then scans instead of the real one
 *     — and script-opening the disclosures means the SHUT state, which is what
 *     every reader arrives at, was never scanned at all. This gate switches
 *     tabs by clicking them and opens each of the five `details.disclose`
 *     panels through its `<summary>`, which is the route a reader has, and
 *     scans before and after.
 *
 *  3. IT DROVE BLIND AND THEN THREW THE STATES AWAY. The old drive clicked
 *     every button whose label matched a regex, swallowed every failure with
 *     `.catch(() => {})`, waited a fixed 120ms per tab, and scanned ONCE at the
 *     end — so the exhausted-budget verdict, the four failure-code readouts,
 *     the collusion alarm and the fold stepper's intermediate states were all
 *     overwritten before anything measured them, and a click that silently did
 *     nothing looked identical to one that worked. This drive names every
 *     control it touches, asserts a real completion signal after each, and
 *     scans after every step, at 1280px and again at 380px.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`. The surfaces that carry
 *     this lab's meaning — all four `.verdict-*` tones, all three `.pill`
 *     states, the `.callout-danger` / `.callout-caveat` scoping warnings, the
 *     `.ct-tile[data-mark]` hit/miss/folded fills, the `.cl-hero-why` accent
 *     wash and the shared top bar's ink — are all `color-mix()` fills axe files
 *     under `incomplete` rather than judging. So is an `aria-label` on a
 *     role-less element.
 *
 *  5. IT HAD NO REFLOW, NON-TEXT-CONTRAST OR GENERATED-CONTENT ORACLE. The old
 *     spec hand-rolled one luminance check over two input selectors, reading
 *     the DECLARED `border-top-color` and `background-color` — blind to
 *     `color-mix()`, to composited backdrops, to every `.btn`, `.tab-btn`,
 *     `.shelf-item` and `.ct-tile`, and to all states past first paint.
 *     `nontext.ts` replaces it with a measured oracle over every control at
 *     every driven state, and `expectNoHorizontalOverflow` adds the 1.4.10
 *     check axe has no rule for.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Two rAFs are not enough. A transition sampled mid-flight has a colour that
 * exists in no state of the page, and axe will happily report it: elsewhere in
 * this fleet that produced a phantom 2.00:1 failure on a button whose settled
 * ratio is 9:1. Transitions also drain in waves rather than in one batch, so a
 * poll for "nothing running right now" can exit through a gap between waves —
 * hence six consecutive quiet frames rather than one.
 *
 * Bounded three ways, because a gate that can hang is a gate nobody runs:
 * animations that never finish (`iterations: Infinity`) are excluded from the
 * quiescence test rather than waited on, a wall-clock budget inside the page
 * gives up and proceeds, and Playwright's own timeout is the backstop.
 *
 * Under the reduced motion this gate asserts, `style.css`'s reduced-motion
 * block cancels every transition this lab declares, so `getAnimations()` is
 * normally empty and this returns on the sixth frame. It
 * stays because the shared top bar's `.cl-btn` transitions are declared
 * OUTSIDE the lab's `@media` block — `* { transition: none !important }` wins
 * today, but that is a property of the current stylesheet, not of the page.
 */
export async function settle(page: Page, budgetMs = 4000): Promise<void> {
  await page.waitForFunction(
    (budget: number) => {
      const w = window as unknown as { __quietFrames?: number; __settleStart?: number };
      if (w.__settleStart === undefined) w.__settleStart = performance.now();
      const done = (): boolean => {
        w.__quietFrames = 0;
        w.__settleStart = undefined;
        return true;
      };
      const running = document.getAnimations().filter((a) => {
        if (a.playState !== 'running') return false;
        const timing = a.effect?.getComputedTiming?.();
        // An infinite decorative animation never drains; waiting on it hangs.
        return timing?.iterations !== Infinity;
      });
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      if (w.__quietFrames >= 6) return done();
      if (performance.now() - (w.__settleStart ?? 0) > budget) return done();
      return false;
    },
    budgetMs,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set. This lab
 * deliberately has no such shape — it declares no `@keyframes` at all, and
 * nothing reaches its visible state THROUGH an animation, so its reduced-motion
 * block only shortens colour and width transitions on elements already fully
 * painted. This assertion is what makes that a measurement rather than a
 * reading of the stylesheet, and it is what would fail the day someone adds a
 * fade-in reveal.
 *
 * `aria-hidden` subtrees are excluded; what this lab hides is decorative
 * verdict/pill glyphs beside their own words and the `#n` tile labels already
 * carried by each tile's `aria-label` — see `contrast.ts`.
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
 * is created. Every panel here renders synchronously at first activation, so a
 * renderer that throws leaves that tabpanel EMPTY — and an empty region is
 * exactly what a scan reports as perfectly accessible. Attach before `boot`,
 * assert after the drive.
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
 * Exactly one banner landmark.
 *
 * The shared `.cl-topbar` carries an explicit `role="banner"`. This lab's own
 * hero is a `<div class="cl-hero">`, not a `<header>`, so nothing here implies
 * a second banner today — but the shared bar's `dedupeBanner()` exists because
 * other labs in this fleet DID ship one, and the hero markup is the part of
 * this page most likely to be re-templated from a lab that uses `<header>`.
 * Asserting the OUTCOME rather than the markup is what catches that edit.
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
 * List semantics survive their styling.
 *
 * This lab's `<ul>` lists — the failure-code roll-call and the forward-links
 * list — are styled `list-style: none`, which is exactly the declaration that
 * makes Safari and VoiceOver DROP the list's implicit role, so both carry an
 * explicit `role="list"` with `role="listitem"` children. Its grid "lists" (the
 * shelf, the two tile grids) are `<div role="list">` wrappers for the same
 * reason. What is asserted is therefore the SHAPE of that fix: any explicit
 * role on a `ul`/`ol` must be `list` (any other value orphans every `<li>`
 * under it), and a `role="list"` must never sit on an empty element, because
 * axe applies `aria-required-children` to the explicit role and fails it the
 * day a list renders with no items. Roles are assigned through an
 * element-creation helper, so ask the DOM rather than grepping the source.
 */
export async function assertListSemantics(page: Page): Promise<void> {
  // TWO selectors, because the two rules have different scopes and an earlier
  // form of this checked only the first while its own documentation described
  // the second. `ul[role], ol[role]` cannot match a `<div role="list">`, which is
  // what all three tile grids on this page are.
  const broken = await page.$$eval('ul[role], ol[role], [role="list"]', (els) =>
    els
      .filter((e) => {
        const role = e.getAttribute('role');
        const isNativeList = e.tagName === 'UL' || e.tagName === 'OL';
        // An explicit non-list role on a <ul>/<ol> orphans every <li> under it.
        if (isNativeList && role !== 'list') return true;
        // Any role="list" with no children fails axe's aria-required-children
        // the day its contents render empty.
        return role === 'list' && e.children.length === 0;
      })
      .map(
        (e) =>
          `${e.tagName.toLowerCase()}[role=${e.getAttribute('role')}] with ${e.children.length} children`
      )
  );
  expect(
    broken,
    'an explicit non-list role on a list deletes its semantics; an empty role="list" fails aria-required-children'
  ).toEqual([]);
}

/**
 * Load the page with reduced motion actually in effect, and assert the content
 * every scan relies on is really on the page — including the lab's DEFAULTS,
 * which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.x, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page. Nothing in this lab's JS branches on
 * `matchMedia`, but the CSS reduced-motion block is the only thing standing
 * between a scan and a mid-flight transition colour, so the assertion is the
 * difference between scanning the reduced-motion rendering and believing we did.
 *
 * DARK IS THE ONLY THEME. `index.html` writes `localStorage.theme = 'dark'` and
 * stamps `data-theme="dark"` on `<html>` before first paint, and there is no
 * toggle anywhere. This boot seeds the key to `'light'` on purpose and then
 * asserts the attribute is `dark` regardless — which is a real check, not a
 * formality: it proves the anti-flash script OVERWRITES a stored preference
 * rather than reading it, which is the behaviour the fleet standard asks for
 * and the one that a returning visitor with an old `light` in storage depends
 * on.
 *
 * The defaults are asserted at length because `main.ts` renders each tabpanel
 * LAZILY on first activation. A navigation that resolves proves nothing: a
 * renderer that threw would leave its panel empty, and an empty region is
 * exactly what a scan reports as perfectly accessible.
 */
export async function boot(page: Page): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful. 30s turns that silent hang
  // into a named failure naming the locator. It is generous because a single
  // click here can be sixty-four RLWE encryptions.
  page.setDefaultTimeout(30_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript(() => localStorage.setItem('theme', 'light'));
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  expect(
    await page.evaluate(() => localStorage.getItem('theme')),
    "the anti-flash script must OVERWRITE a stored 'light', not read it"
  ).toBe('dark');
  await assertSingleBanner(page);
  await assertListSemantics(page);

  // ── The page really rendered ────────────────────────────────────────────
  await expect(page.locator('main')).toHaveCount(1);
  await expect(page.locator('h1')).toHaveCount(1);
  await expect(page.locator('h1')).toHaveText('Shelf Oracle');
  await expect(page.locator('.tab-btn')).toHaveCount(6);

  // The shared skip link points at an id that exists. axe's skip-link rule is
  // best-practice, not WCAG-tagged, so `withTags` never runs it — a skip link
  // aimed at a missing element is exactly the kind of thing a green axe run
  // says nothing about.
  await expect(page.locator('a.cl-skip-link')).toHaveAttribute('href', '#app');
  await expect(page.locator('#app')).toHaveCount(1);

  // This lab ships NO theme control of its own, and the shared bar no longer
  // carries one. The shared CSS hides any lab toggle with
  // `display:none !important`, which would leave a dead-but-known element;
  // asserting the count at zero catches the day one is added without going
  // through that list.
  await expect(
    page.locator('#theme-toggle, #themeToggle, .theme-toggle, .theme-toggle-btn, [data-theme-toggle]')
  ).toHaveCount(0);
  await expect(page.locator('#cl-theme-toggle')).toHaveCount(0);

  // ── The arrival state: The Shelf active, five panels unrendered ─────────
  // Every panel is rendered lazily, so the other five are hidden AND EMPTY
  // until their tab is first activated — asserted, because "empty" is this
  // lab's tell that a renderer threw (see `watchPageErrors`).
  await expect(page.locator('#panel-shelf .shelf-item')).toHaveCount(64);
  await expect(page.locator('#panel-shelf .shelf-item[aria-pressed="true"]')).toHaveCount(1);
  await expect(page.locator('#panel-shelf .shelf-item').first()).toHaveAttribute(
    'aria-pressed',
    'true'
  );
  for (const id of ['server', 'fold', 'versus', 'noise', 'scope']) {
    await expect(page.locator(`#panel-${id}`)).toBeHidden();
    await expect(page.locator(`#panel-${id}`)).toBeEmpty();
  }

  // ── Every shipped control default ───────────────────────────────────────
  await expect(page.locator('#shelf-record-size')).toHaveValue('512');
  await expect(page.locator('#shelf-size')).toHaveValue('64');

  // ── Disclosures ship shut ───────────────────────────────────────────────
  await expect(page.locator('#panel-shelf details[open]')).toHaveCount(0);
  await expect(page.locator('#panel-shelf details.disclose')).toHaveCount(1);

  await settle(page);
  await expectNotBlank(page, 'first paint');
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all. This lab's long
 * values are hex runs and serialized ciphertext heads inside `.code` and
 * `.ct-tile`, which rely on `overflow-wrap: anywhere`; its five wide tables
 * live inside `.table-wrap { overflow-x: auto }` scrollers, which is the
 * sanctioned way to hold a wide table without pushing the document sideways.
 * So the shapes at risk are a new unwrapped run outside a scroller, or a grid
 * whose automatic minimum size is the min-content of a long line. At 380px that
 * is precisely what this check exists to catch — and note the `clipped()` test
 * below, which is what keeps a legitimately-wide table INSIDE a scroller from
 * being reported.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element.
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
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 *
 * This lab has five real scrollers — every `.table-wrap` around the packing
 * table, the head-to-head comparison, the predicted-budget table, the observer
 * log and the what-is-hidden table — and each is built by the `scroller()`
 * helper, which gives it `tabindex="0"`, `role="group"` and an `aria-label`
 * together. So this assertion is LIVE here rather than vacuous, and it is what
 * catches a wide table added by hand instead of through that helper. A scroller
 * born without a keyboard route is invisible to axe.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY);
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
 * Nothing may be focusable while it paints nothing (WCAG 2.4.3 / 2.4.7).
 *
 * `opacity: 0` with `pointer-events: none` is NOT hiding: the element keeps
 * `tabIndex: 0`, so a keyboard reader tabs to a control that is not on screen
 * and the focus ring lands nowhere. `display: none` and `visibility: hidden`
 * DO remove an element from the tab order, so those are skipped rather than
 * flagged — the failure is specifically the invisible-but-tabbable pair. The
 * `hidden` tabpanels here take the `display: none` route, which is why the
 * five inactive panels' worth of controls — up to 64 tiles apiece — are
 * legitimately absent from the tab order.
 *
 * Off-screen-but-focusable is the WCAG-sanctioned skip-link idiom and is
 * deliberately not flagged: the shared skip link parks at `top:-3rem` with
 * full opacity and slides in on focus. The drive scans it focused.
 */
export async function expectNoInvisibleFocusTargets(page: Page, label: string): Promise<void> {
  const bad = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll<HTMLElement>(FOCUSABLE))) {
      if (el.tabIndex < 0) continue;
      // display:none / visibility:hidden already remove it from the tab order.
      if (!el.checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      for (let n: Element | null = el; n; n = n.parentElement) {
        effective *= parseFloat(getComputedStyle(n).opacity);
      }
      const r = el.getBoundingClientRect();
      if (effective !== 0 && r.width > 0 && r.height > 0) continue;
      // Confirm it really is reachable rather than inferring it.
      const before = document.activeElement;
      el.focus();
      const took = document.activeElement === el;
      (before as HTMLElement | null)?.focus?.();
      if (took) {
        out.push(
          `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}.${(el.getAttribute('class') ?? '').trim()}` +
            ` (opacity ${effective}, ${Math.round(r.width)}x${Math.round(r.height)})`
        );
      }
    }
    return Array.from(new Set(out));
  });
  expect(bad, `focusable elements that paint nothing in state: ${label}`).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run.
 * It is a debugging aid only: `A11Y_COLLECT` is never set in CI, and a run
 * with it set prints every finding as it happens and then fails at the end, so
 * a green collection run cannot be mistaken for a green gate.
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
    // Generous, not 900: a truncated oracle dump is how a second and third
    // finding in the same state get missed on a collection pass.
    record(String(e).slice(0, 6000));
  }
}

/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no
 * text node.
 *
 * IT IS CALLED FROM `scan()`, deliberately and not by accident. Fleet-wide
 * this oracle had been called from inside a soft wrapper AFTER its
 * `if (!COLLECTING) return` guard — so in a strict run, which is every run in
 * CI and every run anyone reads as a pass, the guard returned first and
 * `nontext.ts` never executed at all. Thirteen repos certified themselves
 * clean on an oracle that had never looked. Calling it here means it runs at
 * every driven state, including `:hover`, and this repo's baseline was
 * captured by that live path.
 *
 * A check that merely logs is not a gate, so it ratchets: anything NOT in the
 * baseline fails, anything in the baseline that got WORSE fails, and anything
 * in the baseline that has been FIXED fails until its entry is deleted. That
 * last rule is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(`WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`);
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the
 * point — or the drive stopped reaching the state that shows it, which is a
 * coverage regression worth knowing about. Call once, after `driveAllStates`.
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
 *  - `violations` — the usual WCAG A/AA rule failures, plus four landmark
 *    best-practice rules `withTags` does not run on its own.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically — which matters here because the surfaces carrying
 *    this lab's meaning are `color-mix()` fills axe cannot resolve: all four
 *    verdict tones, all three pill states, the danger/caveat callouts, the
 *    tile `data-mark` states, the hero aside and the shared bar's ink.
 *    Everything else in that bucket is a real result axe simply could not
 *    finish — including `aria-prohibited-attr`, which is where an `aria-label`
 *    on a role-less element hides. This page leans on getting that right:
 *    every `.table-wrap` scroller pairs its `aria-label` with `role="group"`,
 *    and the `.meter` pairs its `aria-label` and `aria-valuetext` with
 *    `role="meter"`. Drop any of those roles and the label is silently
 *    discarded.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - the same walk over `aria-hidden` content with the exemption lifted —
 *    SC 1.4.3 is about what a reader SEES; see `contrast.ts` for what this
 *    lab hides and why it is measured anyway.
 *  - non-text contrast and generated content — SC 1.4.11, ratcheted; see
 *    `expectNoNewNonTextFailures`. This is the only oracle that judges a
 *    control's boundary against the surface OUTSIDE it.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - no focusable element that paints nothing — WCAG 2.4.3/2.4.7.
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
  // `.withTags(TAGS).withRules([...4 landmark rules])`, axe runs those FOUR
  // best-practice rules and NOT ONE WCAG RULE, while a green result reads
  // exactly like a full A/AA pass. For scale, `withTags(TAGS)` selects 69 of
  // axe-core 4.12's 105 rule definitions; the chained form executes 4.
  //
  // The landmark four are still wanted because they are best-practice rather
  // than WCAG-tagged, so `withTags` alone does not reach them — and this page
  // has exactly the shape they catch: a sticky `<header role="banner">` above a
  // `<div id="app">` holding an `<aside class="cl-hero-why">`, two `<nav>`s
  // (the shared actions and the tablist wrapper), one `<main>` and a `<footer>`.
  // The hero is a `<div>` rather than a `<header>` precisely so that aside stays
  // top level; `landmark-complementary-is-top-level` is the rule that would
  // catch a regression there, and it only runs in this second call.
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const landmarks = await new AxeBuilder({ page })
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
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

  // The `incomplete` bucket is asserted, not skimmed. `aria-prohibited-attr`
  // and `aria-required-children` appear ONLY here — never in `violations` — so
  // a gate that ignores this bucket cannot see either. Only `color-contrast`
  // is allowed to remain, and only because the arithmetic walk below judges
  // those ratios for real; no other rule is filtered out.
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

  // The aria-hidden walk, exemption lifted — axe skips this text entirely and
  // the default walk honours the same boundary, so this second call is the
  // ONLY thing that ever measures it. See `contrast.ts` for the inventory.
  const hiddenContrast = Array.from(
    new Set(
      formatContrastFailures(
        await auditContrast(page, '[aria-hidden="true"], [aria-hidden="true"] *', true)
      )
    )
  );
  softExpect(hiddenContrast, `measured aria-hidden contrast failures in state: ${label}`, []);

  await soft(() => expectNoNewNonTextFailures(page, label));
  await soft(() => expectScrollersReachable(page, label));
  await soft(() => expectNoInvisibleFocusTargets(page, label));
  await soft(() => expectNoHorizontalOverflow(page, label));
}

// ── The drive ───────────────────────────────────────────────────────────────

/** Switch to a tab by clicking it, and prove the switch happened. */
async function openTab(page: Page, name: RegExp, panelId: string): Promise<void> {
  await page.getByRole('tab', { name }).click();
  await expect(page.getByRole('tab', { name })).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator(panelId)).toBeVisible();
  await expect(page.locator(panelId)).not.toBeEmpty();
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Five things shape this drive:
 *
 *  - THE ARRIVAL STATE IS SCANNED FIRST, exactly as a reader gets it: The Shelf
 *    active with position 0 selected, five panels hidden and unrendered, the
 *    one disclosure shut. The gate this replaces force-revealed all of it
 *    before its only scan.
 *
 *  - EVERY PANEL IS RENDERED LAZILY, so a tab that is never clicked is a panel
 *    that is never even IN the DOM. Each of the six is activated through its
 *    real tab button and scanned in its own driven states.
 *
 *  - EVERY FAILURE AND ALARM STATE. The exhausted-budget verdict, all four
 *    failure codes, the collusion recovery, the deliberately-broken encryption
 *    mode and the distinguisher's saturated result are each reached by pressing
 *    the control that causes them, and each is scanned. None of them is
 *    reachable without doing something on purpose, and none had ever been
 *    scanned by a gate that only looked at first paint.
 *
 *  - HOVER IS A STATE, AND IT PERSISTS AFTER A CLICK. `:hover` stays on the
 *    element under the pointer after `page.click()` resolves, so it is the state
 *    a reader occupies the instant after pressing a button — and `.btn:hover`,
 *    `.tab-btn:hover`, `.shelf-item:hover`, `.ct-tile:hover` and `.cl-btn:hover`
 *    all repaint their fill as a `color-mix()`. Each is scanned explicitly.
 *
 *  - NO FIXED TIMEOUTS. Every wait is on a real DOM completion signal: a verdict
 *    appearing, a progress line's wording, a failure code, `aria-selected`. That
 *    matters more here than in most labs, because a single click can be sixty-
 *    four RLWE encryptions and a fixed wait would either race it or waste a
 *    minute per state.
 */
export async function driveAllStates(page: Page, label: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${label} / ${s}`);

  await scanAt('arrival: The Shelf active, five panels unrendered, the disclosure shut');

  // ── The shared skip link, focused ───────────────────────────────────────
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('the shared skip link focused, slid in from top:-3rem');

  // ── The Shelf ───────────────────────────────────────────────────────────
  await page.locator('#panel-shelf .shelf-item').nth(5).click();
  await expect(page.locator('#panel-shelf .shelf-item').nth(5)).toHaveAttribute(
    'aria-pressed',
    'true'
  );
  await expect(page.locator('#panel-shelf .verdict-info')).toContainText('Position 5');
  await scanAt('Shelf: position 5 selected, its record and tag shown');

  await page.locator('#panel-shelf details.disclose > summary').click();
  await expect(page.locator('#panel-shelf details[open]')).toHaveCount(1);
  await expect(page.locator('#panel-shelf table.data tbody tr')).toHaveCount(8);
  await scanAt('Shelf: the byte-to-coefficient packing table open inside its scroller');

  // A shorter record, which really does truncate the text and halves the
  // coefficients the server multiplies.
  await page.selectOption('#shelf-record-size', '128');
  await expect(page.locator('#panel-shelf .kv dd').first()).toContainText('128 bytes');
  await scanAt('Shelf: 128-byte records — the payload truncated, the tag intact');
  await page.selectOption('#shelf-record-size', '512');
  await expect(page.locator('#panel-shelf .kv dd').first()).toContainText('512 bytes');

  // A tiled shelf past the authored catalog, which swaps in the tiling note.
  await page.selectOption('#shelf-size', '128');
  await expect(page.locator('#panel-shelf .shelf-item')).toHaveCount(128);
  await expect(page.locator('#panel-shelf .inline-note').first()).toContainText('tiled');
  await scanAt('Shelf: 128 positions, the catalog tiled and labelled as tiled');
  await page.selectOption('#shelf-size', '64');
  await expect(page.locator('#panel-shelf .shelf-item')).toHaveCount(64);

  // The run seed. Pinning it swaps a reassuring pass verdict for an alarm that
  // says the secret key is now reproducible — a state no reader reaches by
  // accident and one the gate would otherwise never scan.
  await page.fill('#run-seed', 'gate-run');
  await page.getByRole('button', { name: 'Pin this seed' }).click();
  await expect(page.locator('#panel-shelf [data-role="seed-status"] .verdict-alarm')).toContainText(
    'gate-run'
  );
  await scanAt('Shelf: the run seed pinned — the reproducible-key alarm');

  await page.getByRole('button', { name: 'Back to platform entropy' }).click();
  await expect(page.locator('#panel-shelf [data-role="seed-status"] .verdict-pass')).toContainText(
    'platform entropy'
  );
  await expect(page.getByRole('button', { name: 'Back to platform entropy' })).toBeDisabled();
  await scanAt('Shelf: back on platform entropy, the unpin control disabled');

  await page.getByRole('button', { name: 'Draw a new secret key' }).click();
  await expect(page.locator('#panel-shelf [data-role="seed-status"] .verdict-pass')).toBeVisible();

  await page.locator('#panel-shelf .shelf-item').nth(9).hover();
  await scanAt('Shelf: an unselected shelf item hovered');

  // ── The Server's View ───────────────────────────────────────────────────
  await openTab(page, /The Server's View/, '#panel-server');
  await expect(page.locator('#panel-server .ct-tile')).toHaveCount(64);
  await expect(page.locator('#panel-server .verdict-info')).toContainText('Pick a tile');
  await scanAt('Server view: 64 ciphertexts, the plaintext vector greyed, no guess yet');

  // A guess. Tile 0 is deliberate rather than the selected position: the shelf
  // selection is at 5, so this normally paints the `.ct-tile[data-mark="miss"]`
  // state and the reassuring verdict. BOTH outcomes are real renderings, and
  // the assertion is on the wording common to both rather than on which one
  // came up, because a gate that only ever scanned the happy branch would be
  // scanning the state the reader is least likely to be looking at.
  await page.locator('#panel-server .ct-tile').first().click();
  await expect(page.locator('#panel-server .verdict').first()).toContainText('You guessed');
  await scanAt('Server view: a guess made — hit or miss, both are real states');

  await page.getByRole('button', { name: 'New query, same book' }).click();
  await expect(page.locator('#panel-server .verdict-info')).toContainText('Pick a tile');
  await scanAt('Server view: a fresh query, the guess cleared');

  // The deliberately broken mode, and the distinguisher run against both.
  await page.check('#reuse-randomness');
  await expect(page.locator('#reuse-randomness')).toBeChecked();
  await expect(page.locator('#panel-server .callout-danger')).toContainText('Deliberately broken');
  await scanAt('Server view: encryption randomness reuse switched on — the danger callout');

  await page.getByRole('button', { name: /Run 40 trials/ }).click();
  await expect(page.locator('#panel-server [data-role="trial-out"] .verdict-alarm')).toContainText(
    'Reused randomness'
  );
  await expect(page.locator('#panel-server [data-role="trial-out"] .verdict-pass')).toContainText(
    'Fresh randomness'
  );
  await scanAt('Server view: the distinguisher result — chance against certainty');

  await page.uncheck('#reuse-randomness');
  await expect(page.locator('#reuse-randomness')).not.toBeChecked();

  await page.locator('#panel-server details.disclose > summary').click();
  await expect(page.locator('#panel-server details[open]')).toHaveCount(1);
  await scanAt('Server view: the fresh-randomness argument disclosed');

  await page.locator('#panel-server .ct-tile').nth(3).hover();
  await scanAt('Server view: a ciphertext tile hovered');

  // ── Homomorphic Selection ───────────────────────────────────────────────
  await openTab(page, /Homomorphic Selection/, '#panel-fold');
  await expect(page.locator('#panel-fold [data-role="progress"]')).toContainText(
    'Records folded: 0 of 64'
  );
  await expect(page.locator('#panel-fold .meter')).toHaveAttribute('data-health', /healthy|warning/);
  await scanAt('Fold: step 0 — nothing folded, the accumulator empty');

  await page.getByRole('button', { name: 'Fold one record' }).click();
  await expect(page.locator('#panel-fold [data-role="progress"]')).toContainText(
    'Records folded: 1 of 64'
  );
  await expect(page.locator('#panel-fold .ct-tile[data-mark="folded"]')).toHaveCount(1);
  await scanAt('Fold: one record folded — the budget has already fallen');

  await page.locator('#panel-fold details.disclose > summary').first().click();
  await expect(page.locator('#panel-fold details[open]')).toHaveCount(1);
  await scanAt('Fold: the decryption identity opened for coefficient 0');

  await page.getByRole('button', { name: 'Fold eight' }).click();
  await expect(page.locator('#panel-fold [data-role="progress"]')).toContainText(
    'Records folded: 9 of 64'
  );
  await scanAt('Fold: nine records folded, the answer still an encryption of zero');

  await page.getByRole('button', { name: 'Fold the rest' }).click();
  await expect(page.locator('#panel-fold [data-role="progress"]')).toContainText(
    'Records folded: 64 of 64'
  );
  await expect(page.locator('#panel-fold [data-role="final"] .verdict')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Fold one record' })).toBeDisabled();
  await scanAt('Fold: complete — the record decrypted and its integrity tag checked');

  await page.locator('#panel-fold details.disclose > summary').last().click();
  await scanAt('Fold: the three-line derivation of why the sum selects');

  await page.getByRole('button', { name: 'Start over' }).click();
  await expect(page.locator('#panel-fold [data-role="progress"]')).toContainText(
    'Records folded: 0 of 64'
  );
  await scanAt('Fold: reset to step 0 with a fresh query');

  await page.getByRole('button', { name: 'Fold one record' }).hover();
  await scanAt('Fold: the primary button hovered');

  // ── One Server vs Two ───────────────────────────────────────────────────
  await openTab(page, /One Server vs Two/, '#panel-versus');
  await expect(page.locator('#panel-versus [data-role="out"]')).toContainText('Not run yet');
  await expect(
    page.getByRole('button', { name: /Let the two servers compare notes/ })
  ).toBeDisabled();
  await scanAt('Versus: nothing measured yet, the collusion button disabled');

  await page.getByRole('button', { name: 'Run both' }).click();
  await expect(page.locator('#panel-versus table.data')).toBeVisible();
  await expect(page.locator('#panel-versus .verdict-info')).toContainText('one assumption');
  await scanAt('Versus: both protocols measured, the comparison table inside its scroller');

  await page.getByRole('button', { name: /Let the two servers compare notes/ }).click();
  await expect(page.locator('#panel-versus .verdict-alarm')).toContainText('read off position');
  await scanAt('Versus: the two servers collude and recover the index — the alarm');

  await page.locator('#panel-versus details.disclose > summary').click();
  await expect(page.locator('#panel-versus details[open]')).toHaveCount(1);
  await scanAt('Versus: the cost discussion disclosed');

  // RETIREMENT. Changing a parameter throws the measurements away and says so.
  // The retired state renders a verdict no other path reaches, and it is the
  // state a reader is most likely to meet by accident.
  await openTab(page, /The Shelf/, '#panel-shelf');
  await page.selectOption('#shelf-record-size', '256');
  await openTab(page, /One Server vs Two/, '#panel-versus');
  await expect(page.locator('#panel-versus [data-role="out"]')).toContainText(
    'Measurements retired'
  );
  await scanAt('Versus: the measurements retired, with the reason printed');

  await openTab(page, /The Shelf/, '#panel-shelf');
  await page.selectOption('#shelf-record-size', '512');
  await openTab(page, /One Server vs Two/, '#panel-versus');

  // ── Noise Exhaustion ────────────────────────────────────────────────────
  await openTab(page, /Noise Exhaustion/, '#panel-noise');
  await expect(page.locator('#panel-noise .verdict-pass').first()).toContainText('Inside the table');
  await scanAt('Noise: default parameters, inside the published security table');

  await page.getByRole('button', { name: 'Retrieve at these settings' }).click();
  await expect(page.locator('#panel-noise [data-role="out"] .verdict-pass')).toContainText(
    'Retrieved position'
  );
  await scanAt('Noise: a successful retrieval at the defaults, with its measured budget');

  // The exhaustion, for real: the smallest modulus cannot carry a 64-record
  // answer, and the page says which of the three checks noticed.
  await page.selectOption('#noise-modulus', '18');
  await expect(page.locator('#noise-modulus')).toHaveValue('18');
  await page.getByRole('button', { name: 'Retrieve at these settings' }).click();
  await expect(page.locator('#panel-noise [data-role="out"] .fail-code')).toContainText(
    'NOISE_BUDGET_EXHAUSTED'
  );
  await scanAt('Noise: the budget exhausted — the answer decrypted, to garbage');

  // The other end of the trade: enough modulus to be comfortable, and out of
  // the standard's table for it.
  await page.selectOption('#noise-modulus', '30');
  await expect(page.locator('#panel-noise .verdict-fail').first()).toContainText('PARAM_UNSAFE');
  await scanAt('Noise: PARAM_UNSAFE — a modulus past the table’s 128-bit ceiling');

  await page.selectOption('#noise-modulus', '26');
  await expect(page.locator('#panel-noise .verdict-pass').first()).toContainText('Inside the table');

  // Every failure code, raised by its own button.
  for (const [button, code] of [
    ['Trip DIM_MISMATCH', 'DIM_MISMATCH'],
    ['Trip INDEX_OUT_OF_RANGE', 'INDEX_OUT_OF_RANGE'],
    ['Trip PARAM_UNSAFE', 'PARAM_UNSAFE'],
    ['Trip NOISE_BUDGET_EXHAUSTED', 'NOISE_BUDGET_EXHAUSTED'],
  ] as const) {
    await page.getByRole('button', { name: button }).click();
    await expect(page.locator('#panel-noise [data-role="trip-out"] .fail-code')).toHaveText(code);
    await scanAt(`Noise: ${code} raised by the control that causes it`);
  }

  await page.getByRole('button', { name: 'Clear' }).click();
  await expect(page.locator('#panel-noise [data-role="trip-out"]')).toContainText(
    'No failure raised'
  );

  await page.locator('#panel-noise details.disclose > summary').click();
  await expect(page.locator('#panel-noise details[open]')).toHaveCount(1);
  await scanAt('Noise: the malformed-query note disclosed');

  await page.locator('#noise-modulus').focus();
  await expect(page.locator('#noise-modulus')).toBeFocused();
  await scanAt('Noise: a styled select focused, showing its focus-visible outline');

  // ── What It Does Not Hide ───────────────────────────────────────────────
  await openTab(page, /What It Does Not Hide/, '#panel-scope');
  await expect(page.locator('#panel-scope [data-role="log"]')).toContainText('has seen nothing');
  await scanAt('Scope: the observer log empty, the claim table shown');

  await page.getByRole('button', { name: 'Query a random book' }).click();
  await expect(page.locator('#panel-scope [data-role="log"] table.data')).toBeVisible();
  await page.getByRole('button', { name: /Query position \d+ again/ }).click();
  await expect(page.locator('#panel-scope [data-role="log"] tbody tr')).toHaveCount(2);
  await expect(page.locator('#panel-scope [data-role="log"] .verdict-alarm')).toContainText(
    'queries happened'
  );
  await scanAt('Scope: two queries observed — identical sizes, different times');

  await page.locator('#panel-scope details.disclose > summary').click();
  await expect(page.locator('#panel-scope details[open]')).toHaveCount(1);
  await scanAt('Scope: the construction and its citations disclosed');

  await page.getByRole('button', { name: 'Clear the log' }).click();
  await expect(page.locator('#panel-scope [data-role="log"]')).toContainText('has seen nothing');

  // ── Hover and focus on the shared chrome ────────────────────────────────
  await page.getByRole('tab', { name: /The Shelf/ }).hover();
  await scanAt('an inactive tab hovered — its fill repainted');

  await page.locator('.cl-topbar .cl-btn').first().hover();
  await scanAt('a shared top bar control hovered');

  await page.getByRole('tab', { name: /What It Does Not Hide/ }).focus();
  await scanAt('the active tab focused');
}
