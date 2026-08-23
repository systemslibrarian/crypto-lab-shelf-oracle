import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  REFLOW,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches: the arrival state, where The
 * Shelf is active with position 0 selected and the other five tabpanels are
 * hidden and UNRENDERED; the shared skip link focused; a different book chosen;
 * the byte-to-coefficient packing table opened through its summary; a shorter
 * record and a tiled 128-position shelf; the encrypted selection vector with a
 * guess made against it; the deliberately-broken randomness-reuse mode and the
 * distinguisher result that saturates under it; the homomorphic fold at step 0,
 * at one record, at nine, and complete with its decrypted record and integrity
 * check, then reset; the decryption identity and the why-the-sum-selects
 * derivation opened; both protocols measured head to head and the two servers
 * colluding to recover the index; a successful retrieval and then a genuinely
 * exhausted noise budget; PARAM_UNSAFE raised by a modulus past the standard's
 * ceiling; all four failure codes raised by the controls that cause them; the
 * observer log with two queries in it; and finally three hover states and two
 * focus rings across the lab's own controls and the shared bar. Every one of
 * those states is scanned, at desktop and phone width.
 *
 * Dark is the only theme, so there is one theme loop rather than two — and
 * `boot` seeds `localStorage.theme = 'light'` before navigating precisely so
 * the anti-flash script's OVERWRITE is measured rather than assumed.
 *
 * See `gate.ts` for why nothing is injected into the page (the old gate's
 * `addStyleTag` motion kill bypassed the stylesheet's own reduced-motion
 * block, so the rendering reduced-motion readers get was never the one
 * scanned), why no panel is revealed from script (the old gate stripped every
 * `[hidden]` and opened every `<details>` by JS before its only scan), why the
 * lab's defaults are asserted rather than assumed, and why `violations` is not
 * the whole oracle.
 */

test('no WCAG A/AA violations at desktop width', async ({ page }) => {
  test.setTimeout(1_800_000);
  const errors = watchPageErrors(page);
  await boot(page);
  await driveAllStates(page, 'dark');
  expect(errors, errors.join('\n')).toEqual([]);
  expectBaselineNotStale();
  reportCollected();
});

test('no WCAG A/AA violations at 380px', async ({ page }) => {
  test.setTimeout(1_800_000);
  const errors = watchPageErrors(page);
  await page.setViewportSize(NARROW);
  await boot(page);
  await driveAllStates(page, 'dark @380px');
  expect(errors, errors.join('\n')).toEqual([]);
  expectBaselineNotStale();
  reportCollected();
});

test('no WCAG A/AA violations at 320px — the reflow threshold', async ({ page }) => {
  test.setTimeout(1_800_000);
  const errors = watchPageErrors(page);
  await page.setViewportSize(REFLOW);
  await boot(page);
  await driveAllStates(page, 'dark @280px');
  expect(errors, errors.join('\n')).toEqual([]);
  expectBaselineNotStale();
  reportCollected();
});
