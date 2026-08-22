import { expect, test, type Page } from '@playwright/test';

/**
 * The claims suite: does the page tell the truth?
 *
 * This is a different question from "is the cryptography correct", which
 * `src/pir/*.test.ts` answers. A page can run a flawless protocol and still
 * print a number it did not measure, keep a verdict beside settings it was not
 * measured under, or claim a property it does not have.
 *
 * THE RULE THAT MAKES THESE TESTS WORTH ANYTHING: compare two values the PAGE
 * ITSELF printed, rather than asserting against a hardcoded string. A test that
 * re-derives the same expression the source uses will happily agree with a bug.
 *
 * BUT INTERNAL CONSISTENCY IS NOT ENOUGH — a page can be consistently wrong. So
 * this suite mixes three kinds of check, and says which is which at each site:
 *
 *   - CROSS-CHECK: two surfaces that must agree (the shelf's record text against
 *     the record the homomorphic fold returned; the query size in the Server's
 *     View against the same figure in the head-to-head table).
 *   - INDEPENDENT RE-DERIVATION: recompute a claim from the page's own printed
 *     inputs by a DIFFERENT route than the source takes (the ciphertext size
 *     from the printed ring parameters, where the source measures a serialized
 *     buffer; the budget ceiling from q and t, where the source calls
 *     `maxBudgetBits`).
 *   - PARTS-SUM-TO-WHOLE: the whole query is exactly N ciphertexts; the record
 *     is payload plus tag.
 *
 * Every navigation here is a real click on a real control, and every wait is on
 * a completion signal the page renders — never a fixed timeout. A single click
 * on this page can be sixty-four RLWE encryptions.
 */

const RE_BYTES = /([\d.]+)\s*(B|KiB|MiB)/;

/** Parse a byte figure the page printed back into a number of bytes. */
function parseBytes(text: string): number {
  const m = RE_BYTES.exec(text);
  if (!m) throw new Error(`no byte figure in: ${text}`);
  const value = parseFloat(m[1]);
  return m[2] === 'B' ? value : m[2] === 'KiB' ? value * 1024 : value * 1024 * 1024;
}

async function boot(page: Page): Promise<void> {
  page.setDefaultTimeout(60_000);
  await page.goto('.');
  await expect(page.locator('#panel-shelf .shelf-item')).toHaveCount(64);
}

async function openTab(page: Page, name: RegExp, panel: string): Promise<void> {
  await page.getByRole('tab', { name }).click();
  await expect(page.locator(panel)).toBeVisible();
  await expect(page.locator(panel)).not.toBeEmpty();
}

test.describe('the page tells the truth about what it retrieved', () => {
  test('CROSS-CHECK: the record the fold returns is the record the shelf shows', async ({ page }) => {
    await boot(page);
    // Two surfaces, produced by routes with nothing in common: the shelf reads
    // its own array, and the fold panel performs 64 plaintext-ciphertext
    // multiplications, 63 homomorphic additions and one decryption.
    await page.locator('#panel-shelf .shelf-item').nth(23).click();
    const shelfText = (await page.locator('#panel-shelf .code').first().innerText()).trim();
    expect(shelfText.length).toBeGreaterThan(60);

    await openTab(page, /Homomorphic Selection/, '#panel-fold');
    await page.getByRole('button', { name: 'Fold the rest' }).click();
    await expect(page.locator('#panel-fold [data-role="final"] .verdict')).toBeVisible();
    const retrieved = (
      await page.locator('#panel-fold [data-role="final"] .code').innerText()
    ).trim();

    expect(retrieved).toBe(shelfText);
    await expect(page.locator('#panel-fold [data-role="final"] .verdict-pass')).toContainText(
      'Integrity tag intact'
    );
  });

  test('CROSS-CHECK: the fold and the exhaustion panel agree on the budget ceiling', async ({
    page,
  }) => {
    await boot(page);
    await openTab(page, /Homomorphic Selection/, '#panel-fold');
    const foldCeiling = await page
      .locator('#panel-fold dt', { hasText: 'Ceiling for this modulus' })
      .locator('xpath=following-sibling::dd[1]')
      .innerText();

    await openTab(page, /Noise Exhaustion/, '#panel-noise');
    const noiseCeiling = await page
      .locator('#panel-noise dt', { hasText: 'Fresh budget ceiling' })
      .locator('xpath=following-sibling::dd[1]')
      .innerText();

    expect(parseFloat(foldCeiling)).toBeCloseTo(parseFloat(noiseCeiling), 2);
  });

  test('INDEPENDENT RE-DERIVATION: the ceiling is log2(floor(q/t)) from the printed ring', async ({
    page,
  }) => {
    await boot(page);
    await openTab(page, /The Server's View/, '#panel-server');
    // The page prints its ring parameters. Recompute the ceiling from those,
    // by the definition, rather than by calling anything the source calls.
    const ring = await page
      .locator('#panel-server dt', { hasText: 'Ring' })
      .locator('xpath=following-sibling::dd[1]')
      .innerText();
    const n = Number(/n = (\d+)/.exec(ring)?.[1]);
    const q = Number(/q = (\d+)/.exec(ring)?.[1]);
    const t = Number(/t = (\d+)/.exec(ring)?.[1]);
    expect(n).toBe(1024);
    expect(q).toBeGreaterThan(0);
    expect(t).toBe(17);

    await openTab(page, /Homomorphic Selection/, '#panel-fold');
    const printed = parseFloat(
      await page
        .locator('#panel-fold dt', { hasText: 'Ceiling for this modulus' })
        .locator('xpath=following-sibling::dd[1]')
        .innerText()
    );
    expect(printed).toBeCloseTo(Math.log2(Math.floor(q / t)), 2);
  });

  test('INDEPENDENT RE-DERIVATION + PARTS-SUM-TO-WHOLE: the query is N ciphertexts', async ({
    page,
  }) => {
    await boot(page);
    await openTab(page, /The Server's View/, '#panel-server');
    const ring = await page
      .locator('#panel-server dt', { hasText: 'Ring' })
      .locator('xpath=following-sibling::dd[1]')
      .innerText();
    const n = Number(/n = (\d+)/.exec(ring)?.[1]);
    const q = Number(/q = (\d+)/.exec(ring)?.[1]);

    const one = parseBytes(
      await page
        .locator('#panel-server dt', { hasText: 'One ciphertext' })
        .locator('xpath=following-sibling::dd[1]')
        .innerText()
    );
    const whole = parseBytes(
      await page
        .locator('#panel-server dt', { hasText: 'Whole query' })
        .locator('xpath=following-sibling::dd[1]')
        .innerText()
    );

    // Re-derivation: two components of n coefficients, each ceil(log2 q) bits.
    // The source measures a serialized buffer's `.length`; this recomputes the
    // size from the parameters the page printed, which is a different route.
    const derived = Math.ceil((2 * n * Math.ceil(Math.log2(q))) / 8);
    expect(one).toBeCloseTo(derived, -1);

    // Parts sum to whole: 64 shelf positions, 64 ciphertexts, nothing else.
    const tiles = await page.locator('#panel-server .ct-tile').count();
    expect(tiles).toBe(64);
    expect(whole / one).toBeCloseTo(tiles, 0);
  });

  test('CROSS-CHECK: the head-to-head upload matches the Server’s View query size', async ({
    page,
  }) => {
    await boot(page);
    await openTab(page, /The Server's View/, '#panel-server');
    const fromServerView = parseBytes(
      await page
        .locator('#panel-server dt', { hasText: 'Whole query' })
        .locator('xpath=following-sibling::dd[1]')
        .innerText()
    );

    await openTab(page, /One Server vs Two/, '#panel-versus');
    await page.getByRole('button', { name: 'Run both' }).click();
    await expect(page.locator('#panel-versus table.data')).toBeVisible();
    const row = page.locator('#panel-versus tr', { hasText: 'Upload per query' });
    const lattice = parseBytes(await row.locator('td').nth(0).innerText());
    const xor = parseBytes(await row.locator('td').nth(1).innerText());

    // Same quantity, two panels, measured on two separate runs of the same
    // serializer. They are allowed to be the same size, not the same object.
    expect(lattice).toBeCloseTo(fromServerView, -1);

    // Independent re-derivation of the two-server upload: two masks of one bit
    // per shelf position.
    expect(xor).toBe(2 * Math.ceil(64 / 8));
  });

  test('the collusion attack names the position that was actually selected', async ({ page }) => {
    await boot(page);
    await page.locator('#panel-shelf .shelf-item').nth(41).click();
    await expect(page.locator('#panel-shelf .verdict-info')).toContainText('Position 41');

    await openTab(page, /One Server vs Two/, '#panel-versus');
    await page.getByRole('button', { name: 'Run both' }).click();
    await expect(page.locator('#panel-versus table.data')).toBeVisible();
    await page.getByRole('button', { name: /Let the two servers compare notes/ }).click();
    await expect(page.locator('#panel-versus .verdict-alarm')).toContainText('position 41');
  });
});

test.describe('the failure paths fire, and the page names the actual cause', () => {
  test('NOISE_BUDGET_EXHAUSTED is real: the same click succeeds at 2^26 and fails at 2^18', async ({
    page,
  }) => {
    await boot(page);
    await page.locator('#panel-shelf .shelf-item').nth(12).click();
    const truth = (await page.locator('#panel-shelf .code').first().innerText()).trim();

    await openTab(page, /Noise Exhaustion/, '#panel-noise');
    await page.getByRole('button', { name: 'Retrieve at these settings' }).click();
    await expect(page.locator('#panel-noise [data-role="out"] .verdict-pass')).toBeVisible();
    const good = (await page.locator('#panel-noise [data-role="out"] .code').innerText()).trim();
    expect(good).toBe(truth);

    // Only the modulus changes. Same shelf, same book, same button.
    await page.selectOption('#noise-modulus', '18');
    await page.getByRole('button', { name: 'Retrieve at these settings' }).click();
    await expect(page.locator('#panel-noise [data-role="out"] .fail-code')).toHaveText(
      'NOISE_BUDGET_EXHAUSTED'
    );
    const bad = (await page.locator('#panel-noise [data-role="out"] .code').innerText()).trim();
    expect(bad).not.toBe(truth);

    // And the page names the cause it actually detected, not a generic message:
    // the tag is reported broken and the out-of-range count is nonzero.
    const verdictText = await page.locator('#panel-noise [data-role="out"] .verdict-fail').innerText();
    expect(verdictText).toMatch(/integrity tag broken/);
    const outOfRange = await page
      .locator('#panel-noise dt', { hasText: 'Coefficients out of range' })
      .locator('xpath=following-sibling::dd[1]')
      .innerText();
    expect(Number(outOfRange.split(' ')[0])).toBeGreaterThan(0);
    await expect(
      page.locator('#panel-noise dt', { hasText: 'Integrity tag' }).locator('xpath=following-sibling::dd[1]')
    ).toHaveText('does not match');
  });

  test('DIM_MISMATCH names both lengths, and they match the shelf on screen', async ({ page }) => {
    await boot(page);
    await openTab(page, /Noise Exhaustion/, '#panel-noise');
    await page.getByRole('button', { name: 'Trip DIM_MISMATCH' }).click();
    const text = await page.locator('#panel-noise [data-role="trip-out"]').innerText();
    expect(text).toContain('DIM_MISMATCH');
    // The two numbers in the message must be the half-shelf the button builds
    // and the real shelf length — checked against the shelf control's own value,
    // not against a constant.
    const shelfValue = Number(await page.locator('#noise-shelf').inputValue());
    const carried = Number(/carries (\d+) ciphertexts/.exec(text)?.[1]);
    const holds = Number(/holds (\d+) records/.exec(text)?.[1]);
    expect(holds).toBe(shelfValue);
    expect(carried).toBe(Math.floor(shelfValue / 2));
  });

  test('INDEX_OUT_OF_RANGE names the range the shelf actually has', async ({ page }) => {
    await boot(page);
    await openTab(page, /Noise Exhaustion/, '#panel-noise');
    await page.getByRole('button', { name: 'Trip INDEX_OUT_OF_RANGE' }).click();
    const text = await page.locator('#panel-noise [data-role="trip-out"]').innerText();
    expect(text).toContain('INDEX_OUT_OF_RANGE');
    const shelfValue = Number(await page.locator('#noise-shelf').inputValue());
    expect(text).toContain(`shelf position ${shelfValue} is outside 0 .. ${shelfValue - 1}`);
  });

  test('PARAM_UNSAFE fires from both routes: the table and the exactness guard', async ({ page }) => {
    await boot(page);
    await openTab(page, /Noise Exhaustion/, '#panel-noise');

    // Route one: outside the published security table. The verdict must name the
    // ceiling the page also prints in its own readout.
    await page.selectOption('#noise-modulus', '30');
    await expect(page.locator('#panel-noise .verdict-fail').first()).toContainText('PARAM_UNSAFE');
    const ceiling = await page
      .locator('#panel-noise dt', { hasText: '128-bit ceiling' })
      .locator('xpath=following-sibling::dd[1]')
      .innerText();
    await expect(page.locator('#panel-noise .verdict-fail').first()).toContainText(
      `log2 q = ${ceiling}`
    );
    const logQ = await page
      .locator('#panel-noise dt', { hasText: 'log2 q' })
      .locator('xpath=following-sibling::dd[1]')
      .innerText();
    expect(Number(logQ)).toBeGreaterThan(Number(ceiling));

    // Route two: the arithmetic-exactness guard, which is a different branch of
    // the same code and reports a different sentence.
    await page.selectOption('#noise-modulus', '26');
    await page.getByRole('button', { name: 'Trip PARAM_UNSAFE' }).click();
    const text = await page.locator('#panel-noise [data-role="trip-out"]').innerText();
    expect(text).toContain('PARAM_UNSAFE');
    expect(text).toContain('2^53');
  });

  test('the parameter verdict flips both ways with the modulus', async ({ page }) => {
    await boot(page);
    await openTab(page, /Noise Exhaustion/, '#panel-noise');
    await expect(page.locator('#panel-noise .verdict-pass').first()).toContainText(
      'Inside the table'
    );
    await page.selectOption('#noise-modulus', '30');
    await expect(page.locator('#panel-noise .verdict-fail').first()).toContainText('PARAM_UNSAFE');
    await page.selectOption('#noise-modulus', '26');
    await expect(page.locator('#panel-noise .verdict-pass').first()).toContainText(
      'Inside the table'
    );
  });

  test('the six-sigma prediction is below the measured budget, as a bound must be', async ({
    page,
  }) => {
    await boot(page);
    await openTab(page, /Noise Exhaustion/, '#panel-noise');
    await page.getByRole('button', { name: 'Retrieve at these settings' }).click();
    await expect(page.locator('#panel-noise [data-role="out"] .verdict-pass')).toBeVisible();
    const measured = parseFloat(
      await page
        .locator('#panel-noise dt', { hasText: 'Measured budget' })
        .locator('xpath=following-sibling::dd[1]')
        .innerText()
    );
    const predicted = parseFloat(
      await page
        .locator('#panel-noise dt', { hasText: 'Six-sigma prediction' })
        .locator('xpath=following-sibling::dd[1]')
        .innerText()
    );
    expect(predicted).toBeLessThan(measured);
    expect(measured - predicted).toBeLessThan(6);
  });
});

test.describe('the indistinguishability claim, measured', () => {
  test('the distinguisher is at chance on fresh randomness and certain on reused', async ({
    page,
  }) => {
    test.setTimeout(300_000);
    await boot(page);
    await openTab(page, /The Server's View/, '#panel-server');
    await page.getByRole('button', { name: /Run 40 trials/ }).click();
    await expect(page.locator('#panel-server [data-role="trial-out"] .verdict-alarm')).toBeVisible();

    const fresh = await page.locator('#panel-server [data-role="trial-out"] .verdict-pass').innerText();
    const reused = await page
      .locator('#panel-server [data-role="trial-out"] .verdict-alarm')
      .innerText();

    const freshHits = Number(/(\d+)\/(\d+) correct/.exec(fresh)?.[1]);
    const trials = Number(/(\d+)\/(\d+) correct/.exec(fresh)?.[2]);
    const reusedHits = Number(/(\d+)\/(\d+) correct/.exec(reused)?.[1]);
    expect(trials).toBe(40);

    // Reused randomness: exact, every time. Anything less means the broken mode
    // is not actually broken and the lesson is a lie.
    expect(reusedHits).toBe(trials);

    // Fresh randomness: 1 in 16 per trial. Ten or more of forty has probability
    // under 1 in 1000, so this is a real bound rather than a loose one.
    expect(freshHits).toBeLessThan(10);

    // CROSS-CHECK: the percentage the page prints must be the count it prints.
    const freshPct = parseFloat(/\(([\d.]+)%\)/.exec(fresh)?.[1] ?? 'NaN');
    expect(freshPct).toBeCloseTo((freshHits / trials) * 100, 1);
    const reusedPct = parseFloat(/\(([\d.]+)%\)/.exec(reused)?.[1] ?? 'NaN');
    expect(reusedPct).toBeCloseTo((reusedHits / trials) * 100, 1);
  });
});

test.describe('the negative claim, shown', () => {
  test('every observed query is the same size, and their times differ', async ({ page }) => {
    await boot(page);
    await openTab(page, /What It Does Not Hide/, '#panel-scope');
    for (let i = 0; i < 3; i += 1) {
      await page.getByRole('button', { name: 'Query a random book' }).click();
      await expect(page.locator('#panel-scope [data-role="log"] tbody tr')).toHaveCount(i + 1);
    }

    const rows = page.locator('#panel-scope [data-role="log"] tbody tr');
    const uploads: string[] = [];
    const downloads: string[] = [];
    const times: number[] = [];
    for (let i = 0; i < 3; i += 1) {
      const cells = rows.nth(i).locator('td');
      times.push(Number(await cells.nth(1).innerText()));
      uploads.push(await cells.nth(2).innerText());
      downloads.push(await cells.nth(3).innerText());
    }

    // The property the construction genuinely provides: fixed sizes.
    expect(new Set(uploads).size).toBe(1);
    expect(new Set(downloads).size).toBe(1);
    await expect(page.locator('#panel-scope [data-role="log"] .verdict-pass')).toContainText(
      'Every row is the same size'
    );

    // The property it does NOT provide: occurrence and timing.
    expect(times[2]).toBeGreaterThan(times[0]);
    await expect(page.locator('#panel-scope [data-role="log"] .verdict-alarm')).toContainText(
      '3 queries happened'
    );
  });

  test('the claim table marks occurrence and timing as not hidden', async ({ page }) => {
    await boot(page);
    await openTab(page, /What It Does Not Hide/, '#panel-scope');
    const table = page.locator('#panel-scope table.data').first();
    for (const property of ['That a query happened', 'When it happened', 'Who is asking']) {
      await expect(table.locator('tr', { hasText: property }).locator('.pill-bad')).toContainText(
        'NOT hidden'
      );
    }
    for (const property of [
      'Which record was requested',
      'Whether the response length reveals it',
      'Whether the query length reveals it',
    ]) {
      await expect(table.locator('tr', { hasText: property }).locator('.pill-ok')).toContainText(
        'Hidden by the protocol'
      );
    }

    // The table must not contradict itself: the query length is constant across
    // INDICES (hidden) and simultaneously announces the SHELF SIZE (not hidden).
    // Those are different facts about the same observable, and an earlier draft
    // of this table stated them as if they were the same one.
    await expect(
      table.locator('tr', { hasText: 'The size of the database' }).locator('.pill-bad')
    ).toContainText('NOT hidden');
    await expect(table.locator('caption')).toContainText('a length that is visible but constant');
  });
});

test.describe('verdict retirement', () => {
  test('changing a parameter retires the measurement AND says it was retired', async ({ page }) => {
    await boot(page);
    await openTab(page, /One Server vs Two/, '#panel-versus');
    await page.getByRole('button', { name: 'Run both' }).click();
    await expect(page.locator('#panel-versus table.data')).toBeVisible();

    // Change an input on another tab. The stale table must be GONE, and the
    // panel must say why — a result that vanishes silently is indistinguishable
    // from one that was never produced.
    await openTab(page, /The Shelf/, '#panel-shelf');
    await page.selectOption('#shelf-record-size', '256');

    await openTab(page, /One Server vs Two/, '#panel-versus');
    await expect(page.locator('#panel-versus table.data')).toHaveCount(0);
    await expect(page.locator('#panel-versus [data-role="out"]')).toContainText(
      'Measurements retired'
    );
    await expect(page.locator('#panel-versus [data-role="out"]')).toContainText(
      'the record size changed to 256 bytes'
    );
  });

  test('the exhaustion verdict is retired when the modulus moves under it', async ({ page }) => {
    await boot(page);
    await openTab(page, /Noise Exhaustion/, '#panel-noise');
    await page.getByRole('button', { name: 'Retrieve at these settings' }).click();
    await expect(page.locator('#panel-noise [data-role="out"] .verdict-pass')).toBeVisible();
    await page.selectOption('#noise-modulus', '24');
    await expect(page.locator('#panel-noise [data-role="out"]')).toContainText('Result retired');
    await expect(page.locator('#panel-noise [data-role="out"]')).toContainText(
      'the ciphertext modulus changed to 2^24'
    );
  });

  test('NO-OP GUARD: re-selecting the same book does NOT retire a fresh measurement', async ({
    page,
  }) => {
    await boot(page);
    await page.locator('#panel-shelf .shelf-item').nth(7).click();
    await openTab(page, /One Server vs Two/, '#panel-versus');
    await page.getByRole('button', { name: 'Run both' }).click();
    await expect(page.locator('#panel-versus table.data')).toBeVisible();

    // Click the SAME shelf position again. Nothing has changed, so nothing may
    // be retired — otherwise a reader learns that results here are arbitrary
    // rather than parameter-dependent.
    await openTab(page, /The Shelf/, '#panel-shelf');
    await page.locator('#panel-shelf .shelf-item').nth(7).click();
    await expect(page.locator('#panel-shelf .shelf-item').nth(7)).toHaveAttribute(
      'aria-pressed',
      'true'
    );

    await openTab(page, /One Server vs Two/, '#panel-versus');
    await expect(page.locator('#panel-versus table.data')).toBeVisible();
    await expect(page.locator('#panel-versus [data-role="out"]')).not.toContainText(
      'Measurements retired'
    );

    // And selecting a DIFFERENT one does retire it, so the guard above is not
    // simply a broken listener.
    await openTab(page, /The Shelf/, '#panel-shelf');
    await page.locator('#panel-shelf .shelf-item').nth(8).click();
    await openTab(page, /One Server vs Two/, '#panel-versus');
    await expect(page.locator('#panel-versus [data-role="out"]')).toContainText(
      'Measurements retired'
    );
  });
});

test.describe('the page is what it says it is', () => {
  /**
   * The `[hidden]` probe from §4.1.
   *
   * A class rule that sets `display` outranks the UA's `[hidden]` rule, so an
   * element can carry the attribute, be believed hidden by the code, and paint
   * anyway. This lab hit exactly that: `.panel { display: grid }` kept five
   * `[hidden]` tabpanels in the layout as zero-height grids, still in the tab
   * order. `#app [hidden] { display: none }` closes it, and this asserts the
   * OUTCOME rather than the rule.
   */
  test('every hidden panel is genuinely not displayed', async ({ page }) => {
    await boot(page);
    const states = await page.evaluate(() =>
      Array.from(document.querySelectorAll('[hidden]')).map((el) => ({
        id: el.id,
        display: getComputedStyle(el).display,
        rect: el.getBoundingClientRect().height,
      }))
    );
    expect(states.length).toBeGreaterThan(0);
    for (const s of states) {
      expect(s.display, `#${s.id} carries [hidden] but computes display: ${s.display}`).toBe('none');
      expect(s.rect).toBe(0);
    }
  });

  test('the honest-scope claims are on the page, not only in the README', async ({ page }) => {
    await boot(page);
    await expect(page.locator('.scope-note')).toContainText('Not production cryptography');
    await expect(page.locator('.scope-note')).toContainText('no network is involved');

    await openTab(page, /What It Does Not Hide/, '#panel-scope');
    await expect(page.locator('#panel-scope')).toContainText('What this page does not prove');
    await expect(page.locator('#panel-scope')).toContainText('Schoolbook');
    await expect(page.locator('#panel-scope')).toContainText('No constant-time discipline');
  });

  test('pinning a seed warns that the secret key becomes reproducible', async ({ page }) => {
    await boot(page);
    await expect(page.locator('#panel-shelf [data-role="seed-status"] .verdict-pass')).toContainText(
      'platform entropy'
    );
    await page.fill('#run-seed', 'shelf-oracle');
    await page.getByRole('button', { name: 'Pin this seed' }).click();
    const warn = page.locator('#panel-shelf [data-role="seed-status"] .verdict-alarm');
    await expect(warn).toContainText('shelf-oracle');
    await expect(warn).toContainText('INCLUDING the secret key');
    await page.getByRole('button', { name: 'Back to platform entropy' }).click();
    await expect(page.locator('#panel-shelf [data-role="seed-status"] .verdict-pass')).toContainText(
      'platform entropy'
    );
  });

  test('a pinned seed makes the run reproducible, byte for byte', async ({ page }) => {
    // The claim the seed control makes, checked: the same seed must produce the
    // same ciphertexts. Two loads, one seed, one comparison of the bytes the
    // page itself printed.
    const headsFor = async (): Promise<string[]> => {
      await boot(page);
      await page.fill('#run-seed', 'reproducible-run');
      await page.getByRole('button', { name: 'Pin this seed' }).click();
      await openTab(page, /The Server's View/, '#panel-server');
      const tiles = page.locator('#panel-server .ct-tile');
      const out: string[] = [];
      for (let i = 0; i < 6; i += 1) out.push(await tiles.nth(i).innerText());
      return out;
    };
    const first = await headsFor();
    const second = await headsFor();
    expect(second).toEqual(first);
    // And the heads must not all be identical to each other, which would mean
    // the encryption stopped randomising rather than that the seed worked.
    expect(new Set(first).size).toBe(first.length);
  });
});
