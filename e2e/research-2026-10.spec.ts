import { test, expect } from '@playwright/test';

test('research note preserves evidence and attack-model boundaries', async ({ page }) => {
  await page.goto('./');
  await page.locator('[role=tab][data-panel=scope]').click();
  const note = page.locator('#decryption-feedback-research');
  await expect(note).toBeVisible();
  await expect(note).toContainText('20 October 2026');
  await expect(note).toContainText('IND-CPA-D');
  await expect(note).toContainText('adversary learns computation results');
  await expect(note).toContainText('heuristic correctness assumptions');
  await expect(note).toContainText('OpenFHE');
  await expect(note).toContainText('HElib');
  await expect(note).toContainText('does not reproduce those attacks');
  await expect(note).toContainText('ACM CCS 2026');
  await expect(note.locator('a[href="https://eprint.iacr.org/2026/2546"]')).toBeVisible();
});
