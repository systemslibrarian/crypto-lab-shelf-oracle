import { defineConfig, devices } from '@playwright/test';

/**
 * E2E runs against the PRODUCTION build served by `vite preview`, so what passes
 * here is what ships.
 *
 * Port 4691 is unique to this lab across the fleet — never the Vite default
 * 4173. With well over a hundred labs side by side, a shared port means
 * `reuseExistingServer` silently scans a different lab's preview.
 */
const PORT = 4691;
const BASE = '/crypto-lab-shelf-oracle/';

export default defineConfig({
  testDir: './e2e',
  // ONE WORKER, deliberately. The a11y drive holds a page with several hundred
  // controls and runs ~forty full-page scans over it; the claims suite runs real
  // RLWE arithmetic on every click. Several of those in parallel with the
  // preview server on one machine is enough memory pressure to get the server
  // killed mid-run, which surfaces as an ERR_CONNECTION_REFUSED in whichever
  // test happened to navigate next — a flake that says nothing about the page.
  // A gate that is only reliable when the machine is idle is not a gate.
  fullyParallel: false,
  workers: 1,
  // The a11y drive scans every state of every panel, and every one of those
  // states is real RLWE arithmetic rather than a re-render.
  timeout: 900_000,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: 'list',
  use: {
    baseURL: `http://localhost:${PORT}${BASE}`,
    colorScheme: 'dark', // dark is the only theme
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    // Build BEFORE serving. `vite preview` only serves whatever is already in
    // dist/, so without the build in front a failing compile leaves the last
    // good bundle in place and the whole suite passes green against source that
    // no longer compiles — which would silently invalidate mutation testing,
    // the only thing that proves these tests have teeth.
    command: `npm run build && npm run preview -- --port ${PORT} --strictPort`,
    url: `http://localhost:${PORT}${BASE}`,
    reuseExistingServer: !process.env.CI,
    timeout: 180_000,
  },
});
