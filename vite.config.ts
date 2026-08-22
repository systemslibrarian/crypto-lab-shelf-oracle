import { defineConfig, configDefaults } from 'vitest/config';

// base must match the GitHub Pages project subpath:
// https://systemslibrarian.github.io/crypto-lab-shelf-oracle/
export default defineConfig({
  base: '/crypto-lab-shelf-oracle/',
  test: {
    // Colocated unit tests only; the Playwright specs in e2e/ are not Vitest tests.
    include: ['src/**/*.test.ts'],
    exclude: [...configDefaults.exclude, 'e2e/**'],
    // A single PIR query is sixty-four RLWE encryptions and every one of them
    // is a schoolbook O(n^2) multiply at n = 1024 -- real work, not a hang. The
    // default five seconds is not a gate this suite is trying to pass, it is a
    // watchdog sized for tests that do no arithmetic. Nothing here is skipped,
    // sampled or shortened to fit inside it.
    testTimeout: 180_000,
    hookTimeout: 180_000,
  },
});
