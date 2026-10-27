// Clean-baseline mutation gate for Shelf Oracle.
//
// The README has described seventeen hand-applied mutations since the L-R-05
// delivery; until this file existed nothing could replay them, so the claim was
// reproducible only by repeating the prose by hand. This runner is the fleet
// pattern (Attestation Gate, Matsui Line, Residue Gate): for every recipe it
// proves, in order,
//
//   1. the unmodified copy passes the WHOLE unit suite and builds,
//   2. the named owning test is green on the unmodified copy,
//   3. the patch produces a NON-EMPTY source change and the production bundle
//      hash moves (a mutation the build never picked up proves nothing),
//   4. the named owning test goes RED on a test failure -- a timeout, a crash,
//      a missing module or a server that failed to start is NOT a kill,
//   5. the source is restored byte for byte, the bundle hash returns to the
//      baseline, and the owning test is green again.
//
// Twelve recipes are owned by Vitest tests and five by Playwright claims, which
// run against a fresh production build served by `vite preview` (CI=1 makes the
// Playwright config rebuild and refuse to reuse a running server).
//
// Run from the repository root: node scripts/mutations.mjs [mutation name]

import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { stripVTControlCharacters } from 'node:util';

const RING = 'src/pir/ring.ts';
const NTT = 'src/pir/ntt.ts';
const PIR = 'src/pir/pir.ts';
const BFV = 'src/pir/bfv.ts';
const EXPAND = 'src/pir/expand.ts';
const PIANO = 'src/pir/piano.ts';
const STYLE = 'src/style.css';
const STATE = 'src/ui/state.ts';
const DOM = 'src/ui/dom.ts';
const MAIN = 'src/main.ts';
const CLAIMS = 'e2e/claims.spec.ts';

const unit = (spec, test) => ({ runner: 'vitest', spec, test });
const browser = (test) => ({ runner: 'playwright', spec: CLAIMS, test });

const mutations = [
  // --- the original eight ------------------------------------------------
  {
    name: 'direct ring loses the negacyclic sign',
    file: RING,
    anchor: '    for (let j = lim; j < n; j += 1) acc[i + j - n] -= si * a[j];',
    replacement: '    for (let j = lim; j < n; j += 1) acc[i + j - n] += si * a[j];',
    ...unit('src/pir/ring.test.ts', 'X^(n-1) * X = -1, not +1'),
  },
  {
    name: 'DIM_MISMATCH guard stops comparing the query with the shelf',
    file: PIR,
    anchor: '  assertDimensionsMatch(queryLength, shelfSize);\n  return {\n    acc0: new Float64Array(p.n),',
    replacement: '  assertDimensionsMatch(shelfSize + 0 * queryLength, shelfSize);\n  return {\n    acc0: new Float64Array(p.n),',
    ...unit('src/pir/pir.test.ts', 'DIM_MISMATCH — a query built for a different shelf length is refused first'),
  },
  {
    name: 'encryption stops drawing fresh randomness',
    file: BFV,
    anchor: '  const a = randomness ? randomness.a : sampleUniform(p, rng);',
    replacement: '  const a = randomness ? randomness.a : new Int32Array(p.n);',
    ...unit('src/pir/bfv.test.ts', 'two encryptions of the same value differ in every component'),
  },
  {
    name: 'the [hidden] cascade rule stops removing panels from layout',
    file: STYLE,
    anchor: '#app [hidden] {\n  display: none;\n}',
    replacement: '#app [hidden] {\n  visibility: hidden;\n}',
    ...browser('every hidden panel is genuinely not displayed'),
  },
  {
    name: 'the no-op selection guard is removed',
    file: STATE,
    anchor: '    if (index === this.selectedIndex) return;',
    replacement: '    if (false && index === this.selectedIndex) return;',
    ...browser('NO-OP GUARD: re-selecting the same book does NOT retire a fresh measurement'),
  },
  {
    name: 'focus is no longer restored after a re-render',
    file: DOM,
    anchor: '  if (target && typeof target.focus === \'function\') target.focus({ preventScroll: true });',
    replacement: '  if (target && typeof target.focus === \'function\') target.blur();',
    ...browser('activating a control keeps focus on it across the re-render'),
  },
  {
    name: 'the live region is rebuilt as a fresh node on every status write',
    file: DOM,
    anchor: '  if (region && region.textContent !== text) region.textContent = text;',
    replacement:
      "  if (region) region.replaceWith(el('p', { class: 'live-status', role: 'status', 'aria-live': 'polite' }, text));",
    ...browser('the live region is ONE node that survives every render'),
  },
  {
    name: 'the on-screen panel stops re-rendering when a parameter changes',
    file: MAIN,
    anchor: '    if (open) render(open.dataset.panel as PanelId);',
    replacement: '    if (open) stale.add(open.dataset.panel as PanelId);',
    ...browser('the exhaustion verdict is retired when the modulus moves under it'),
  },
  // --- four on the compressed path ---------------------------------------
  {
    name: 'the odd Galois schedule is shifted by one round',
    file: EXPAND,
    anchor: '  return Array.from({ length: rounds }, (_, i) => p.n / 2 ** i + 1);',
    replacement: '  return Array.from({ length: rounds }, (_, i) => p.n / 2 ** (i + 1) + 1);',
    ...unit('src/pir/expand.test.ts', 'uses the published odd substitution schedule'),
  },
  {
    name: 'the automorphism drops its negacyclic sign',
    file: EXPAND,
    anchor:
      '    const exponent = (i * element) % (2 * n);\n    if (exponent < n) out[exponent] = polynomial[i];\n    else out[exponent - n] = mod(-polynomial[i], q);',
    replacement:
      '    const exponent = (i * element) % (2 * n);\n    if (exponent < n) out[exponent] = polynomial[i];\n    else out[exponent - n] = mod(polynomial[i], q);',
    ...unit('src/pir/expand.test.ts', 'applies ring automorphisms and monomial shifts with the negacyclic sign'),
  },
  {
    name: 'key switching discards the substituted c0 term',
    file: EXPAND,
    anchor: '  return { c0: addPoly(substituted.c0, switched0, p.q), c1: switched1 };',
    replacement: '  return { c0: switched0, c1: switched1 };',
    ...unit('src/pir/expand.test.ts', 'serializes reusable evaluation keys and expands all 16 positions to real one-hot vectors'),
  },
  {
    name: 'the NTT fold adds instead of subtracting modulo X^n + 1',
    file: NTT,
    anchor: '    const r0 = mod(time[0][i] - time[0][i + n], PRIMES[0].modulus);',
    replacement: '    const r0 = mod(time[0][i] + time[0][i + n], PRIMES[0].modulus);',
    ...unit('src/pir/ntt.test.ts', 'gets the X^(n-1) times X sign right'),
  },
  // --- five on the bounded Piano core ------------------------------------
  {
    name: 'recovery omits the replacement record from its XOR',
    file: PIANO,
    anchor: '    recovered = xorThree(plan.originalHintParity, response, plan.replacementValue);',
    replacement: '    recovered = xorThree(plan.originalHintParity, response, new Uint8Array(PIANO_RECORD_BYTES));',
    ...unit('src/pir/piano.test.ts', 'recovers 33 independently checked records, then sends only a dummy beyond the window'),
  },
  {
    name: 'the refresh slot is no longer consumed before send',
    file: PIANO,
    anchor: '          data.consumedSlots[chunk] += 1;',
    replacement: '          data.consumedSlots[chunk] += 0;',
    ...unit('src/pir/piano.test.ts', 'a malformed response consumes the target and refresh slot, then invalidates rather than retrying'),
  },
  {
    name: 'a malformed response no longer invalidates the epoch',
    file: PIANO,
    anchor: '    invalidate(data, malformed);',
    replacement: '    void malformed;',
    ...unit('src/pir/piano.test.ts', 'commits a setup miss before send, so malformed and abandoned states round-trip'),
  },
  {
    name: 'an oversized query encoding is accepted',
    file: PIANO,
    anchor: '  if (!(bytes instanceof Uint8Array) || bytes.length !== PIANO_QUERY_BYTES) {',
    replacement: '  if (!(bytes instanceof Uint8Array) || bytes.length < PIANO_QUERY_BYTES) {',
    ...unit('src/pir/piano.test.ts', 'rejects truncated, extended, reordered and noncanonical query encodings'),
  },
  {
    name: 'the database digest comparison always reports equality',
    file: PIANO,
    anchor: '  if (sameBytes(current, data.databaseDigest)) return true;',
    replacement: '  if (sameBytes(current, current)) return true;',
    ...unit('src/pir/piano.test.ts', 'rejects a pending response when a known database update invalidates the epoch'),
  },
];

const INFRASTRUCTURE = /No test files found|Cannot find module|Failed to load url|Unhandled Error|error TS\d+|ERR_CONNECTION_REFUSED|webServer was not able|Timed out waiting \d+ms from config\.webServer|Error: Process from config\.webServer|Test timed out|Test timeout of/;

function run(command, args, timeout) {
  const child = spawnSync(command, args, {
    encoding: 'utf8',
    env: { ...process.env, CI: '1', NO_COLOR: '1' },
    maxBuffer: 32 * 1024 * 1024,
    timeout,
  });
  return {
    ok: child.status === 0 && !child.error && !child.signal,
    status: child.status,
    signal: child.signal,
    error: child.error,
    output: stripVTControlCharacters(`${child.stdout ?? ''}${child.stderr ?? ''}`),
  };
}

function requirePass(result, label) {
  if (!result.ok) {
    throw new Error(`${label} failed (status ${result.status}, signal ${result.signal ?? 'none'}):\n${result.output.slice(-4000)}`);
  }
}

function build() {
  requirePass(run('npm', ['run', 'build'], 300_000), 'build');
}

/** Hash of every emitted asset, JavaScript AND CSS: one recipe mutates a stylesheet. */
function bundleHash() {
  const dir = 'dist/assets';
  const files = readdirSync(dir).filter((file) => statSync(join(dir, file)).isFile()).sort();
  if (files.length === 0) throw new Error('build produced no assets');
  const hash = createHash('sha256');
  for (const file of files) hash.update(file).update(readFileSync(join(dir, file)));
  return hash.digest('hex');
}

const escapeRegex = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function owningTest(mutation) {
  if (mutation.runner === 'vitest') {
    return run('npx', ['vitest', 'run', mutation.spec, '-t', escapeRegex(mutation.test)], 300_000);
  }
  // --retries=0 overrides the config's CI retry so a kill is one red run, and
  // CI=1 makes the webServer rebuild from the (mutated) source instead of
  // reusing a preview that is still serving the clean bundle.
  return run(
    'npx',
    ['playwright', 'test', mutation.spec, '-g', escapeRegex(mutation.test), '--retries=0', '--reporter=line'],
    1_500_000
  );
}

function requireNamedGreen(result, mutation, label) {
  requirePass(result, label);
  const exactlyOne = mutation.runner === 'vitest' ? /Tests\s+1 passed\b/ : /\b1 passed\b/;
  if (!exactlyOne.test(result.output) || /\d+ failed\b/.test(result.output)) {
    throw new Error(`${label} did not execute exactly one passing test:\n${result.output.slice(-3000)}`);
  }
}

function requireNamedRed(result, mutation) {
  if (result.ok) throw new Error(`${mutation.name}: mutation SURVIVED its owning test`);
  if (INFRASTRUCTURE.test(result.output)) {
    throw new Error(`${mutation.name}: an infrastructure failure or timeout is not a kill:\n${result.output.slice(-3000)}`);
  }
  if (!result.output.includes(mutation.test)) {
    throw new Error(`${mutation.name}: the failure did not name its owning test:\n${result.output.slice(-3000)}`);
  }
  const red = mutation.runner === 'vitest' ? /Tests\s+1 failed\b/ : /\b1 failed\b/;
  if (!red.test(result.output)) {
    throw new Error(`${mutation.name}: the owning test did not fail exactly once:\n${result.output.slice(-3000)}`);
  }
  // A kill is a test FAILURE: an expect() assertion, or the code under test
  // throwing into the test body. Both are reported as failed tests; what is
  // excluded is everything the INFRASTRUCTURE pattern names above.
}

const requested = process.argv[2];
const selected = requested ? mutations.filter((mutation) => mutation.name === requested) : mutations;
if (selected.length === 0) throw new Error(`unknown mutation: ${requested}`);

const files = [...new Set(selected.map((mutation) => mutation.file))];
if (run('git', ['diff', '--quiet', 'HEAD', '--', ...files], 60_000).status !== 0) {
  throw new Error('commit the mutated source files before replaying mutations; the harness restores from disk, not from git');
}

build();
const baseline = bundleHash();
// The WHOLE unit suite: a baseline scoped to the mutated files would stay green
// while a mutation broke something elsewhere, and the restore control at the
// end would agree with it.
requirePass(run('npx', ['vitest', 'run'], 600_000), 'unmutated unit baseline');
console.log('baseline: unmutated copy PASSES');

const evidence = [];
for (const [index, mutation] of selected.entries()) {
  const original = readFileSync(mutation.file, 'utf8');
  if (original.split(mutation.anchor).length !== 2) {
    throw new Error(`${mutation.name}: the anchor must occur exactly once in ${mutation.file}`);
  }
  requireNamedGreen(owningTest(mutation), mutation, `${mutation.name}: named baseline`);
  let record;
  try {
    const changed = original.replace(mutation.anchor, mutation.replacement);
    if (changed === original) throw new Error(`${mutation.name}: the patch changed nothing`);
    writeFileSync(mutation.file, changed);
    const diff = run('git', ['diff', '--no-ext-diff', '--', mutation.file], 60_000);
    if (diff.output.trim() === '') throw new Error(`${mutation.name}: the source diff was empty`);
    build();
    const mutant = bundleHash();
    if (mutant === baseline) throw new Error(`${mutation.name}: the production bundle did not change`);
    const red = owningTest(mutation);
    requireNamedRed(red, mutation);
    record = {
      name: mutation.name,
      file: mutation.file,
      runner: mutation.runner,
      owningTest: mutation.test,
      baselineGreen: true,
      sourceDiffNonEmpty: true,
      baselineBundle: baseline,
      mutantBundle: mutant,
      bundleMoved: true,
      owningTestRed: true,
      failureExcerpt: red.output.split('\n').filter((line) => /expect|Error|✗|×|FAIL/.test(line)).slice(0, 6),
    };
    console.log(`caught ${index + 1}/${selected.length}: ${mutation.name} -> ${mutation.test}`);
  } finally {
    writeFileSync(mutation.file, original);
    if (readFileSync(mutation.file, 'utf8') !== original) {
      throw new Error(`${mutation.name}: source was not restored byte for byte`);
    }
    build();
    if (bundleHash() !== baseline) throw new Error(`${mutation.name}: restored bundle differs from the baseline`);
  }
  requireNamedGreen(owningTest(mutation), mutation, `${mutation.name}: restored baseline`);
  record.restoredGreen = true;
  evidence.push(record);
  writeFileSync('mutation-evidence.json', `${JSON.stringify(evidence, null, 2)}\n`);
}

requirePass(run('npx', ['vitest', 'run'], 600_000), 'restored unit baseline');
console.log(`all ${evidence.length} of ${selected.length} mutation(s) caught; sources and production bundle restored byte for byte`);
