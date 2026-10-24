import { addCiphertext, decrypt, keyGen, maxBudgetBits, noiseBudgetBits } from '../pir/bfv';
import {
  buildCompressedQuery,
  deserializeEvaluationKeys,
  EXPANSION_MODULUS,
  EXPANSION_RECORD_BYTES,
  EXPANSION_SELECTION_LENGTH,
  expandCompressedQuery,
  generateEvaluationKeys,
  serializeEvaluationKeys,
  type ExpansionRound,
} from '../pir/expand';
import { makeParams } from '../pir/params';
import { buildQuery, decodeAnswer, serverAnswer } from '../pir/pir';
import {
  buildRecord,
  bytesToCoefficients,
  recordText,
  shelfToPlaintexts,
} from '../pir/records';
import { assessSecurity } from '../pir/security';
import {
  deserializeCiphertext,
  serializeCiphertext,
  serializeQuery,
} from '../pir/serialize';
import { zeroPoly } from '../pir/ring';
import { entryText, shelfEntries } from '../data/catalog';
import {
  append,
  card,
  clear,
  disclose,
  el,
  formatBytes,
  formatMs,
  kv,
  nextFrame,
  panelStatus,
  scroller,
  verdict,
  withFocusRestored,
} from './dom';
import type { Lab } from './state';

/**
 * The full-catalog SealPIR query-expansion lesson.
 *
 * It is intentionally its own run, rather than silently replacing the mature
 * 64-row direct path. Each fixed block expands to 16 selectors; four query and
 * four response ciphertexts cover all 64 rows without revealing the selected
 * block. The 16-selector and 27-bit-modulus limits keep evaluation-key noise
 * inside this teaching engine's one-modulus budget. The page prints that bound
 * everywhere it matters.
 */

interface Timings {
  readonly directQueryMs: number;
  readonly directFoldMs: number;
  readonly evaluationKeyMs: number;
  readonly compressedQueryMs: number;
  readonly expansionMs: number;
  readonly compressedFoldMs: number;
}
interface Costs {
  readonly directUploadBytes: number;
  readonly compressedUploadBytes: number;
  readonly evaluationKeyBytes: number;
  readonly directResponseBytes: number;
  readonly compressedResponseBytes: number;
  readonly keySamples: number;
  readonly crossoverQueries: number;
}

interface NoiseReadings {
  readonly ceiling: number;
  readonly directSelectorMinimum: number;
  readonly compressedBlockMinimum: number;
  readonly expandedSelectorMinimum: number;
  readonly expandedSelected: number;
  readonly directAnswer: number;
  readonly compressedAnswerMinimum: number;
  readonly compressedSelectedAnswer: number;
  readonly combinedAnswer: number;
}

interface ComparisonResult {
  readonly globalIndex: number;
  readonly localIndex: number;
  readonly selectedBlock: number;
  readonly blockCount: number;
  readonly title: string;
  readonly expectedText: string;
  readonly directText: string;
  readonly compressedText: string;
  readonly directCorrect: boolean;
  readonly compressedCorrect: boolean;
  readonly routesAgree: boolean;
  readonly combinedFailure: string | null;
  readonly inverseScale: number;
  readonly digitCount: number;
  readonly costs: Costs;
  readonly timings: Timings;
  readonly noise: NoiseReadings;
  readonly rounds: readonly ExpansionRound[];
  readonly securitySummary: string;
}

interface PanelState {
  result: ComparisonResult | null;
  running: boolean;
  stage: string | null;
  error: string | null;
  retired: string | null;
  generation: number;
}

const state: PanelState = {
  result: null,
  running: false,
  stage: null,
  error: null,
  retired: null,
  generation: 0,
};

const FULL_CATALOG_LENGTH = 64;
const FULL_CATALOG_BLOCKS = FULL_CATALOG_LENGTH / EXPANSION_SELECTION_LENGTH;

export function resetExpand(reason?: string): void {
  state.generation += 1;
  if (state.result || state.running || state.error || state.retired) state.retired = reason ?? null;
  state.result = null;
  state.running = false;
  state.stage = null;
  state.error = null;
}

export function renderExpand(root: HTMLElement, lab: Lab): void {
  const s = lab.snapshot();
  const inBound = s.selectedIndex < FULL_CATALOG_LENGTH;
  const localIndex = s.selectedIndex % EXPANSION_SELECTION_LENGTH;
  clear(root);

  append(
    root,
    card('Four encrypted blocks in, sixty-four encrypted selectors out', [
      el(
        'p',
        { class: 'lede' },
        inBound
          ? `This run retrieves catalog position ${s.selectedIndex} (${s.entries[s.selectedIndex].title}) ` +
            `from the fixed 64-record teaching database two ways: sixty-four direct one-hot ` +
            `ciphertexts, then four encrypted blocks expanded by the server. No plaintext field ` +
            `carries the selected block or local position ${localIndex}; the choice is present only ` +
            `under encryption. All four query blocks and all four response ciphertexts always cross ` +
            `the boundary.`
          : `The compressed lesson has a fixed 64-record teaching database. Position ${s.selectedIndex} ` +
            `is outside it; choose a catalog position from 0 through 63 before running this comparison.`
      ),
      el('div', { class: 'controls' }, [
        el(
          'button',
          {
            class: 'btn btn-primary',
            type: 'button',
            'data-role': 'run-expansion',
            disabled: !inBound,
            'aria-disabled': state.running ? 'true' : undefined,
          },
          state.running ? 'Running real expansion…' : 'Run direct and compressed queries'
        ),
      ]),
      el('div', { 'data-role': 'expansion-out' }, output()),
    ])
  );

  append(root, card('What this construction assumes', [scopeNotes()]));

  announce(root, headline());
  bind(root, lab);
}

function headline(): string {
  if (state.running) return state.stage ?? 'Running compressed-query expansion.';
  if (state.result) {
    return state.result.routesAgree && state.result.compressedCorrect
      ? `Direct and compressed queries returned the same record; ${state.result.rounds.length} rounds ran for each of ${state.result.blockCount} blocks.`
      : 'The compressed-query comparison completed with a correctness failure.';
  }
  if (state.error) return `Compressed-query run stopped: ${state.error}`;
  if (state.retired) return `Compressed-query result retired: ${state.retired}.`;
  return 'Compressed-query comparison has not run yet.';
}

function output(): HTMLElement {
  if (state.running) {
    return el('p', { class: 'status-line' }, state.stage ?? 'Starting the fixed-block run…');
  }
  if (state.error) {
    return verdict('fail', [
      el('strong', {}, 'The run stopped rather than printing an unearned comparison. '),
      state.error,
    ]);
  }
  if (!state.result) {
    return state.retired
      ? verdict('info', [
          el('strong', {}, 'Result retired: '),
          `${state.retired}. The record and key-dependent measurements were discarded; run again ` +
            `to compare the current selection.`,
        ])
      : el(
          'p',
          { class: 'status-line' },
          'Not run yet. The button executes key generation, wire round-trips, four expansions, the direct and four block folds, and every decryption check.'
        );
  }

  const r = state.result;
  const success = r.directCorrect && r.compressedCorrect && r.routesAgree;
  const firstCompressed = r.costs.evaluationKeyBytes + r.costs.compressedUploadBytes;
  const traceTable = el('table', { class: 'data' }, [
    el(
      'caption',
      {},
      `The per-block expansion executed for each of ${r.blockCount} fixed query blocks. Each input ciphertext is substituted once, key-switched once, and split into two outputs.`
    ),
    el(
      'thead',
      {},
      el('tr', {}, [
        el('th', { class: 'num' }, 'Round'),
        el('th', { class: 'num' }, 'X → X^g'),
        el('th', { class: 'num' }, 'Ciphertexts'),
        el('th', { class: 'num' }, 'Key switches'),
        el('th', { class: 'num' }, 'Exact convolutions'),
        el('th', { class: 'num' }, 'Adds / shifts'),
      ])
    ),
    el(
      'tbody',
      {},
      r.rounds.map((round) =>
        el('tr', {}, [
          el('th', { scope: 'row', class: 'num' }, String(round.round)),
          el('td', { class: 'num' }, String(round.galoisElement)),
          el('td', { class: 'num' }, `${round.inputs} → ${round.outputs}`),
          el('td', { class: 'num' }, String(round.keySwitches)),
          el('td', { class: 'num' }, String(round.keySwitchConvolutions)),
          el('td', { class: 'num' }, `${round.ciphertextAdds} / ${round.monomialShifts}`),
        ])
      )
    ),
  ]);

  const costRows: Array<[string, string, string]> = [
    ['Reusable setup sent once', exactBytes(0), exactBytes(r.costs.evaluationKeyBytes)],
    ['Per-query upload', exactBytes(r.costs.directUploadBytes), exactBytes(r.costs.compressedUploadBytes)],
    ['First upload including setup', exactBytes(r.costs.directUploadBytes), exactBytes(firstCompressed)],
    ['Response', exactBytes(r.costs.directResponseBytes), exactBytes(r.costs.compressedResponseBytes)],
    ['Client query encryptions', String(FULL_CATALOG_LENGTH), String(r.blockCount)],
    ['Server record products', String(FULL_CATALOG_LENGTH), String(FULL_CATALOG_LENGTH)],
    [
      'Server expansion key switches',
      '0',
      String(r.blockCount * r.rounds.reduce((n, row) => n + row.keySwitches, 0)),
    ],
    [
      'Exact key-switch convolutions',
      '0',
      String(r.blockCount * r.rounds.reduce((n, row) => n + row.keySwitchConvolutions, 0)),
    ],
    ['Client query build', formatMs(r.timings.directQueryMs), formatMs(r.timings.compressedQueryMs)],
    ['Server expansion', '0 ms', formatMs(r.timings.expansionMs)],
    ['Server record fold', formatMs(r.timings.directFoldMs), formatMs(r.timings.compressedFoldMs)],
  ];
  const costTable = el('table', { class: 'data' }, [
    el(
      'caption',
      {},
      'Measured buffers, executed operation counters and browser timings from this run. Timings are illustrative, not paper benchmarks.'
    ),
    el('thead', {}, el('tr', {}, [el('th', {}, 'Cost'), el('th', {}, 'Direct one-hot'), el('th', {}, 'Compressed + expansion')])),
    el(
      'tbody',
      {},
      costRows.map(([label, direct, compressed]) =>
        el('tr', {}, [el('th', { scope: 'row' }, label), el('td', {}, direct), el('td', {}, compressed)])
      )
    ),
  ]);

  const noiseTable = el('table', { class: 'data' }, [
    el('caption', {}, 'Teacher-side invariant-noise measurements. A server cannot make these measurements because it has no secret key.'),
    el('thead', {}, el('tr', {}, [el('th', {}, 'Ciphertext state'), el('th', { class: 'num' }, 'Budget left')])),
    el('tbody', {}, [
      noiseRow('Modulus ceiling', r.noise.ceiling),
      noiseRow('Direct selectors — minimum', r.noise.directSelectorMinimum),
      noiseRow('Four compressed blocks — minimum before expansion', r.noise.compressedBlockMinimum),
      noiseRow('Expanded selectors — minimum', r.noise.expandedSelectorMinimum),
      noiseRow('Expanded selected Enc(1)', r.noise.expandedSelected),
      noiseRow('Direct answer', r.noise.directAnswer),
      noiseRow('Four compressed responses — minimum', r.noise.compressedAnswerMinimum),
      noiseRow('Selected compressed response', r.noise.compressedSelectedAnswer),
      noiseRow('Four block responses summed — discarded trial', r.noise.combinedAnswer),
    ]),
  ]);

  return el('div', {}, [
    verdict(success ? 'pass' : 'fail', [
      el(
        'strong',
        {},
        success
          ? `Both full-catalog routes returned position ${r.globalIndex}, byte for byte. `
          : 'The two routes did not produce the same tagged record. '
      ),
      success
        ? `The direct decrypt, expanded-query decrypt and plain record all agree; the SHA-256 record tag is intact on both paths.`
        : `No success claim is made. Inspect the noise ledger below; this bounded teaching model stops being correct when its budget is exhausted.`,
    ]),
    el('span', { class: 'code', 'data-role': 'expanded-record' }, r.compressedText),
    kv([
      ['Selected record', `${r.globalIndex} — ${r.title}`],
      [
        'Client-only selection',
        `block ${r.selectedBlock} of ${r.blockCount - 1}; local index ${r.localIndex} — neither value is serialized as a plaintext field`,
      ],
      [
        'Compressed plaintexts',
        `block ${r.selectedBlock} encrypts ${r.inverseScale} · X^${r.localIndex}; the other ${
          r.blockCount - 1
        } blocks encrypt zero; ${EXPANSION_SELECTION_LENGTH} · ${r.inverseScale} ≡ 1 (mod 17)`,
      ],
      ['Ring', `n = 1024, q = ${EXPANSION_MODULUS} (2^27 − 39), t = 17`],
      ['HES modulus-bit comparison', r.securitySummary],
      ['Binary gadget', `${r.digitCount} digits per switch key`],
      ['Evaluation-key generation + serialization', `${r.costs.keySamples} noisy RLWE samples; ${formatMs(r.timings.evaluationKeyMs)}`],
      ['Amortized upload crossover', `compressed cumulative upload becomes smaller on query ${r.costs.crossoverQueries}`],
    ]),
    el(
      'p',
      { class: 'inline-note' },
      `“One ciphertext” describes each 16-record block, not this whole 64-record query. The ` +
        `${formatBytes(r.costs.evaluationKeyBytes)} evaluation-key payload is reusable, so the first compressed run is larger. ` +
        `Repeated queries amortize it, but the server still expands ${r.blockCount} blocks, touches all ${FULL_CATALOG_LENGTH} ` +
        `records and returns ${r.blockCount} fixed ciphertexts so the selected block is not exposed.`
    ),
    el('h4', {}, 'Expansion trace'),
    scroller('Compressed-query expansion trace', traceTable),
    el('h4', {}, 'Measured cost ledger'),
    scroller('Direct and compressed query cost comparison', costTable),
    el('h4', {}, 'Noise paid for key switching'),
    scroller('Noise budget through direct and compressed routes', noiseTable),
    verdict(r.combinedFailure ? 'alarm' : 'info', [
      el('strong', {}, 'Discarded one-response trial. '),
      r.combinedFailure
        ? `In this run, adding all four block responses exhausted the measured noise budget and produced ${r.combinedFailure}. `
        : `In this run, the sum happened to decode with only ${r.noise.combinedAnswer.toFixed(2)} bits of measured budget. `,
      `The outcome is sample-dependent and lacks a dependable margin, so the teaching adaptation returns all four fixed responses instead.`,
    ]),
    disclose('Independent correctness checks from this run', [
      el('p', {}, `Plain record: ${r.expectedText}`),
      el('p', {}, `Direct route: ${r.directText}`),
      el('p', {}, `Compressed route, selected response: ${r.compressedText}`),
      el(
        'p',
        {},
        `The comparison does not ask one implementation to certify itself: both decrypted byte arrays are checked against the separately built catalog record and its embedded SHA-256 decode tag. The other ${
          r.blockCount - 1
        } fixed response ciphertexts are independently required to decrypt to zero; the tag is not an authenticity mechanism against a malicious server.`
      ),
    ]),
  ]);
}

function noiseRow(label: string, bits: number): HTMLTableRowElement {
  return el('tr', {}, [el('th', { scope: 'row' }, label), el('td', { class: 'num' }, `${bits.toFixed(2)} bits`)]);
}

function exactBytes(bytes: number): string {
  return `${bytes} B (${formatBytes(bytes)})`;
}

function scopeNotes(): HTMLElement {
  return el('div', {}, [
    el('p', { class: 'callout callout-caveat' }, [
      el('strong', {}, 'The bound is part of the result. '),
      `Each ciphertext expands to exactly ${EXPANSION_SELECTION_LENGTH} selectors. Four fixed blocks cover the entire ` +
        `${FULL_CATALOG_LENGTH}-record, ${EXPANSION_RECORD_BYTES}-byte teaching catalog; all four queries are expanded, all ` +
        `${FULL_CATALOG_LENGTH} records are scanned, and all four responses are returned. This does not claim that one ` +
        `ciphertext under this 27-bit modulus can expand to 64 or 256 correct selectors, and it does not claim sublinear server work.`,
    ]),
    el('p', { class: 'callout' }, [
      el('strong', {}, 'What is implemented. '),
      `The client encrypts one 16⁻¹·Xⁱ block and three zero blocks, then sends all four without a ` +
        `plaintext block or index field. The server deserializes each ciphertext and executes the same odd ` +
        `substitution schedule as `,
      el(
        'a',
        {
          href: 'https://github.com/microsoft/SealPIR/blob/master/src/pir_server.cpp',
          target: '_blank',
          rel: 'noopener noreferrer',
        },
        'Microsoft SealPIR’s expand_query'
      ),
      `: X→X^(1025, 513, 257, 129), noisy binary-gadget key switching, additions and ` +
        `negacyclic monomial shifts. Dense switch products use an exact two-prime NTT/CRT and ` +
        `are checked against the CRT coefficient bound before reduction.`,
    ]),
    el('p', { class: 'callout callout-caveat' }, [
      el('strong', {}, 'Why four responses return. '),
      `Adding the four block folds has an inadequate, sample-dependent noise margin: deterministic ` +
        `regression samples include both exhausted answers and answers that only barely survive. The ` +
        `page measures and labels the discarded sum from each run. Returning every fixed block ` +
        `response keeps the response shape index-independent and preserves the tested block-level ` +
        `correctness, at four times the response bytes. This is a bounded adaptation, not SealPIR's ` +
        `multi-dimensional recursion or production response path.`,
    ]),
    el('p', { class: 'callout callout-danger' }, [
      el('strong', {}, 'What is not proved. '),
      `The HES 2018 row provides a 27-bit 128-bit-classical ceiling for n=1024 under the ` +
        `standard’s Gaussian-error assumptions. This lab instead samples a centered-binomial error with ` +
        `σ≈3.24, so the row is a reference bit-size comparison, not a parameter certification or a ` +
        `proof of RLWE hardness. It does not assess this JavaScript or by itself justify releasing ` +
        `key-dependent Galois hints. `,
      el(
        'a',
        {
          href: 'https://eprint.iacr.org/2024/1587',
          target: '_blank',
          rel: 'noopener noreferrer',
        },
        'Geelen and Vercauteren'
      ),
      ` explicitly distinguish IND-CPA security without evaluation keys from key-dependent ` +
        `evaluation-key generation, which requires an additional circular-security assumption. ` +
        `Nothing here is constant time or audited.`,
    ]),
    el('p', { class: 'inline-note' }, [
      `Primary construction: Angel, Chen, Laine and Setty, `,
      el(
        'a',
        {
          href: 'https://eprint.iacr.org/2017/1142.pdf',
          target: '_blank',
          rel: 'noopener noreferrer',
        },
        'PIR with Compressed Queries and Amortized Query Processing'
      ),
      `. That paper applies the inverse power-of-two scale to expanded outputs; the Microsoft implementation ` +
        `moves the algebraically equivalent inverse scale into the client monomial, which is the convention used here. ` +
        `The page derives its own bytes, operations, timings and noise and copies no benchmark numbers.`,
    ]),
  ]);
}

function bind(root: HTMLElement, lab: Lab): void {
  root.querySelector<HTMLButtonElement>('[data-role="run-expansion"]')?.addEventListener('click', () => {
    void run(root, lab);
  });
}

async function showStage(root: HTMLElement, lab: Lab, generation: number, stage: string): Promise<boolean> {
  if (generation !== state.generation) return false;
  state.stage = stage;
  redraw(root, lab);
  await nextFrame();
  return generation === state.generation;
}

async function run(root: HTMLElement, lab: Lab): Promise<void> {
  if (state.running) return;
  const initial = lab.snapshot();
  if (initial.selectedIndex >= FULL_CATALOG_LENGTH) {
    state.error = `catalog position ${initial.selectedIndex} is outside the fixed 0 .. ${
      FULL_CATALOG_LENGTH - 1
    } compressed-query database`;
    redraw(root, lab);
    return;
  }
  state.generation += 1;
  const generation = state.generation;
  state.running = true;
  state.stage = 'Building the fixed sixty-four-record comparison database…';
  state.error = null;
  state.retired = null;
  state.result = null;
  redraw(root, lab);
  await nextFrame();

  const version = lab.parameterVersion;
  const snapshot = lab.snapshot();
  const selectedBlock = Math.floor(snapshot.selectedIndex / EXPANSION_SELECTION_LENGTH);
  const localIndex = snapshot.selectedIndex % EXPANSION_SELECTION_LENGTH;
  const entries = shelfEntries(FULL_CATALOG_LENGTH);
  const p = makeParams(EXPANSION_MODULUS, EXPANSION_RECORD_BYTES);
  const rng = lab.random;

  try {
    const records = await Promise.all(
      entries.map((entry) => buildRecord(entryText(entry), EXPANSION_RECORD_BYTES))
    );
    if (generation !== state.generation || version !== lab.parameterVersion) return;
    const plaintexts = shelfToPlaintexts(records, p);
    const sk = keyGen(p, rng);
    const truth = bytesToCoefficients(records[snapshot.selectedIndex], p.n);

    if (!(await showStage(root, lab, generation, 'Encrypting sixty-four direct one-hot selectors…'))) return;
    const directStart = performance.now();
    const directQuery = buildQuery(p, sk, snapshot.selectedIndex, FULL_CATALOG_LENGTH, rng);
    const directQueryMs = performance.now() - directStart;
    const directUploadBytes = serializeQuery(p, directQuery.ciphertexts).length;
    const directFoldStart = performance.now();
    const directAnswer = serverAnswer(p, plaintexts, directQuery.ciphertexts);
    const directFoldMs = performance.now() - directFoldStart;
    const directDecoded = await decodeAnswer(
      p,
      sk,
      directAnswer,
      EXPANSION_RECORD_BYTES,
      truth
    );

    if (!(await showStage(root, lab, generation, 'Generating and serializing the four required Galois keys…'))) return;
    const evaluationStart = performance.now();
    const generatedKeys = generateEvaluationKeys(p, sk, EXPANSION_SELECTION_LENGTH, rng);
    const evaluationKeyWire = serializeEvaluationKeys(p, generatedKeys);
    const evaluationKeyMs = performance.now() - evaluationStart;
    // The server consumes the wire representation, not the in-memory client object.
    const serverKeys = deserializeEvaluationKeys(p, evaluationKeyWire);

    if (!(await showStage(root, lab, generation, 'Encrypting four fixed blocks and round-tripping their wire bytes…'))) return;
    const compressedStart = performance.now();
    const compressedQueries = Array.from({ length: FULL_CATALOG_BLOCKS }, (_, block) =>
      buildCompressedQuery(
        p,
        sk,
        block === selectedBlock ? localIndex : null,
        EXPANSION_SELECTION_LENGTH,
        rng
      )
    );
    const compressedQueryMs = performance.now() - compressedStart;
    const compressedWires = compressedQueries.map((query) =>
      serializeCiphertext(p, query.ciphertext)
    );
    const serverQueries = compressedWires.map((wire) => ({
      ciphertext: deserializeCiphertext(p, wire),
      selectionLength: EXPANSION_SELECTION_LENGTH,
    }));

    if (!(await showStage(root, lab, generation, 'Expanding all four ciphertext blocks through four rounds each…'))) return;
    const expansionStart = performance.now();
    const expansions = serverQueries.map((query) =>
      expandCompressedQuery(p, query, serverKeys)
    );
    const expansionMs = performance.now() - expansionStart;

    if (!(await showStage(root, lab, generation, 'Folding all sixty-four records into four fixed responses…'))) return;
    const compressedFoldStart = performance.now();
    const compressedAnswers = expansions.map((expansion, block) =>
      serverAnswer(
        p,
        plaintexts.slice(
          block * EXPANSION_SELECTION_LENGTH,
          (block + 1) * EXPANSION_SELECTION_LENGTH
        ),
        expansion.ciphertexts
      )
    );
    const compressedFoldMs = performance.now() - compressedFoldStart;
    const compressedAnswer = compressedAnswers[selectedBlock];
    const compressedDecoded = await decodeAnswer(
      p,
      sk,
      compressedAnswer,
      EXPANSION_RECORD_BYTES,
      truth
    );
    const combinedAnswer = compressedAnswers.reduce((sum, answer) =>
      addCiphertext(p, sum, answer)
    );
    const combinedDecoded = await decodeAnswer(
      p,
      sk,
      combinedAnswer,
      EXPANSION_RECORD_BYTES,
      truth
    );
    if (generation !== state.generation || version !== lab.parameterVersion) return;

    const expectedText = recordText(records[snapshot.selectedIndex]);
    const directText = recordText(directDecoded.bytes);
    const compressedText = recordText(compressedDecoded.bytes);
    const directCorrect =
      directDecoded.failure === null &&
      sameBytes(directDecoded.bytes, records[snapshot.selectedIndex]);
    const zero = zeroPoly(p.n);
    const zeroResponsesCorrect = compressedAnswers.every(
      (answer, block) =>
        block === selectedBlock ||
        decrypt(p, sk, answer).every((coefficient) => coefficient === 0)
    );
    const compressedCorrect =
      compressedDecoded.failure === null &&
      sameBytes(compressedDecoded.bytes, records[snapshot.selectedIndex]) &&
      zeroResponsesCorrect;
    const routesAgree = sameBytes(directDecoded.bytes, compressedDecoded.bytes);

    const one = zeroPoly(p.n);
    one[0] = 1;
    const monomial = zeroPoly(p.n);
    monomial[localIndex] = compressedQueries[selectedBlock].inverseScale;
    const directSelectorMinimum = Math.min(
      ...directQuery.ciphertexts.map((ct, i) =>
        noiseBudgetBits(p, sk, ct, i === snapshot.selectedIndex ? one : zero)
      )
    );
    const compressedBlockBudgets = compressedQueries.map((query, block) =>
      noiseBudgetBits(p, sk, query.ciphertext, block === selectedBlock ? monomial : zero)
    );
    const expandedBudgets = expansions.flatMap((expansion, block) =>
      expansion.ciphertexts.map((ct, i) =>
        noiseBudgetBits(p, sk, ct, block === selectedBlock && i === localIndex ? one : zero)
      )
    );
    const responseBudgets = compressedAnswers.map((answer, block) =>
      noiseBudgetBits(p, sk, answer, block === selectedBlock ? truth : zero)
    );
    const directResponseBytes = serializeCiphertext(p, directAnswer).length;
    const compressedUploadBytes = compressedWires.reduce((sum, wire) => sum + wire.length, 0);
    const compressedResponseBytes = compressedAnswers.reduce(
      (sum, answer) => sum + serializeCiphertext(p, answer).length,
      0
    );
    const uploadDifference = directUploadBytes - compressedUploadBytes;
    const crossoverQueries =
      uploadDifference > 0
        ? Math.floor(evaluationKeyWire.length / uploadDifference) + 1
        : Number.POSITIVE_INFINITY;
    const security = assessSecurity(p);

    state.result = {
      globalIndex: snapshot.selectedIndex,
      localIndex,
      selectedBlock,
      blockCount: FULL_CATALOG_BLOCKS,
      title: entries[snapshot.selectedIndex].title,
      expectedText,
      directText,
      compressedText,
      directCorrect,
      compressedCorrect,
      routesAgree,
      combinedFailure: combinedDecoded.failure?.code ?? null,
      inverseScale: compressedQueries[selectedBlock].inverseScale,
      digitCount: serverKeys.digitCount,
      costs: {
        directUploadBytes,
        compressedUploadBytes,
        evaluationKeyBytes: evaluationKeyWire.length,
        directResponseBytes,
        compressedResponseBytes,
        keySamples: serverKeys.keys.length * serverKeys.digitCount,
        crossoverQueries,
      },
      timings: {
        directQueryMs,
        directFoldMs,
        evaluationKeyMs,
        compressedQueryMs,
        expansionMs,
        compressedFoldMs,
      },
      noise: {
        ceiling: maxBudgetBits(p),
        directSelectorMinimum,
        compressedBlockMinimum: Math.min(...compressedBlockBudgets),
        expandedSelectorMinimum: Math.min(...expandedBudgets),
        expandedSelected:
          expandedBudgets[
            selectedBlock * EXPANSION_SELECTION_LENGTH + localIndex
          ],
        directAnswer: directDecoded.budgetBits,
        compressedAnswerMinimum: Math.min(...responseBudgets),
        compressedSelectedAnswer: compressedDecoded.budgetBits,
        combinedAnswer: combinedDecoded.budgetBits,
      },
      rounds: expansions[0].rounds,
      securitySummary: security.summary,
    };
    // The security assessment is retained in the result so a future parameter
    // edit cannot silently sever the table check; render it in the scope card.
    if (!security.atOrBelow128BitCeiling || security.logQ !== 27) {
      throw new Error(`expansion parameters left their declared HES bit-ceiling comparison: ${security.summary}`);
    }
    state.running = false;
    state.stage = null;
    redraw(root, lab);
  } catch (error) {
    if (generation !== state.generation) return;
    state.running = false;
    state.stage = null;
    state.result = null;
    state.error = error instanceof Error ? error.message : String(error);
    redraw(root, lab);
  }
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
  return true;
}

function announce(root: HTMLElement, text: string): void {
  if (root.parentElement) panelStatus(root.parentElement, text);
}

function redraw(root: HTMLElement, lab: Lab): void {
  withFocusRestored(root, () => renderExpand(root, lab));
}
