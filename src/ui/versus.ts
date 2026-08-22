import {
  append,
  card,
  clear,
  disclose,
  el,
  formatBytes,
  formatMs,
  nextFrame,
  panelStatus,
  withFocusRestored,
  scroller,
  verdict,
} from './dom';
import type { Lab } from './state';
import { buildQuery, decodeAnswer, serverAnswer } from '../pir/pir';
import { serializeCiphertext, serializeQuery } from '../pir/serialize';
import { bytesToCoefficients } from '../pir/records';
import {
  buildXorQuery,
  colludeRecoverIndex,
  combineXorAnswers,
  xorAnswer,
  type XorQuery,
} from '../pir/xorpir';

/**
 * Act four: one server against two, on the same shelf, with measured numbers.
 *
 * Both protocols run here, on this page, over the identical 64 records. Nothing
 * is quoted from a paper and nothing is quoted from a sibling lab — Oblivious
 * Shelf runs the same Chor et al. scheme over a sixteen-entry shelf of single
 * BITS, so its costs are not these costs and citing them would be a category
 * error. The XOR implementation in `xorpir.ts` exists precisely so this
 * comparison can be a measurement.
 *
 * The honest headline is that two servers win on every number in the table. The
 * column that decides it is the last one.
 */

interface Measurement {
  uploadBytes: number;
  downloadBytes: number;
  clientMs: number;
  serverMs: number;
  correct: boolean;
}

interface PanelState {
  lattice: Measurement | null;
  xor: (Measurement & { query: XorQuery }) | null;
  colluded: number | null;
  running: boolean;
  /** Why the last measurement was thrown away, or null if none was. */
  retired: string | null;
}

const state: PanelState = {
  lattice: null,
  xor: null,
  colluded: null,
  running: false,
  retired: null,
};

/**
 * Discard the measurements, and REMEMBER WHY.
 *
 * Bytes and milliseconds measured at one modulus, record size or shelf length
 * are not comparable with another, so they cannot survive a parameter change.
 * Dropping them silently would leave a reader unable to tell a retired result
 * from one that was never run — so the reason is kept and printed.
 */
export function resetVersus(reason?: string): void {
  // `|| state.retired` so a SECOND parameter change updates the reason rather
  // than leaving the first one's wording beside the second one's cause.
  if (state.lattice || state.xor || state.retired) state.retired = reason ?? null;
  state.lattice = null;
  state.xor = null;
  state.colluded = null;
}

export function renderVersus(root: HTMLElement, lab: Lab): void {
  const s = lab.snapshot();
  clear(root);

  append(
    root,
    card('Run both protocols over the same shelf', [
      el(
        'p',
        { class: 'lede' },
        `Position ${s.selectedIndex}, ${s.recordBytes}-byte records, ${s.shelfSize} of them. ` +
          `Single-server RLWE PIR and two-server XOR PIR both retrieve it here, in this page, and ` +
          `every number below is taken from the run — bytes by serializing, milliseconds by ` +
          `timing the calls.`
      ),
      el('div', { class: 'controls' }, [
        el(
          'button',
          { class: 'btn btn-primary', type: 'button', 'data-role': 'run', disabled: state.running },
          state.running ? 'Running…' : 'Run both'
        ),
        el(
          'button',
          {
            class: 'btn btn-danger',
            type: 'button',
            'data-role': 'collude',
            disabled: !state.xor,
          },
          'Let the two servers compare notes'
        ),
      ]),
      el('div', { 'data-role': 'out' }, output(lab)),
    ])
  );

  append(root, card('What the numbers do not say', [honestyNotes(s.shelfSize)]));

  announce(root, versusHeadline(s.shelfSize));

  bind(root, lab);
}

function versusHeadline(shelfSize: number): string {
  if (state.running) return 'Running both protocols and timing them.';
  if (state.colluded !== null) {
    return `The two servers compared masks and recovered shelf position ${state.colluded}.`;
  }
  if (state.lattice && state.xor) {
    return (
      `Both protocols retrieved the record over ${shelfSize} positions. ` +
      `Single-server upload ${formatBytes(state.lattice.uploadBytes)}, ` +
      `two-server upload ${formatBytes(state.xor.uploadBytes)}.`
    );
  }
  if (state.retired) return `Measurements retired: ${state.retired}.`;
  return 'Nothing measured yet.';
}

function output(lab: Lab): HTMLElement {
  if (state.running) return el('p', { class: 'status-line' }, 'Encrypting, folding and timing…');
  if (!state.lattice || !state.xor) {
    return state.retired
      ? verdict('info', [
          el('strong', {}, 'Measurements retired: '),
          `${state.retired}. Bytes and timings taken under different parameters are not ` +
            `comparable, so the previous run was discarded rather than left on screen. Press Run ` +
            `both to measure again.`,
        ])
      : el(
          'p',
          { class: 'status-line' },
          'Not run yet. Press Run both to measure the two protocols side by side.'
        );
  }
  const s = lab.snapshot();
  const a = state.lattice;
  const b = state.xor;

  const rows: Array<[string, string, string, 'a' | 'b' | 'tie']> = [
    ['Servers required', '1', '2', 'a'],
    ['Trust assumption', 'None between operators', 'The two must never collude', 'a'],
    [
      'Privacy',
      'Computational — decision RLWE',
      'Information-theoretic — unconditional',
      'b',
    ],
    ['Upload per query', formatBytes(a.uploadBytes), formatBytes(b.uploadBytes), 'b'],
    ['Download per query', formatBytes(a.downloadBytes), formatBytes(b.downloadBytes), 'b'],
    ['Client work', formatMs(a.clientMs), formatMs(b.clientMs), 'b'],
    ['Server work', formatMs(a.serverMs), formatMs(b.serverMs), 'b'],
    [
      'Records touched',
      `${s.shelfSize} of ${s.shelfSize}`,
      `about half of ${s.shelfSize}, per server`,
      'tie',
    ],
    ['Can the answer be wrong?', 'Yes — if the noise budget runs out', 'No — XOR is exact', 'b'],
    ['Record returned correctly', a.correct ? 'yes' : 'no', b.correct ? 'yes' : 'no', 'tie'],
  ];

  const table = el('table', { class: 'data' }, [
    el(
      'caption',
      {},
      `Measured on this page, this run: shelf of ${s.shelfSize}, ${s.recordBytes}-byte records, ` +
        `ring degree ${s.params.n}, modulus ${s.modulus.label}.`
    ),
    el(
      'thead',
      {},
      el('tr', {}, [
        el('th', {}, 'Property'),
        el('th', {}, 'Shelf Oracle — 1 server, RLWE'),
        el('th', {}, 'Oblivious Shelf scheme — 2 servers, XOR'),
      ])
    ),
    el(
      'tbody',
      {},
      // WCAG 1.4.1. The winning cell is marked with the WORD "better" as well as
      // the colour, because a reader who cannot see the green would otherwise
      // lose the comparison entirely — and the comparison is the exhibit.
      rows.map(([label, left, right, better]) =>
        el('tr', {}, [
          el('th', { scope: 'row' }, label),
          cell(left, better === 'a'),
          cell(right, better === 'b'),
        ])
      )
    ),
  ]);

  return el('div', {}, [
    scroller('Head-to-head measurements', table),
    el(
      'p',
      { class: 'inline-note' },
      `Each row marks the better cell where "better" is unambiguous. Two servers win every row ` +
        `that is a cost — cheaper, faster, exact. They lose exactly two, and the two are the ` +
        `same fact said twice: this scheme needs one server, so there is no non-collusion ` +
        `assumption to make. That is what the whole noise budget is buying.`
    ),
    collusionOutput(),
  ]);
}

/** One comparison cell: the value, and the word "better" where one side wins. */
function cell(value: string, wins: boolean): HTMLElement {
  return el(
    'td',
    { class: wins ? 'win' : undefined },
    wins ? [value, ' ', el('span', { class: 'win-tag' }, 'better')] : value
  );
}

function collusionOutput(): HTMLElement {
  if (state.colluded === null) {
    return verdict(
      'info',
      'The two-server scheme rests on one assumption. Press the red button to spend it.'
    );
  }
  return el('div', {}, [
    verdict('alarm', [
      el('strong', {}, `The two servers XOR their masks and read off position ${state.colluded}. `),
      `No cryptanalysis, no parameters, no time: the two masks were built to differ in exactly one ` +
        `bit, and that bit is the index. This is not a flaw in the scheme — it is the scheme's ` +
        `stated assumption, failing.`,
    ]),
    verdict(
      'pass',
      `There is no equivalent button for the single-server column. There is only one server, so ` +
        `there is nothing to collude with — which is what the noise budget is buying.`
    ),
  ]);
}

function honestyNotes(shelfSize: number): HTMLElement {
  return el('div', {}, [
    el(
      'p',
      { class: 'callout callout-caveat' },
      [
        el('strong', {}, 'This upload column is not SealPIR’s. '),
        `A real SealPIR client sends ONE ciphertext plus Galois keys and the server expands it into ` +
          `the ${shelfSize}-element selection vector using plaintext substitutions. That turns an ` +
          `upload linear in the shelf into a constant one, and it is the single biggest engineering ` +
          `difference between this page and the paper. Query expansion needs ciphertext rotations ` +
          `and key switching, which are out of scope in a browser — so the number above is what ` +
          `THIS implementation moved, and it is worse than the state of the art by roughly a factor ` +
          `of the shelf length.`,
      ]
    ),
    el(
      'p',
      { class: 'callout callout-caveat' },
      [
        el('strong', {}, 'Nor is it as small as it could be even here. '),
        `The c1 half of every ciphertext is a uniform ring element, so an implementation would send ` +
          `the 32-byte seed it was expanded from instead of the polynomial, halving the upload. ` +
          `This lab serializes both halves because the seed trick would make the byte count depend ` +
          `on a compression choice rather than on the protocol.`,
      ]
    ),
    el(
      'p',
      { class: 'callout' },
      [
        el('strong', {}, 'And the timings are browser timings. '),
        `Both protocols run as ordinary JavaScript in one tab, on whatever machine you are reading ` +
          `this on, with a schoolbook O(n²) polynomial multiply where a real implementation uses a ` +
          `number-theoretic transform. Treat the ratio between the two columns as meaningful and ` +
          `the absolute values as anecdote.`,
      ]
    ),
    disclose('Why the two-server scheme is cheaper, and why that is not the end of it', [
      el(
        'p',
        {},
        `XOR PIR moves one bit of query per record and one record-sized reply per server. RLWE PIR ` +
          `moves a whole ciphertext per record and gets a whole ciphertext back, and a ciphertext ` +
          `is thousands of times larger than the bit it encrypts. That expansion factor is what ` +
          `lattice encryption costs.`
      ),
      el(
        'p',
        {},
        `The comparison is still worth making, because communication is the metric a deployment can ` +
          `usually afford to lose and non-collusion is the one it usually cannot get. Running two ` +
          `servers under genuinely separate operational control — separate staff, separate legal ` +
          `jurisdictions, separate subpoena exposure — is an organisational problem, not a ` +
          `technical one, and it is the reason single-server constructions get built.`
      ),
      el(
        'p',
        {},
        `It is also why the state of the art matters: SealPIR's query expansion and the Spiral and ` +
          `OnionPIR lines of work exist to close exactly the gap this table shows.`
      ),
    ]),
  ]);
}

function bind(root: HTMLElement, lab: Lab): void {
  root.querySelector<HTMLButtonElement>('[data-role="run"]')?.addEventListener('click', () => {
    void run(root, lab);
  });
  root.querySelector<HTMLButtonElement>('[data-role="collude"]')?.addEventListener('click', () => {
    if (!state.xor) return;
    state.colluded = colludeRecoverIndex(state.xor.query);
    redraw(root, lab);
  });
}

async function run(root: HTMLElement, lab: Lab): Promise<void> {
  if (state.running) return;
  state.running = true;
  state.colluded = null;
  state.retired = null;
  redraw(root, lab);
  await nextFrame();

  const s = lab.snapshot();
  const records = s.records as Uint8Array[];

  // ── single-server RLWE ────────────────────────────────────────────────
  const t0 = performance.now();
  const query = buildQuery(s.params, s.sk, s.selectedIndex, s.shelfSize, lab.random);
  const clientBuildMs = performance.now() - t0;
  const uploadBytes = serializeQuery(s.params, query.ciphertexts).length;

  const t1 = performance.now();
  const answer = serverAnswer(s.params, s.plaintexts, query.ciphertexts);
  const latticeServerMs = performance.now() - t1;
  const downloadBytes = serializeCiphertext(s.params, answer).length;

  const t2 = performance.now();
  const decoded = await decodeAnswer(
    s.params,
    s.sk,
    answer,
    s.recordBytes,
    bytesToCoefficients(records[s.selectedIndex], s.params.n)
  );
  const clientDecodeMs = performance.now() - t2;

  state.lattice = {
    uploadBytes,
    downloadBytes,
    clientMs: clientBuildMs + clientDecodeMs,
    serverMs: latticeServerMs,
    correct: decoded.failure === null && sameBytes(decoded.bytes, records[s.selectedIndex]),
  };

  await nextFrame();

  // ── two-server XOR ────────────────────────────────────────────────────
  const t3 = performance.now();
  const xq = buildXorQuery(s.shelfSize, s.selectedIndex, lab.random);
  const xorClientBuildMs = performance.now() - t3;

  const t4 = performance.now();
  const replyA = xorAnswer(records, xq.maskA);
  const replyB = xorAnswer(records, xq.maskB);
  const xorServerMs = performance.now() - t4;

  const t5 = performance.now();
  const combined = combineXorAnswers(replyA, replyB);
  const xorClientCombineMs = performance.now() - t5;

  state.xor = {
    query: xq,
    uploadBytes: xq.maskA.length + xq.maskB.length,
    downloadBytes: replyA.length + replyB.length,
    clientMs: xorClientBuildMs + xorClientCombineMs,
    serverMs: xorServerMs,
    correct: sameBytes(combined, records[s.selectedIndex]),
  };

  state.running = false;
  redraw(root, lab);
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * Announce the panel's headline through the ONE live region `main.ts` created
 * before any render ran. `root` is the panel body; the region is its sibling.
 */
function announce(root: HTMLElement, text: string): void {
  if (root.parentElement) panelStatus(root.parentElement, text);
}

/**
 * Re-render from an event handler WITHOUT throwing the keyboard reader away.
 *
 * A panel rebuilds its whole subtree, which destroys the control the reader is
 * standing on. `main.ts` wraps the renders IT drives; these are the ones the
 * panel drives itself — pressing a button, opening a disclosure, running a
 * measurement — and they are the majority.
 */
function redraw(root: HTMLElement, lab: Lab): void {
  withFocusRestored(root, () => renderVersus(root, lab));
}
