import {
  append,
  card,
  clear,
  disclose,
  el,
  kv,
  nextFrame,
  panelStatus,
  withFocusRestored,
  scroller,
  verdict,
} from './dom';
import type { Lab } from './state';
import { buildQuery, decodeAnswer, serverAnswer, type DecodedAnswer } from '../pir/pir';
import { maxBudgetBits, predictedBudgetBits, keyGen } from '../pir/bfv';
import { bytesToCoefficients, recordText } from '../pir/records';
import {
  assertExactArithmetic,
  makeParams,
  MODULI,
  RECORD_SIZES,
  SHELF_SIZES,
} from '../pir/params';
import { assessSecurity } from '../pir/security';
import { FAILURE_CODES, isPirError, PirError } from '../pir/errors';
import { Rng } from '../pir/rng';
import { shelfToPlaintexts } from '../pir/records';

/**
 * Act five: push it until it breaks, then read the failure codes.
 *
 * Three knobs, all of which move real arithmetic — the ciphertext modulus, the
 * record size and the shelf length. Two of them buy payload and cost budget; the
 * third buys budget and, past a point, costs the only security estimate this
 * lab can honestly quote.
 *
 * The exhaustion is not simulated. At the smallest modulus a sixty-four-record
 * answer genuinely decrypts to garbage, the record's own integrity tag genuinely
 * fails, and coefficients genuinely come back outside the range the encoder can
 * produce. All three are reported separately, because two of them are checks a
 * real client could actually run and the third is not.
 */

interface Failure {
  code: string;
  detail: string;
}

interface PanelState {
  decoded: DecodedAnswer | null;
  text: string;
  running: boolean;
  /**
   * A failure raised by the RETRIEVE button, and only that button.
   *
   * Kept separate from `tripFailure` because the two are different events with
   * different meanings, and one field for both meant that pressing a demo
   * failure-code button silently replaced the retrieval verdict at the top of the
   * panel with a red failure that retrieval never produced.
   */
  runFailure: Failure | null;
  /** A failure raised by one of the four demonstration buttons. */
  tripFailure: Failure | null;
  /** Why the last retrieval was thrown away, or null if none was. */
  retired: string | null;
}

const state: PanelState = {
  decoded: null,
  text: '',
  running: false,
  runFailure: null,
  tripFailure: null,
  retired: null,
};

/**
 * Discard the retrieval, and REMEMBER WHY.
 *
 * The whole point of this panel is that a budget figure belongs to one exact
 * parameter set. Carrying a verdict across a modulus change would be the single
 * most misleading thing this page could do, so it is discarded — and the reason
 * is printed, because a silently empty panel reads as "not run yet".
 */
export function resetNoise(reason?: string): void {
  // `|| state.retired` matters: after the first retirement there is no result
  // left to guard on, so without it a SECOND parameter change would leave the
  // first change's reason on screen — a retirement notice naming the wrong cause
  // is worse than none.
  if (state.decoded || state.runFailure || state.retired) state.retired = reason ?? null;
  state.decoded = null;
  state.text = '';
  state.runFailure = null;
  state.tripFailure = null;
}

export function renderNoise(root: HTMLElement, lab: Lab): void {
  const s = lab.snapshot();
  const assessment = assessSecurity(s.params);
  clear(root);

  append(
    root,
    card('Push it until it breaks', [
      el(
        'p',
        { class: 'lede' },
        `Every record the server folds in adds its own encryption error to the answer, whether or ` +
          `not that record was the one you wanted. Longer shelf, bigger records, or a smaller ` +
          `modulus — all three walk the budget down to zero, and at zero the answer decrypts to ` +
          `nonsense that looks exactly like a record until you check it.`
      ),
      el('div', { class: 'controls' }, [
        el('div', { class: 'field' }, [
          el('label', { for: 'noise-modulus' }, 'Ciphertext modulus q'),
          el(
            'select',
            { id: 'noise-modulus', 'data-role': 'modulus' },
            MODULI.map((option) =>
              el(
                'option',
                { value: option.logQ, selected: option.logQ === s.modulus.logQ },
                `${option.label} (${option.q})`
              )
            )
          ),
        ]),
        el('div', { class: 'field' }, [
          el('label', { for: 'noise-record' }, 'Record size'),
          el(
            'select',
            { id: 'noise-record', 'data-role': 'record' },
            RECORD_SIZES.map((size) =>
              el('option', { value: size, selected: size === s.recordBytes }, `${size} bytes`)
            )
          ),
        ]),
        el('div', { class: 'field' }, [
          el('label', { for: 'noise-shelf' }, 'Shelf length N'),
          el(
            'select',
            { id: 'noise-shelf', 'data-role': 'shelf' },
            SHELF_SIZES.map((size) =>
              el('option', { value: size, selected: size === s.shelfSize }, `${size} records`)
            )
          ),
        ]),
        el(
          'button',
          {
            class: 'btn btn-primary',
            type: 'button',
            'data-role': 'run',
            disabled: state.running,
          },
          state.running ? 'Running…' : 'Retrieve at these settings'
        ),
      ]),
      el('div', { 'data-role': 'out' }, runOutput(lab)),
    ])
  );

  append(
    root,
    card('The parameters, judged against a published table', [
      assessment.inTable
        ? verdict('pass', [el('strong', {}, 'Inside the table. '), assessment.summary])
        : verdict('fail', [
            el('span', { class: 'fail-code' }, 'PARAM_UNSAFE'),
            ' — ',
            assessment.summary,
          ]),
      kv([
        ['Ring degree n', String(s.params.n)],
        ['log2 q (ceiled)', String(assessment.logQ)],
        ['128-bit ceiling for this n', assessment.ceiling128 === null ? 'not tabulated' : String(assessment.ceiling128)],
        ['Secret distribution', 'uniform ternary'],
        ['Error distribution', `centred binomial, eta = ${s.params.eta}, sigma = ${Math.sqrt(s.params.eta / 2).toFixed(3)}`],
        ['Fresh budget ceiling', `${maxBudgetBits(s.params).toFixed(2)} bits`],
      ]),
      el(
        'p',
        { class: 'callout callout-caveat' },
        [
          el('strong', {}, 'What "inside the table" is worth. '),
          `The Homomorphic Encryption Security Standard (HomomorphicEncryption.org, November 2018) ` +
            `tabulates, for each ring degree, the largest modulus at which the underlying RLWE ` +
            `problem was estimated to reach a given security level. A row is an estimate from 2018, ` +
            `not a proof and not a current one. It also says nothing about this implementation: the ` +
            `arithmetic here is not constant time, the secret key sits in ordinary browser memory, ` +
            `and none of it has been audited. Passing the table means the parameters are not ` +
            `obviously broken. It does not mean this page is secure, and it is not.`,
        ]
      ),
      budgetTable(lab),
    ])
  );

  append(root, card('The failure codes', failureLab()));

  announce(root, noiseHeadline(s.selectedIndex, assessment.inTable));

  bind(root, lab);
}

function noiseHeadline(index: number, inTable: boolean): string {
  if (state.runFailure) return `${state.runFailure.code}: the retrieval was refused.`;
  const params = inTable
    ? 'Parameters inside the published table.'
    : 'PARAM_UNSAFE: parameters outside the published table.';
  if (state.running) return `${params} Running a retrieval.`;
  if (state.decoded) {
    return state.decoded.failure
      ? `${params} ${state.decoded.failure.code}: the answer came back and is wrong.`
      : `${params} Retrieved position ${index} with ` +
        `${state.decoded.budgetBits.toFixed(2)} bits of budget left.`;
  }
  if (state.retired) return `${params} Previous result retired: ${state.retired}.`;
  return `${params} No retrieval run yet.`;
}

function runOutput(lab: Lab): HTMLElement {
  if (state.running) return el('p', { class: 'status-line' }, 'Encrypting, folding, decoding…');
  if (state.runFailure) {
    return verdict('fail', [
      el('span', { class: 'fail-code' }, state.runFailure.code),
      ' — ',
      state.runFailure.detail,
    ]);
  }
  if (!state.decoded) {
    return state.retired
      ? verdict('info', [
          el('strong', {}, 'Result retired: '),
          `${state.retired}. A noise budget belongs to one exact parameter set, so the previous ` +
            `verdict was discarded rather than left beside settings it was not measured under.`,
        ])
      : el(
          'p',
          { class: 'status-line' },
          'Not run yet. Change a setting and retrieve, or retrieve at the defaults first for a baseline.'
        );
  }
  const s = lab.snapshot();
  const d = state.decoded;
  const entry = s.entries[s.selectedIndex];
  return el('div', {}, [
    d.failure
      ? verdict('fail', [
          el('span', { class: 'fail-code' }, d.failure.code),
          ' — the answer came back, and it is wrong. ',
          `Budget ${d.budgetBits.toFixed(2)} bits, ${d.outOfRange} coefficient(s) outside the ` +
            `encodable range, integrity tag ${d.tagOk ? 'intact' : 'broken'}.`,
        ])
      : verdict('pass', [
          el('strong', {}, `Retrieved position ${s.selectedIndex}: ${entry.title}. `),
          `Budget ${d.budgetBits.toFixed(2)} bits remaining, tag intact.`,
        ]),
    el('h4', {}, 'What the client actually decoded'),
    el('code', { class: 'code' }, state.text || '(no printable text)'),
    kv([
      ['Measured budget', `${d.budgetBits.toFixed(2)} bits`],
      ['Six-sigma prediction', `${predictedBudgetBits(s.params, s.shelfSize).toFixed(2)} bits`],
      ['Coefficients out of range', `${d.outOfRange} of ${s.params.coeffsUsed}`],
      ['Integrity tag', d.tagOk ? 'matches' : 'does not match'],
    ]),
    el(
      'p',
      { class: 'inline-note' },
      `The out-of-range count and the tag check are things a real client could do for itself; the ` +
        `budget is not, because measuring it needs the secret key AND the true record, and a ` +
        `client that had the record would not be asking. Note how unequal the two client-side ` +
        `checks are: just past the ceiling most coefficients still decode correctly and the few ` +
        `that drift land on other legal nibbles, so the out-of-range count is often ZERO while the ` +
        `record is already wrong. The tag is what notices. That is why a PIR deployment sizes its ` +
        `parameters in advance and does not discover exhaustion at runtime.`
    ),
  ]);
}

/**
 * The predicted budget across every shelf length at the current settings.
 *
 * Prediction, clearly labelled: it is computed from N, the record size, t and
 * eta with no ciphertext involved. It is drawn so the shape — one bit of budget
 * per four-fold growth in the shelf — is visible before the reader spends a
 * click finding out.
 */
function budgetTable(lab: Lab): HTMLElement {
  const s = lab.snapshot();
  const table = el('table', { class: 'data' }, [
    el(
      'caption',
      {},
      `Predicted remaining budget at ${s.modulus.label}, ${s.recordBytes}-byte records. Six-sigma ` +
        `bound from the parameters — no ciphertext involved. Anything at or below zero cannot be ` +
        `decrypted.`
    ),
    el(
      'thead',
      {},
      el('tr', {}, [
        el('th', { class: 'num' }, 'Shelf length'),
        el('th', { class: 'num' }, 'Predicted budget'),
        el('th', {}, 'Verdict'),
      ])
    ),
    el(
      'tbody',
      {},
      SHELF_SIZES.map((size) => {
        const bits = predictedBudgetBits(s.params, size);
        return el('tr', {}, [
          el('td', { class: 'num' }, String(size)),
          el('td', { class: 'num' }, `${bits.toFixed(2)} bits`),
          el(
            'td',
            {},
            bits <= 0
              ? el('span', { class: 'pill pill-bad' }, ['✕ exhausted'])
              : bits < 3
                ? el('span', { class: 'pill pill-warn' }, ['⚠ thin'])
                : el('span', { class: 'pill pill-ok' }, ['✓ decodable'])
          ),
        ]);
      })
    ),
  ]);
  return scroller('Predicted budget by shelf length', table);
}

function failureLab(): HTMLElement {
  return el('div', {}, [
    el(
      'p',
      { class: 'lede' },
      `Four codes, each raised by real code on a real input — and they divide in two. Three are ` +
        `REFUSALS: the protocol stops before it can produce an answer at all. The fourth, ` +
        `NOISE_BUDGET_EXHAUSTED, is a REPORT, and deliberately so — nothing can stop it, because ` +
        `the ciphertext decrypts perfectly well and simply yields the wrong bytes. The whole ` +
        `point is that a PIR answer which is quietly wrong looks exactly like one that is quietly ` +
        `right, since the client cannot see the database. Naming it is all anyone can do.`
    ),
    el(
      'ul',
      { class: 'stack-list', role: 'list' },
      FAILURE_CODES.map((code) =>
        el('li', { role: 'listitem' }, [
          el('span', { class: 'fail-code' }, code),
          ' — ',
          FAILURE_BLURB[code],
        ])
      )
    ),
    el('div', { class: 'controls' }, [
      el(
        'button',
        { class: 'btn', type: 'button', 'data-role': 'trip-dim' },
        'Trip DIM_MISMATCH'
      ),
      el(
        'button',
        { class: 'btn', type: 'button', 'data-role': 'trip-index' },
        'Trip INDEX_OUT_OF_RANGE'
      ),
      el(
        'button',
        { class: 'btn', type: 'button', 'data-role': 'trip-param' },
        'Trip PARAM_UNSAFE'
      ),
      el(
        'button',
        { class: 'btn', type: 'button', 'data-role': 'trip-noise' },
        'Trip NOISE_BUDGET_EXHAUSTED'
      ),
      el('button', { class: 'btn', type: 'button', 'data-role': 'trip-clear' }, 'Clear'),
    ]),
    el(
      'div',
      { 'data-role': 'trip-out' },
      state.tripFailure
        ? verdict('fail', [
            el('span', { class: 'fail-code' }, state.tripFailure.code),
            ' — ',
            state.tripFailure.detail,
          ])
        : el('p', { class: 'status-line' }, 'No failure raised. Press one of the buttons above.')
    ),
    disclose('Why a malformed query is not on this list', [
      el(
        'p',
        {},
        `Nothing checks that your selection vector is one-hot, and nothing can: the server cannot ` +
          `read it. Send a vector with two ones and the server answers faithfully — you get the ` +
          `SUM of two records modulo 17, which is neither of them and carries no failure code at ` +
          `all, because no rule was broken.`
      ),
      el(
        'p',
        {},
        `That is a real property of unauthenticated PIR, and it matters: PIR is a privacy ` +
          `mechanism, not an access-control one. A deployment that needs to bound what a client can ` +
          `extract has to add something — a proof that the query is well-formed, or a rate limit, ` +
          `or both. The test suite pins this behaviour so it stays visible.`
      ),
    ]),
  ]);
}

const FAILURE_BLURB: Record<string, string> = {
  NOISE_BUDGET_EXHAUSTED:
    'the accumulated error passed the decryption ceiling; the answer decrypts, to garbage.',
  DIM_MISMATCH:
    'the query is not the same length as the shelf, so it would answer over a prefix or read past ' +
    'the end. Refused before any homomorphic work.',
  PARAM_UNSAFE:
    'the parameters are outside the published security table, or would push this implementation ' +
    'past the range where JavaScript integers are exact.',
  INDEX_OUT_OF_RANGE: 'the requested shelf position does not exist.',
};

function bind(root: HTMLElement, lab: Lab): void {
  const modulus = root.querySelector<HTMLSelectElement>('[data-role="modulus"]');
  modulus?.addEventListener('change', () => {
    const chosen = MODULI.find((m) => m.logQ === Number(modulus.value));
    if (chosen) void lab.setModulus(chosen);
  });
  const record = root.querySelector<HTMLSelectElement>('[data-role="record"]');
  record?.addEventListener('change', () => void lab.setRecordBytes(Number(record.value)));
  const shelf = root.querySelector<HTMLSelectElement>('[data-role="shelf"]');
  shelf?.addEventListener('change', () => void lab.setShelfSize(Number(shelf.value)));

  root.querySelector<HTMLButtonElement>('[data-role="run"]')?.addEventListener('click', () => {
    void run(root, lab);
  });

  root.querySelector<HTMLButtonElement>('[data-role="trip-clear"]')?.addEventListener('click', () => {
    state.tripFailure = null;
    redraw(root, lab);
  });
  root.querySelector<HTMLButtonElement>('[data-role="trip-dim"]')?.addEventListener('click', () => {
    trip(root, lab, () => {
      const s = lab.snapshot();
      const half = Math.max(1, Math.floor(s.shelfSize / 2));
      const query = buildQuery(s.params, s.sk, 0, half, lab.random);
      serverAnswer(s.params, s.plaintexts, query.ciphertexts);
    });
  });
  root.querySelector<HTMLButtonElement>('[data-role="trip-index"]')?.addEventListener('click', () => {
    trip(root, lab, () => {
      const s = lab.snapshot();
      buildQuery(s.params, s.sk, s.shelfSize, s.shelfSize, lab.random);
    });
  });
  root.querySelector<HTMLButtonElement>('[data-role="trip-param"]')?.addEventListener('click', () => {
    trip(root, lab, () => {
      const s = lab.snapshot();
      // A modulus far past anything selectable, to reach the exactness guard
      // rather than the security table — both raise PARAM_UNSAFE, and this is
      // the branch the table above does not already show.
      assertExactArithmetic({ ...s.params, q: 2 ** 44 });
    });
  });
  root.querySelector<HTMLButtonElement>('[data-role="trip-noise"]')?.addEventListener('click', () => {
    void tripNoise(root, lab);
  });
}

function trip(root: HTMLElement, lab: Lab, fn: () => void): void {
  try {
    fn();
    state.tripFailure = {
      code: 'no failure',
      detail: 'that input was accepted — which is itself worth knowing about.',
    };
  } catch (e) {
    state.tripFailure = isPirError(e)
      ? { code: e.code, detail: e.detail }
      : { code: 'UNEXPECTED', detail: String(e) };
  }
  redraw(root, lab);
}

/**
 * Raise NOISE_BUDGET_EXHAUSTED for real, without disturbing the lab's own
 * settings: run a complete retrieval at the smallest modulus on a private key
 * and a private shelf encoding, and report what came back.
 */
async function tripNoise(root: HTMLElement, lab: Lab): Promise<void> {
  const s = lab.snapshot();
  const tiny = makeParams(MODULI[0].q, s.recordBytes);
  const rng = Rng.fromEntropy();
  const sk = keyGen(tiny, rng);
  const plaintexts = shelfToPlaintexts(s.records as Uint8Array[], tiny);
  const query = buildQuery(tiny, sk, s.selectedIndex, s.shelfSize, rng);
  const answer = serverAnswer(tiny, plaintexts, query.ciphertexts);
  const decoded = await decodeAnswer(
    tiny,
    sk,
    answer,
    s.recordBytes,
    bytesToCoefficients(s.records[s.selectedIndex], tiny.n)
  );
  state.tripFailure = decoded.failure
    ? { code: decoded.failure.code, detail: decoded.failure.detail }
    : {
        code: 'no failure',
        detail: `the ${MODULI[0].label} modulus carried a ${s.shelfSize}-record answer after all — ` +
          `budget ${decoded.budgetBits.toFixed(2)} bits.`,
      };
  redraw(root, lab);
}

async function run(root: HTMLElement, lab: Lab): Promise<void> {
  if (state.running) return;
  state.running = true;
  state.runFailure = null;
  state.retired = null;
  redraw(root, lab);
  await nextFrame();

  const s = lab.snapshot();
  try {
    const query = buildQuery(s.params, s.sk, s.selectedIndex, s.shelfSize, lab.random);
    const answer = serverAnswer(s.params, s.plaintexts, query.ciphertexts);
    const decoded = await decodeAnswer(
      s.params,
      s.sk,
      answer,
      s.recordBytes,
      bytesToCoefficients(s.records[s.selectedIndex], s.params.n)
    );
    state.decoded = decoded;
    state.text = recordText(decoded.bytes);
  } catch (e) {
    state.decoded = null;
    state.text = '';
    state.runFailure =
      e instanceof PirError
        ? { code: e.code, detail: e.detail }
        : { code: 'UNEXPECTED', detail: String(e) };
  }
  state.running = false;
  redraw(root, lab);
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
  withFocusRestored(root, () => renderNoise(root, lab));
}
