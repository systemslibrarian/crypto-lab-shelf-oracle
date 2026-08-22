import { append, card, clear, disclose, el, kv, nextFrame, verdict } from './dom';
import type { Lab } from './state';
import {
  beginAnswer,
  buildQuery,
  decodeAnswer,
  finishAnswer,
  foldRecord,
  partialMessage,
  type AnswerState,
  type PirQuery,
} from '../pir/pir';
import {
  maxBudgetBits,
  noiseBudgetBits,
  predictedBudgetBits,
  traceCoefficient,
  decrypt,
  type Ciphertext,
} from '../pir/bfv';
import { coefficientsToBytes, recordText, toHex } from '../pir/records';
import { serializeCiphertext } from '../pir/serialize';

/**
 * Act three, and the one mechanism this lab exists to show.
 *
 * sum over i of  R_i * Enc(b_i)  =  Enc(R_index)
 *
 * The reader steps it. Every record on the shelf lights up as the server
 * multiplies it in — ALL of them, which is the cost of the privacy and the
 * reason PIR is linear in the database size. The accumulator's bytes churn and
 * stay unreadable. The noise budget falls, measured rather than estimated. And
 * until the chosen record is folded in, the running ciphertext decrypts to
 * literal zero, which is the most direct way to see that the sum is doing the
 * selecting.
 *
 * At the end, one decryption produces a record the server never identified.
 */

interface PanelState {
  query: PirQuery | null;
  answer: AnswerState | null;
  history: number[];
  finished: boolean;
  decoded: Awaited<ReturnType<typeof decodeAnswer>> | null;
  busy: boolean;
  retired: string | null;
}

const state: PanelState = {
  query: null,
  answer: null,
  history: [],
  finished: false,
  decoded: null,
  busy: false,
  retired: null,
};

/**
 * Throw away the fold in progress, and REMEMBER WHY.
 *
 * A half-folded accumulator is a ciphertext under one key over one shelf. If the
 * shelf or the modulus moves under it, continuing would be arithmetic nonsense —
 * so the run restarts, and the panel says which parameter caused it rather than
 * silently snapping back to step 0.
 */
export function resetFold(reason?: string): void {
  if (state.answer && state.answer.folded > 0) state.retired = reason ?? null;
  state.query = null;
  state.answer = null;
  state.history = [];
  state.finished = false;
  state.decoded = null;
}

export function renderFold(root: HTMLElement, lab: Lab): void {
  const s = lab.snapshot();
  if (!state.query || state.query.ciphertexts.length !== s.shelfSize) {
    startRun(lab);
  }
  const query = state.query as PirQuery;
  const answer = state.answer as AnswerState;
  const current = finishAnswer(s.params, answer);
  const expected = partialMessage(s.params, s.plaintexts, query.plainSelection, answer.folded);
  const measured = noiseBudgetBits(s.params, s.sk, current, expected);
  const ceiling = maxBudgetBits(s.params);

  clear(root);

  append(
    root,
    card('The homomorphic inner product', [
      el(
        'p',
        { class: 'lede' },
        `The server multiplies every record by its encrypted selection bit and adds the results. ` +
          `It cannot see which bit is the 1, so it has no choice but to do the work for all ` +
          `${s.shelfSize} — and that is exactly why the answer reveals nothing. Step it.`
      ),
      el('div', { class: 'controls' }, [
        el(
          'button',
          {
            class: 'btn btn-primary',
            type: 'button',
            'data-role': 'step',
            disabled: state.finished || state.busy,
          },
          'Fold one record'
        ),
        el(
          'button',
          {
            class: 'btn',
            type: 'button',
            'data-role': 'step8',
            disabled: state.finished || state.busy,
          },
          'Fold eight'
        ),
        el(
          'button',
          {
            class: 'btn',
            type: 'button',
            'data-role': 'all',
            disabled: state.finished || state.busy,
          },
          'Fold the rest'
        ),
        el('button', { class: 'btn', type: 'button', 'data-role': 'reset' }, 'Start over'),
      ]),
      state.retired && answer.folded === 0
        ? verdict('info', [
            el('strong', {}, 'Fold restarted: '),
            `${state.retired}. A partly-folded accumulator belongs to one shelf under one key, so ` +
              `it was discarded rather than continued against different parameters.`,
          ])
        : null,
      el(
        'p',
        { class: 'status-line', role: 'status', 'aria-live': 'polite', 'data-role': 'progress' },
        `Records folded: ${answer.folded} of ${s.shelfSize}. ` +
          (answer.folded === 0
            ? 'The accumulator is empty.'
            : answer.folded < s.shelfSize
              ? 'The server is still reading the shelf.'
              : 'Every record has been multiplied in. The answer is one ciphertext.')
      ),
      el(
        'div',
        { class: 'ct-grid', role: 'list', 'aria-label': 'Records folded into the answer so far' },
        s.entries.map((entry, i) =>
          el(
            'div',
            { role: 'listitem' },
            // NOT `aria-label` on a role-less <div>. `aria-label` is prohibited
            // on an element with no role, and axe reports that only in its
            // `incomplete` bucket — which is exactly why this gate asserts that
            // bucket. The position and the state are visible text instead, so
            // the accessible name and the rendering are the same thing.
            el(
              'div',
              {
                class: 'ct-tile',
                'data-mark': i < answer.folded ? 'folded' : undefined,
                title: entry.title,
              },
              [
                el('span', { class: 'ct-tile-idx' }, `#${i}`),
                i < answer.folded ? 'read' : 'waiting',
              ]
            )
          )
        )
      ),
    ])
  );

  append(
    root,
    card('The noise budget, measured', [
      budgetMeter(measured, ceiling),
      kv([
        ['Measured budget', `${measured.toFixed(2)} bits`],
        ['Ceiling for this modulus', `${ceiling.toFixed(2)} bits (log2 of Delta)`],
        [
          'Heuristic prediction',
          answer.folded === 0
            ? '—'
            : `${predictedBudgetBits(s.params, answer.folded).toFixed(2)} bits (six-sigma bound)`,
        ],
        ['Budget history', state.history.length ? state.history.map((b) => b.toFixed(1)).join(' → ') : '—'],
      ]),
      el(
        'p',
        { class: 'inline-note' },
        `Measured, not modelled: the running ciphertext is decrypted with the secret key and ` +
          `compared against what it ought to hold. A real client could not do this — it does not ` +
          `know the record it is asking for. The prediction beside it is the six-sigma bound from ` +
          `the parameters alone, and it never uses a ciphertext.`
      ),
      traceTable(lab, current, expected),
    ])
  );

  append(root, card('The running answer', [
    el(
      'p',
      { class: 'lede' },
      answer.folded === 0
        ? 'Nothing has been folded in yet.'
        : answer.folded <= indexOfOne(query)
          ? `The accumulator is a perfectly valid ciphertext of the number zero. Every record so ` +
            `far was multiplied by an encrypted 0 — the messages cancelled, the noise did not.`
          : `The accumulator now carries the chosen record, plus every subsequent record times ` +
            `zero.`
    ),
    el('code', { class: 'code code-dim' }, toHex(serializeCiphertext(s.params, current), 48) + ' …'),
    partialDecryption(lab, current),
    answer.folded === s.shelfSize ? finalOutput(lab) : null,
  ]));

  append(
    root,
    card('What the server learned', [
      verdict('pass', [
        el(
          'strong',
          {},
          `Shelf positions still consistent with everything the server saw: ${s.shelfSize} of ${s.shelfSize}. `
        ),
        `The server received ${s.shelfSize} ciphertexts, multiplied each by its own public record, ` +
          `and added. Nothing in that transcript separates one position from another without the ` +
          `secret key.`,
      ]),
      el(
        'p',
        { class: 'callout callout-caveat' },
        [
          el('strong', {}, 'Under an assumption, not unconditionally. '),
          `This is computational privacy: it holds against an adversary who cannot break decision ` +
            `RLWE at these parameters. Oblivious Shelf and Patron Shield get the same hiding with ` +
            `no assumption about computing power at all — and pay for it with a second server ` +
            `that must never collude. That is the trade, and it is on the next tab with numbers.`,
        ]
      ),
      mechanismDisclosure(),
    ])
  );

  bind(root, lab);
}

function indexOfOne(query: PirQuery): number {
  return Array.from(query.plainSelection).findIndex((b) => b === 1);
}

function budgetMeter(measured: number, ceiling: number): HTMLElement {
  const pct = Math.max(0, Math.min(100, (measured / ceiling) * 100));
  const health = measured <= 0 ? 'critical' : measured < 3 ? 'warning' : 'healthy';
  const label =
    health === 'healthy'
      ? 'Healthy'
      : health === 'warning'
        ? 'Warning — close to the ceiling'
        : 'Exhausted — decryption is no longer reliable';
  return el('div', { class: 'meter-row' }, [
    el(
      'div',
      {
        class: 'meter',
        'data-health': health,
        role: 'meter',
        'aria-valuenow': measured.toFixed(2),
        'aria-valuemin': '0',
        'aria-valuemax': ceiling.toFixed(2),
        'aria-label': 'Remaining noise budget in bits',
        'aria-valuetext': `${measured.toFixed(2)} of ${ceiling.toFixed(2)} bits — ${label}`,
      },
      el('span', { class: 'meter-fill', style: `width:${pct.toFixed(1)}%` })
    ),
    el('p', { class: 'meter-legend' }, [
      el('span', {}, [el('strong', {}, `${measured.toFixed(2)} bits`), ' remaining']),
      el('span', {}, label),
    ]),
  ]);
}

function traceTable(lab: Lab, current: Ciphertext, expected: Int32Array): HTMLElement {
  const s = lab.snapshot();
  const t = traceCoefficient(s.params, s.sk, current, expected, 0);
  return disclose('Open the decryption identity for one coefficient', [
    el(
      'p',
      {},
      `Decryption computes c0 + c1·s, which equals Delta·m + e modulo q. The signal is a multiple ` +
        `of Delta; the noise is whatever is left over. Rounding recovers m as long as the noise ` +
        `stays under half of Delta.`
    ),
    kv([
      ['Delta = floor(q / t)', String(t.delta)],
      ['m (coefficient 0 of the true partial sum)', String(t.message)],
      ['Delta · m — the signal', String(t.signal)],
      ['c0 + c1·s — what decryption sees', String(t.recovered)],
      ['difference — the noise', String(t.error)],
      ['ceiling — half of Delta', String(t.ceiling)],
      [
        'decodes to',
        `${t.decoded} ${t.decoded === t.message ? '(correct)' : '(WRONG — the noise won)'}`,
      ],
    ]),
    el(
      'p',
      { class: 'inline-note' },
      `Every one of those numbers comes from the ciphertext currently on screen. Fold more records ` +
        `and watch the noise line grow while the ceiling stays put.`
    ),
  ]);
}

function partialDecryption(lab: Lab, current: Ciphertext): HTMLElement {
  const s = lab.snapshot();
  const coefficients = decrypt(s.params, s.sk, current);
  const { bytes } = coefficientsToBytes(coefficients, s.recordBytes);
  const allZero = bytes.every((b) => b === 0);
  return el('div', {}, [
    el('h4', {}, 'Decrypted right now, mid-computation'),
    allZero
      ? verdict('info', 'All zero bytes. The accumulator holds a valid encryption of nothing.')
      : el('code', { class: 'code' }, recordText(bytes) || '(no printable text yet)'),
  ]);
}

function finalOutput(lab: Lab): HTMLElement {
  const s = lab.snapshot();
  const decoded = state.decoded;
  if (!decoded) {
    return el('p', { class: 'status-line', role: 'status', 'aria-live': 'polite' }, 'Decoding…');
  }
  const entry = s.entries[s.selectedIndex];
  return el('div', { 'data-role': 'final' }, [
    el('h4', {}, 'The answer, decrypted'),
    decoded.failure
      ? verdict('fail', [
          el('span', { class: 'fail-code' }, decoded.failure.code),
          ' — ',
          decoded.failure.detail,
        ])
      : verdict('pass', [
          el('strong', {}, 'Retrieved: '),
          `${entry.title} / ${entry.author}. Integrity tag intact, every coefficient inside the ` +
            `encodable range, ${decoded.budgetBits.toFixed(2)} bits of budget to spare.`,
        ]),
    el('code', { class: 'code' }, recordText(decoded.bytes) || '(unreadable)'),
    el(
      'p',
      { class: 'inline-note' },
      `One ciphertext came back — the same size whichever record you asked for. That fixed ` +
        `response length is a property of the construction, and it is the one metadata leak this ` +
        `design does close. See What It Does Not Hide for the ones it does not.`
    ),
  ]);
}

function mechanismDisclosure(): HTMLElement {
  return disclose('Why the sum selects, in three lines', [
    el(
      'p',
      {},
      `Write the query as b = (b_0, …, b_{N-1}) with b_index = 1 and every other entry 0. The ` +
        `server computes sum_i R_i · Enc(b_i). BFV is homomorphic for plaintext multiplication and ` +
        `for addition, so that ciphertext decrypts to sum_i R_i · b_i.`
    ),
    el(
      'p',
      {},
      `Every term with b_i = 0 contributes the zero polynomial. The single term with b_i = 1 ` +
        `contributes R_index. So the sum IS the record — arithmetic did the selecting, and the ` +
        `server never had to know which term survived.`
    ),
    el(
      'p',
      {},
      `The noise is the part that does not cancel. Each term contributes R_i · e_i, where e_i is ` +
        `that ciphertext's own encryption error — including the terms whose message vanished. ` +
        `That is why the budget falls from the very first record, long before the chosen one is ` +
        `reached.`
    ),
  ]);
}

function startRun(lab: Lab): void {
  const s = lab.snapshot();
  state.query = buildQuery(s.params, s.sk, s.selectedIndex, s.shelfSize, lab.random);
  state.answer = beginAnswer(s.params, s.shelfSize, state.query.ciphertexts.length);
  state.history = [];
  state.finished = false;
  state.decoded = null;
}

function bind(root: HTMLElement, lab: Lab): void {
  const step = (count: number): void => {
    void advance(root, lab, count);
  };
  root.querySelector<HTMLButtonElement>('[data-role="step"]')?.addEventListener('click', () => step(1));
  root.querySelector<HTMLButtonElement>('[data-role="step8"]')?.addEventListener('click', () => step(8));
  root.querySelector<HTMLButtonElement>('[data-role="all"]')?.addEventListener('click', () => {
    step(Number.MAX_SAFE_INTEGER);
  });
  root.querySelector<HTMLButtonElement>('[data-role="reset"]')?.addEventListener('click', () => {
    resetFold();
    state.retired = null;
    renderFold(root, lab);
  });
}

async function advance(root: HTMLElement, lab: Lab, count: number): Promise<void> {
  if (state.busy || state.finished) return;
  const s = lab.snapshot();
  const query = state.query as PirQuery;
  const answer = state.answer as AnswerState;
  state.busy = true;

  state.retired = null;
  const target = Math.min(s.shelfSize, answer.folded + count);
  while (answer.folded < target) {
    foldRecord(s.params, answer, s.plaintexts[answer.folded], query.ciphertexts[answer.folded]);
  }

  const current = finishAnswer(s.params, answer);
  const expected = partialMessage(s.params, s.plaintexts, query.plainSelection, answer.folded);
  state.history.push(noiseBudgetBits(s.params, s.sk, current, expected));
  if (state.history.length > 6) state.history.splice(0, state.history.length - 6);

  if (answer.folded === s.shelfSize) {
    state.finished = true;
    state.busy = false;
    renderFold(root, lab);
    await nextFrame();
    state.decoded = await decodeAnswer(s.params, s.sk, current, s.recordBytes, expected);
    renderFold(root, lab);
    return;
  }
  state.busy = false;
  renderFold(root, lab);
}
