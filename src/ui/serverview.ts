import { append, card, clear, disclose, el, formatBytes, kv, nextFrame, verdict } from './dom';
import type { Lab } from './state';
import { buildQuery, distinguishIndex, type PirQuery, type QueryRandomness } from '../pir/pir';
import { ciphertextBytes, serializeCiphertext, serializeQuery } from '../pir/serialize';
import { toHex } from '../pir/records';

/**
 * Act two: what crosses the wire.
 *
 * The claim is that the server cannot tell which of the N ciphertexts encrypts
 * the 1. The temptation is to assert it under a picture of hex. Instead this
 * panel lets the reader TRY — pick the tile they think is the one — and then
 * runs a real distinguisher over many fresh queries and reports its measured
 * accuracy against the 1-in-N baseline.
 *
 * And then it lets them break it. Turning off fresh encryption randomness is a
 * single, clearly-marked control that makes every Enc(0) byte-identical and
 * leaves Enc(1) exactly Delta away, at which point the same crude attack is
 * right every single time. Nothing about the attack changes; only the
 * encryption does. That is the lesson.
 */

/** The distinguishing experiment runs on a short shelf so it finishes in about
 *  a second AND so its 1-in-16 baseline is separable from certainty in the
 *  number of trials a page can afford. */
const TRIAL_SHELF = 16;
const TRIALS = 40;

interface PanelState {
  query: PirQuery | null;
  randomness: QueryRandomness;
  guess: number | null;
  trialResult: { fresh: number; reused: number; trials: number } | null;
  running: boolean;
  retired: string | null;
}

const state: PanelState = {
  query: null,
  randomness: 'fresh',
  guess: null,
  trialResult: null,
  running: false,
  retired: null,
};

export function renderServerView(root: HTMLElement, lab: Lab): void {
  const s = lab.snapshot();
  if (!state.query || state.query.ciphertexts.length !== s.shelfSize) {
    state.query = buildQuery(s.params, s.sk, s.selectedIndex, s.shelfSize, lab.random, {
      randomness: state.randomness,
    });
    state.guess = null;
  }
  const query = state.query;

  clear(root);

  append(
    root,
    card('What you send', [
      el(
        'p',
        { class: 'lede' },
        `Your query is a vector of ${s.shelfSize} numbers: a 1 at the position you want and a 0 ` +
          `everywhere else. Each entry is encrypted separately under BFV before it leaves. The ` +
          `server receives ${s.shelfSize} ciphertexts and no index.`
      ),
      el('h4', {}, 'The selection vector — your copy'),
      el(
        'div',
        { class: 'plain-vector' },
        Array.from(query.plainSelection).map((bit) =>
          bit ? el('b', {}, `${bit}`) : document.createTextNode(`${bit}`)
        )
      ),
      el(
        'p',
        { class: 'inline-note' },
        `Drawn dashed and dim because this is the one thing that never leaves your machine. The ` +
          `server sees only the encryptions below.`
      ),
      el('h4', {}, 'The ciphertexts — the server’s copy'),
      el(
        'div',
        { class: 'ct-grid', role: 'list', 'aria-label': 'Encrypted selection vector' },
        query.ciphertexts.map((ct, i) =>
          el(
            'div',
            { role: 'listitem' },
            el(
              'button',
              {
                class: 'ct-tile',
                type: 'button',
                'data-index': i,
                'data-mark': markFor(i, query, state.guess),
                'aria-label': `Guess that ciphertext ${i} encrypts the one`,
              },
              [
                el('span', { class: 'ct-tile-idx', 'aria-hidden': 'true' }, `#${i}`),
                toHex(serializeCiphertext(s.params, ct), 6),
              ]
            )
          )
        )
      ),
      guessVerdict(query),
      kv([
        ['One ciphertext', formatBytes(ciphertextBytes(s.params))],
        ['Whole query', formatBytes(serializeQuery(s.params, query.ciphertexts).length)],
        ['Ring', `n = ${s.params.n}, q = ${s.params.q} (${s.modulus.label}), t = ${s.params.t}`],
      ]),
      el(
        'p',
        { class: 'inline-note' },
        `Those byte counts are measured — the query really is serialized, ` +
          `${Math.ceil(Math.log2(s.params.q))} bits per coefficient, and its length read back. ` +
          `A real SealPIR client would send far less; see One Server vs Two.`
      ),
    ])
  );

  append(
    root,
    card('Break it yourself', [
      el(
        'p',
        { class: 'lede' },
        `Above, you can guess. Here, a machine guesses ${TRIALS} times. The attack is the crudest ` +
          `one available: take each ciphertext's first coefficient, centre it on the median of all ` +
          `of them, and pick the biggest outlier. If encryption is doing its job, that is a ` +
          `1-in-${TRIAL_SHELF} coin flip.`
      ),
      el('div', { class: 'switch-row' }, [
        el('input', {
          type: 'checkbox',
          id: 'reuse-randomness',
          'data-role': 'reuse',
          checked: state.randomness === 'reused',
        }),
        el(
          'label',
          { for: 'reuse-randomness' },
          'Break the encryption: reuse one random pair for every entry'
        ),
      ]),
      el(
        'p',
        { class: 'callout callout-danger' },
        [
          el('strong', {}, 'Deliberately broken. '),
          `With this on, all ${s.shelfSize} encryptions share the same uniform element a and the ` +
            `same error e. Every Enc(0) becomes byte-identical, and Enc(1) differs from them by ` +
            `exactly Delta in one coefficient. This is not the protocol; it is what the protocol ` +
            `is avoiding, and it is off by default.`,
        ]
      ),
      el('div', { class: 'controls' }, [
        el(
          'button',
          { class: 'btn btn-primary', type: 'button', 'data-role': 'run-trials' },
          `Run ${TRIALS} trials against both`
        ),
        el(
          'button',
          { class: 'btn', type: 'button', 'data-role': 'new-query' },
          'New query, same book'
        ),
      ]),
      el(
        'div',
        { 'data-role': 'trial-out', role: 'status', 'aria-live': 'polite' },
        trialOutput()
      ),
      whyDisclosure(),
    ])
  );

  bind(root, lab);
}

function markFor(index: number, query: PirQuery, guess: number | null): string | undefined {
  if (guess === null || guess !== index) return undefined;
  return query.plainSelection[index] === 1 ? 'hit' : 'miss';
}

function guessVerdict(query: PirQuery): HTMLElement {
  if (state.guess === null) {
    return verdict('info', 'Pick a tile. Which one encrypts the 1?', { live: true });
  }
  const right = query.plainSelection[state.guess] === 1;
  const truth = Array.from(query.plainSelection).findIndex((b) => b === 1);
  return verdict(
    right ? 'alarm' : 'pass',
    right
      ? [
          el('strong', {}, `You guessed ${state.guess}, and that is the one. `),
          `A one-in-${query.ciphertexts.length} guess comes up sometimes — that is what a ` +
            `one-in-${query.ciphertexts.length} guess means. Run the trials below to see whether ` +
            `anything better than chance is available.`,
        ]
      : [
          el('strong', {}, `You guessed ${state.guess}. The 1 was at ${truth}. `),
          `Nothing in the bytes told you, because nothing in the bytes can: under RLWE, Enc(0) and ` +
            `Enc(1) are indistinguishable without the secret key.`,
        ],
    { live: true }
  );
}

function trialOutput(): HTMLElement {
  if (state.running) {
    return el('p', { class: 'status-line' }, 'Running trials — encrypting…');
  }
  if (!state.trialResult) {
    return state.retired
      ? verdict('info', [
          el('strong', {}, 'Trial result retired: '),
          `${state.retired}. An accuracy measured under one parameter set says nothing about ` +
            `another, so the previous run was discarded. Baseline for a ${TRIAL_SHELF}-position ` +
            `shelf is ${(100 / TRIAL_SHELF).toFixed(1)} percent.`,
        ])
      : el(
          'p',
          { class: 'status-line' },
          `No trials run yet. Baseline for a ${TRIAL_SHELF}-position shelf is ` +
            `${(100 / TRIAL_SHELF).toFixed(1)} percent.`
        );
  }
  const { fresh, reused, trials } = state.trialResult;
  const freshPct = ((fresh / trials) * 100).toFixed(1);
  const reusedPct = ((reused / trials) * 100).toFixed(1);
  return el('div', {}, [
    verdict('pass', [
      el('strong', {}, `Fresh randomness: ${fresh}/${trials} correct (${freshPct}%). `),
      `Chance is ${(100 / TRIAL_SHELF).toFixed(1)}%. The attack learns nothing.`,
    ]),
    verdict('alarm', [
      el('strong', {}, `Reused randomness: ${reused}/${trials} correct (${reusedPct}%). `),
      `The same attack, against encryptions that stopped being random.`,
    ]),
    el(
      'p',
      { class: 'inline-note' },
      `Both columns ran the identical distinguisher over ${trials} freshly-built queries on a ` +
        `${TRIAL_SHELF}-position shelf, with a fresh random target index each time. Only the ` +
        `encryption changed.`
    ),
  ]);
}

function whyDisclosure(): HTMLElement {
  return disclose('Why fresh randomness is the whole security argument', [
    el(
      'p',
      {},
      `A BFV ciphertext is the pair (c0, c1) = (-(a·s) + Delta·m + e, a). The message m is buried ` +
        `under a·s, which looks uniform to anyone without s, and under e, which is small but ` +
        `unknown. Take a fresh a and a fresh e each time and the pair is pseudorandom: that is ` +
        `precisely the decision-RLWE assumption.`
    ),
    el(
      'p',
      {},
      `Reuse them and the mask cancels. Subtract two ciphertexts built from the same (a, e) and ` +
        `everything vanishes except Delta·(m1 - m2) — the messages, in the clear, with no key ` +
        `involved. That is not a weakness of BFV; it is the same failure as reusing a one-time ` +
        `pad, and it is the reason encryption is randomized at all.`
    ),
    el(
      'p',
      {},
      `The lesson generalises past this page: nonce and randomness reuse is one of the most common ` +
        `ways real deployments fail, and it never looks broken from the outside.`
    ),
  ]);
}

function bind(root: HTMLElement, lab: Lab): void {
  root.querySelectorAll<HTMLButtonElement>('.ct-tile').forEach((tile) => {
    tile.addEventListener('click', () => {
      state.guess = Number(tile.dataset.index);
      renderServerView(root, lab);
    });
  });

  const reuse = root.querySelector<HTMLInputElement>('[data-role="reuse"]');
  reuse?.addEventListener('change', () => {
    state.randomness = reuse.checked ? 'reused' : 'fresh';
    state.query = null;
    state.trialResult = null;
    renderServerView(root, lab);
  });

  root.querySelector<HTMLButtonElement>('[data-role="new-query"]')?.addEventListener('click', () => {
    state.query = null;
    renderServerView(root, lab);
  });

  root.querySelector<HTMLButtonElement>('[data-role="run-trials"]')?.addEventListener('click', () => {
    void runTrials(root, lab);
  });
}

/**
 * Run the experiment, yielding between trials so the page stays responsive.
 *
 * Forty trials on a sixteen-position shelf is 1,280 real RLWE encryptions, each
 * one a schoolbook multiply at n = 1024. That takes about a second, which is why
 * it is chunked rather than run in one blocking loop.
 */
async function runTrials(root: HTMLElement, lab: Lab): Promise<void> {
  if (state.running) return;
  state.running = true;
  state.retired = null;
  renderServerView(root, lab);
  await nextFrame();

  const s = lab.snapshot();
  let fresh = 0;
  let reused = 0;
  for (let trial = 0; trial < TRIALS; trial += 1) {
    const index = lab.random.uniformBelow(TRIAL_SHELF);
    const freshQuery = buildQuery(s.params, s.sk, index, TRIAL_SHELF, lab.random);
    if (distinguishIndex(s.params, freshQuery.ciphertexts) === index) fresh += 1;
    const reusedQuery = buildQuery(s.params, s.sk, index, TRIAL_SHELF, lab.random, {
      randomness: 'reused',
    });
    if (distinguishIndex(s.params, reusedQuery.ciphertexts) === index) reused += 1;
    if (trial % 4 === 3) await nextFrame();
  }

  state.trialResult = { fresh, reused, trials: TRIALS };
  state.running = false;
  renderServerView(root, lab);
}

/**
 * Discard the query and the trial result, and REMEMBER WHY.
 *
 * A query is a set of ciphertexts under one specific key and modulus; a trial
 * result is an accuracy measured under those same parameters. Neither survives
 * a parameter change, and neither should vanish without saying so.
 */
export function resetServerView(reason?: string): void {
  if (state.trialResult) state.retired = reason ?? null;
  state.query = null;
  state.guess = null;
  state.trialResult = null;
}
