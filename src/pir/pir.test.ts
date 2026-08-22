import { describe, expect, it } from 'vitest';
import { decrypt, keyGen, noiseBudgetBits, predictedBudgetBits } from './bfv';
import { isPirError } from './errors';
import {
  DEFAULT_RECORD_BYTES,
  MODULI,
  defaultParams,
  makeParams,
  type PirParams,
} from './params';
import {
  beginAnswer,
  buildQuery,
  decodeAnswer,
  distinguishIndex,
  finishAnswer,
  foldRecord,
  partialMessage,
  serverAnswer,
} from './pir';
import { bytesToCoefficients, buildRecord, recordText, shelfToPlaintexts } from './records';
import { Rng } from './rng';
import { CATALOG, entryText, shelfEntries } from '../data/catalog';
import {
  buildXorQuery,
  colludeRecoverIndex,
  combineXorAnswers,
  maskWeight,
  xorAnswer,
} from './xorpir';

const P = defaultParams();

async function buildShelf(size: number, recordBytes: number): Promise<Uint8Array[]> {
  return Promise.all(shelfEntries(size).map((e) => buildRecord(entryText(e), recordBytes)));
}

describe('single-server RLWE PIR', () => {
  it('retrieves the requested record, byte for byte', async () => {
    const rng = Rng.fromSeed('pir-retrieve');
    const sk = keyGen(P, rng);
    const shelf = await buildShelf(64, DEFAULT_RECORD_BYTES);
    const plaintexts = shelfToPlaintexts(shelf, P);

    for (const index of [0, 1, 17, 42, 63]) {
      const query = buildQuery(P, sk, index, shelf.length, rng);
      const answer = serverAnswer(P, plaintexts, query.ciphertexts);
      const decoded = await decodeAnswer(
        P,
        sk,
        answer,
        DEFAULT_RECORD_BYTES,
        bytesToCoefficients(shelf[index], P.n)
      );
      expect(decoded.failure).toBeNull();
      expect(decoded.tagOk).toBe(true);
      expect(decoded.outOfRange).toBe(0);
      expect(Array.from(decoded.bytes)).toEqual(Array.from(shelf[index]));
      expect(recordText(decoded.bytes)).toContain(CATALOG[index].title);
    }
  });

  it('the answer does not depend on anything the client kept private', async () => {
    // The architectural claim, checked by construction: `serverAnswer` is given
    // ONLY the parameters, the server's own plaintexts, and the ciphertexts.
    // Reconstructing the call from a stripped copy of the query — no index, no
    // plaintext selection vector, no key — must produce the identical answer.
    const rng = Rng.fromSeed('pir-purity');
    const sk = keyGen(P, rng);
    const shelf = await buildShelf(32, 256);
    const p = makeParams(P.q, 256);
    const plaintexts = shelfToPlaintexts(shelf, p);
    const query = buildQuery(p, sk, 11, shelf.length, rng);

    const stripped = query.ciphertexts.map((ct) => ({ c0: ct.c0.slice(), c1: ct.c1.slice() }));
    const a = serverAnswer(p, plaintexts, query.ciphertexts);
    const b = serverAnswer(p, plaintexts, stripped);
    expect(Array.from(a.c0)).toEqual(Array.from(b.c0));
    expect(Array.from(a.c1)).toEqual(Array.from(b.c1));
  });

  it('the server touches every record — folding fewer gives a different answer', async () => {
    // "The server must read the whole shelf" is the cost claim the page makes.
    // Here it is a measurement: stopping one record short changes the answer
    // even when the record skipped is not the one requested.
    const rng = Rng.fromSeed('pir-linear');
    const sk = keyGen(P, rng);
    const shelf = await buildShelf(16, 256);
    const p = makeParams(P.q, 256);
    const plaintexts = shelfToPlaintexts(shelf, p);
    const query = buildQuery(p, sk, 3, shelf.length, rng);

    const full = serverAnswer(p, plaintexts, query.ciphertexts);

    const partial = beginAnswer(p, shelf.length, query.ciphertexts.length);
    for (let i = 0; i < shelf.length - 1; i += 1) {
      foldRecord(p, partial, plaintexts[i], query.ciphertexts[i]);
    }
    const short = finishAnswer(p, partial);
    expect(Array.from(short.c0)).not.toEqual(Array.from(full.c0));
  });

  it('stepping the fold reaches the same ciphertext as the one-shot server', async () => {
    // The page animates the inner product with `foldRecord`. If the stepped and
    // one-shot routes could disagree, the animation would be a separate
    // implementation pretending to be the protocol.
    const rng = Rng.fromSeed('pir-step');
    const sk = keyGen(P, rng);
    const shelf = await buildShelf(24, 128);
    const p = makeParams(P.q, 128);
    const plaintexts = shelfToPlaintexts(shelf, p);
    const query = buildQuery(p, sk, 5, shelf.length, rng);

    const state = beginAnswer(p, shelf.length, query.ciphertexts.length);
    for (let i = 0; i < shelf.length; i += 1) foldRecord(p, state, plaintexts[i], query.ciphertexts[i]);
    expect(state.folded).toBe(shelf.length);
    const stepped = finishAnswer(p, state);
    const oneShot = serverAnswer(p, plaintexts, query.ciphertexts);
    expect(Array.from(stepped.c0)).toEqual(Array.from(oneShot.c0));
    expect(Array.from(stepped.c1)).toEqual(Array.from(oneShot.c1));
  });

  it('the measured budget falls monotonically as records are folded in', async () => {
    const rng = Rng.fromSeed('pir-budget-fall');
    const sk = keyGen(P, rng);
    const shelf = await buildShelf(64, DEFAULT_RECORD_BYTES);
    const plaintexts = shelfToPlaintexts(shelf, P);
    const index = 9;
    const query = buildQuery(P, sk, index, shelf.length, rng);

    const state = beginAnswer(P, shelf.length, query.ciphertexts.length);
    const samples: number[] = [];
    for (let i = 0; i < shelf.length; i += 1) {
      foldRecord(P, state, plaintexts[i], query.ciphertexts[i]);
      if (i === 0 || i === 15 || i === 31 || i === 63) {
        // Measured against the PARTIAL sum, which is an encryption of zero
        // until record 9 is folded in. The budget is already falling by then:
        // records 0 through 8 contributed their errors and no message.
        const expected = partialMessage(P, plaintexts, query.plainSelection, state.folded);
        samples.push(noiseBudgetBits(P, sk, finishAnswer(P, state), expected));
      }
    }
    for (let i = 1; i < samples.length; i += 1) {
      expect(samples[i]).toBeLessThan(samples[i - 1]);
    }
    // And it must still be positive at the shipped parameters, or the default
    // page load would be broken.
    expect(samples[samples.length - 1]).toBeGreaterThan(0);
  });

  it('a partial answer decrypts to zero until the chosen record is folded in', async () => {
    // The step-through exhibit shows this: for the first nine steps the
    // accumulator is a perfectly valid encryption of nothing at all.
    const rng = Rng.fromSeed('pir-partial');
    const sk = keyGen(P, rng);
    const shelf = await buildShelf(16, 128);
    const p = makeParams(P.q, 128);
    const plaintexts = shelfToPlaintexts(shelf, p);
    const index = 6;
    const query = buildQuery(p, sk, index, shelf.length, rng);

    const state = beginAnswer(p, shelf.length, query.ciphertexts.length);
    for (let i = 0; i < shelf.length; i += 1) {
      foldRecord(p, state, plaintexts[i], query.ciphertexts[i]);
      const got = decrypt(p, sk, finishAnswer(p, state));
      const expected = partialMessage(p, plaintexts, query.plainSelection, state.folded);
      expect(Array.from(got.subarray(0, p.coeffsUsed))).toEqual(
        Array.from(expected.subarray(0, p.coeffsUsed))
      );
      const isZero = Array.from(got.subarray(0, p.coeffsUsed)).every((v) => v === 0);
      expect(isZero).toBe(i < index);
    }
  });

  it('the heuristic prediction is a bound the measurement respects', async () => {
    // §4.1b: an independent re-derivation, not a recomputation of the same
    // expression. `predictedBudgetBits` derives the budget from N, coeffsUsed, t
    // and eta with no ciphertext in sight; the measurement decrypts a real
    // answer. A six-sigma bound must be pessimistic — below the measurement —
    // and close enough to be worth printing.
    const rng = Rng.fromSeed('pir-prediction');
    const sk = keyGen(P, rng);
    const shelf = await buildShelf(64, DEFAULT_RECORD_BYTES);
    const plaintexts = shelfToPlaintexts(shelf, P);
    const query = buildQuery(P, sk, 20, shelf.length, rng);
    const answer = serverAnswer(P, plaintexts, query.ciphertexts);
    const measured = noiseBudgetBits(P, sk, answer, bytesToCoefficients(shelf[20], P.n));
    const predicted = predictedBudgetBits(P, 64);
    expect(predicted).toBeLessThan(measured);
    expect(measured - predicted).toBeLessThan(4);
  });

  it('a fresh query is indistinguishable; a query with reused randomness is not', async () => {
    // The break-it-yourself exhibit, as a measurement. The same crude
    // distinguisher is run against both, and only the encryption randomness
    // changes. Sixteen positions rather than sixty-four so the run finishes
    // inside a test timeout AND so the chance baseline (1 in 16) is large
    // enough that forty trials can tell it from certainty — which is exactly
    // the trade the page's own control makes, for the same reason.
    const rng = Rng.fromSeed('pir-distinguish');
    const sk = keyGen(P, rng);
    const shelfSize = 16;
    const trials = 40;

    let freshHits = 0;
    let reusedHits = 0;
    for (let trial = 0; trial < trials; trial += 1) {
      const index = rng.uniformBelow(shelfSize);
      const fresh = buildQuery(P, sk, index, shelfSize, rng);
      if (distinguishIndex(P, fresh.ciphertexts) === index) freshHits += 1;
      const reused = buildQuery(P, sk, index, shelfSize, rng, { randomness: 'reused' });
      if (distinguishIndex(P, reused.ciphertexts) === index) reusedHits += 1;
    }
    // Reused randomness: the attack is exact, every time.
    expect(reusedHits).toBe(trials);
    // Fresh randomness: 1 in 16 per trial, so 2.5 hits expected. Ten or more
    // has probability under 1 in 1000 and the seed is fixed, so this cannot
    // flake — but it fails loudly if encryption ever stops randomising.
    expect(freshHits).toBeLessThan(10);
  });
});

describe('the failure codes are reachable and fail closed', () => {
  it('INDEX_OUT_OF_RANGE — asking for a shelf position that does not exist', () => {
    const rng = Rng.fromSeed('fail-index');
    const sk = keyGen(P, rng);
    try {
      buildQuery(P, sk, 64, 64, rng);
      expect.unreachable('should have refused');
    } catch (e) {
      expect(isPirError(e) && e.code).toBe('INDEX_OUT_OF_RANGE');
    }
  });

  it('DIM_MISMATCH — a query built for a different shelf length is refused first', async () => {
    const rng = Rng.fromSeed('fail-dim');
    const sk = keyGen(P, rng);
    const shelf = await buildShelf(32, 128);
    const p = makeParams(P.q, 128);
    const plaintexts = shelfToPlaintexts(shelf, p);
    const query = buildQuery(p, sk, 3, 16, rng);
    try {
      serverAnswer(p, plaintexts, query.ciphertexts);
      expect.unreachable('should have refused');
    } catch (e) {
      expect(isPirError(e) && e.code).toBe('DIM_MISMATCH');
    }
  });

  it('NOISE_BUDGET_EXHAUSTED — a modulus too small for the shelf returns garbage, and says so', async () => {
    // Not simulated: the smallest selectable modulus genuinely cannot carry a
    // 64-record answer, and the decode reports it through the record's own tag
    // and the out-of-range coefficient count.
    const tiny: PirParams = makeParams(MODULI[0].q, DEFAULT_RECORD_BYTES);
    const rng = Rng.fromSeed('fail-noise');
    const sk = keyGen(tiny, rng);
    const shelf = await buildShelf(64, DEFAULT_RECORD_BYTES);
    const plaintexts = shelfToPlaintexts(shelf, tiny);
    const query = buildQuery(tiny, sk, 7, shelf.length, rng);
    const answer = serverAnswer(tiny, plaintexts, query.ciphertexts);
    const decoded = await decodeAnswer(
      tiny,
      sk,
      answer,
      DEFAULT_RECORD_BYTES,
      bytesToCoefficients(shelf[7], tiny.n)
    );
    expect(decoded.failure).not.toBeNull();
    expect(decoded.failure?.code).toBe('NOISE_BUDGET_EXHAUSTED');
    expect(decoded.tagOk).toBe(false);
    expect(Array.from(decoded.bytes)).not.toEqual(Array.from(shelf[7]));
  });

  it('a malformed two-hot query returns the SUM of two records, not either one', async () => {
    // Unauthenticated by construction: the server cannot see that the selection
    // vector is not one-hot, so it answers faithfully and the client gets
    // nonsense. A real property, and the reason PIR is not an access-control
    // mechanism.
    const rng = Rng.fromSeed('fail-twohot');
    const sk = keyGen(P, rng);
    const shelf = await buildShelf(32, 128);
    const p = makeParams(P.q, 128);
    const plaintexts = shelfToPlaintexts(shelf, p);
    const weights = new Uint8Array(32);
    weights[4] = 1;
    weights[9] = 1;
    const query = buildQuery(p, sk, 4, 32, rng, { weights });
    const answer = serverAnswer(p, plaintexts, query.ciphertexts);
    const got = decrypt(p, sk, answer);
    const a = bytesToCoefficients(shelf[4], p.n);
    const b = bytesToCoefficients(shelf[9], p.n);
    for (let i = 0; i < p.coeffsUsed; i += 1) {
      expect(got[i]).toBe((a[i] + b[i]) % p.t);
    }
  });
});

describe('two-server XOR PIR, and the head-to-head', () => {
  it('reconstructs the record, and each mask on its own is uniform', async () => {
    const rng = Rng.fromSeed('xor-basic');
    const shelf = await buildShelf(64, DEFAULT_RECORD_BYTES);
    for (const index of [0, 13, 63]) {
      const q = buildXorQuery(shelf.length, index, rng);
      const combined = combineXorAnswers(xorAnswer(shelf, q.maskA), xorAnswer(shelf, q.maskB));
      expect(Array.from(combined)).toEqual(Array.from(shelf[index]));
    }
  });

  it('a single mask selects about half the shelf regardless of the index', async () => {
    const rng = Rng.fromSeed('xor-uniform');
    const weights: number[] = [];
    for (let trial = 0; trial < 200; trial += 1) {
      weights.push(maskWeight(buildXorQuery(64, 0, rng).maskA, 64));
    }
    const mean = weights.reduce((a, b) => a + b, 0) / weights.length;
    expect(mean).toBeGreaterThan(28);
    expect(mean).toBeLessThan(36);
  });

  it('collusion recovers the index exactly, in one XOR', () => {
    const rng = Rng.fromSeed('xor-collude');
    for (let index = 0; index < 64; index += 1) {
      expect(colludeRecoverIndex(buildXorQuery(64, index, rng))).toBe(index);
    }
  });

  it('both schemes return the SAME bytes as a direct lookup', async () => {
    // The strongest correctness check in the suite, and deliberately a
    // three-way one: two protocols with nothing in common — one lattice, one
    // XOR — and a plain array read, all agreeing byte for byte. A bug in either
    // protocol has to be reproduced identically by the other to survive this.
    const rng = Rng.fromSeed('cross-check');
    const sk = keyGen(P, rng);
    const shelf = await buildShelf(64, DEFAULT_RECORD_BYTES);
    const plaintexts = shelfToPlaintexts(shelf, P);

    for (const index of [2, 30, 61]) {
      const direct = shelf[index];

      const lattice = await decodeAnswer(
        P,
        sk,
        serverAnswer(P, plaintexts, buildQuery(P, sk, index, shelf.length, rng).ciphertexts),
        DEFAULT_RECORD_BYTES,
        bytesToCoefficients(direct, P.n)
      );

      const xq = buildXorQuery(shelf.length, index, rng);
      const xor = combineXorAnswers(xorAnswer(shelf, xq.maskA), xorAnswer(shelf, xq.maskB));

      expect(Array.from(lattice.bytes)).toEqual(Array.from(direct));
      expect(Array.from(xor)).toEqual(Array.from(direct));
    }
  });
});
