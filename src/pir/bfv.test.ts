import { describe, expect, it } from 'vitest';
import {
  addCiphertext,
  decrypt,
  decryptRaw,
  encrypt,
  encryptScalar,
  invariantNoise,
  keyGen,
  maxBudgetBits,
  noiseBudgetBits,
  predictedBudgetBits,
  sampleError,
  sampleUniform,
  traceCoefficient,
} from './bfv';
import { defaultParams, delta, makeParams, MODULI, assertExactArithmetic } from './params';
import { Rng } from './rng';
import { centerLift, mod, zeroPoly } from './ring';
import { isPirError } from './errors';

const P = defaultParams();

function randomMessage(rng: Rng, n: number, t: number, used: number): Int32Array {
  const m = zeroPoly(n);
  for (let i = 0; i < used; i += 1) m[i] = rng.uniformBelow(t - 1);
  return m;
}

describe('BFV over R_q', () => {
  it('round-trips a full-ring plaintext', () => {
    const rng = Rng.fromSeed('bfv-roundtrip');
    const sk = keyGen(P, rng);
    const m = randomMessage(rng, P.n, P.t, P.coeffsUsed);
    const ct = encrypt(P, sk, m, rng);
    expect(Array.from(decrypt(P, sk, ct))).toEqual(Array.from(m));
  });

  it('round-trips every plaintext value in a scalar slot', () => {
    const rng = Rng.fromSeed('bfv-scalars');
    const sk = keyGen(P, rng);
    for (let v = 0; v < P.t; v += 1) {
      const ct = encryptScalar(P, sk, v, rng);
      expect(decrypt(P, sk, ct)[0]).toBe(v);
    }
  });

  it('the decryption identity really is Delta*m + e', () => {
    const rng = Rng.fromSeed('bfv-identity');
    const sk = keyGen(P, rng);
    const m = randomMessage(rng, P.n, P.t, P.coeffsUsed);
    const ct = encrypt(P, sk, m, rng);
    const v = decryptRaw(P, sk, ct);
    const d = delta(P);
    // Recomputed here from c0 + c1*s directly, by a different route than
    // `decrypt` takes: subtract the signal and check what remains is bounded by
    // the error sampler's own support, not merely "small".
    for (let i = 0; i < P.n; i += 1) {
      const noise = centerLift(centerLift(v[i], P.q) - centerLift(mod(m[i] * d, P.q), P.q), P.q);
      expect(Math.abs(noise)).toBeLessThanOrEqual(P.eta);
    }
  });

  it('is additively homomorphic', () => {
    const rng = Rng.fromSeed('bfv-add');
    const sk = keyGen(P, rng);
    for (let trial = 0; trial < 6; trial += 1) {
      const a = rng.uniformBelow(P.t);
      const b = rng.uniformBelow(P.t);
      const sum = addCiphertext(P, encryptScalar(P, sk, a, rng), encryptScalar(P, sk, b, rng));
      expect(decrypt(P, sk, sum)[0]).toBe((a + b) % P.t);
    }
  });

  it('two encryptions of the same value differ in every component', () => {
    const rng = Rng.fromSeed('bfv-fresh');
    const sk = keyGen(P, rng);
    const a = encryptScalar(P, sk, 1, rng);
    const b = encryptScalar(P, sk, 1, rng);
    expect(Array.from(a.c0)).not.toEqual(Array.from(b.c0));
    expect(Array.from(a.c1)).not.toEqual(Array.from(b.c1));
    expect(decrypt(P, sk, a)[0]).toBe(decrypt(P, sk, b)[0]);
  });

  it('reused randomness makes Enc(1) differ from Enc(0) by exactly Delta', () => {
    // The deliberately broken mode, asserted to be broken in the specific way
    // the page claims — not merely "different".
    const rng = Rng.fromSeed('bfv-reused');
    const sk = keyGen(P, rng);
    const shared = { a: sampleUniform(P, rng), e: sampleError(P, rng) };
    const zero = encryptScalar(P, sk, 0, rng, shared);
    const one = encryptScalar(P, sk, 1, rng, shared);
    expect(Array.from(zero.c1)).toEqual(Array.from(one.c1));
    expect(centerLift(one.c0[0] - zero.c0[0], P.q)).toBe(delta(P));
    for (let i = 1; i < P.n; i += 1) {
      expect(centerLift(one.c0[i] - zero.c0[i], P.q)).toBe(0);
    }
  });

  it('a fresh ciphertext has budget, and it is below the modulus ceiling', () => {
    const rng = Rng.fromSeed('bfv-budget');
    const sk = keyGen(P, rng);
    const m = randomMessage(rng, P.n, P.t, P.coeffsUsed);
    const ct = encrypt(P, sk, m, rng);
    const bits = noiseBudgetBits(P, sk, ct, m);
    expect(bits).toBeGreaterThan(12);
    expect(bits).toBeLessThan(maxBudgetBits(P));
  });

  it('adding ciphertexts costs budget, and decryption survives it', () => {
    const rng = Rng.fromSeed('bfv-budget-add');
    const sk = keyGen(P, rng);
    let ct = encryptScalar(P, sk, 1, rng);
    const m = zeroPoly(P.n);
    m[0] = 1;
    const fresh = noiseBudgetBits(P, sk, ct, m);
    let total = 1;
    for (let i = 0; i < 8; i += 1) {
      ct = addCiphertext(P, ct, encryptScalar(P, sk, 1, rng));
      total = (total + 1) % P.t;
    }
    const after = noiseBudgetBits(P, sk, ct, (() => {
      const mm = zeroPoly(P.n);
      mm[0] = total;
      return mm;
    })());
    expect(after).toBeLessThan(fresh);
    expect(decrypt(P, sk, ct)[0]).toBe(total);
  });

  it('the budget falls as the modulus shrinks', () => {
    const rng = Rng.fromSeed('bfv-moduli');
    const budgets = MODULI.map((option) => {
      const p = makeParams(option.q, 512);
      const sk = keyGen(p, rng);
      const m = randomMessage(rng, p.n, p.t, p.coeffsUsed);
      const ct = encrypt(p, sk, m, rng);
      return noiseBudgetBits(p, sk, ct, m);
    });
    for (let i = 1; i < budgets.length; i += 1) {
      expect(budgets[i]).toBeGreaterThan(budgets[i - 1]);
    }
  });

  it('the heuristic prediction halves its budget every four-fold shelf growth', () => {
    // `predictedBudgetBits` is a six-sigma bound on the noise of a PIR answer,
    // and the page draws it beside the measured value. Its SHAPE is what makes
    // it worth drawing: the noise grows as sqrt(N), so every four-fold growth in
    // the shelf costs exactly one bit of budget. That relationship is checked
    // here; the prediction is checked against a real measured answer in
    // `pir.test.ts`, where an answer exists to measure.
    const one = predictedBudgetBits(P, 16);
    const four = predictedBudgetBits(P, 64);
    const sixteen = predictedBudgetBits(P, 256);
    expect(one - four).toBeCloseTo(1, 6);
    expect(four - sixteen).toBeCloseTo(1, 6);
  });

  it('traceCoefficient opens the identity for display without lying about it', () => {
    const rng = Rng.fromSeed('bfv-trace');
    const sk = keyGen(P, rng);
    const m = zeroPoly(P.n);
    m[0] = 9;
    const ct = encrypt(P, sk, m, rng);
    const trace = traceCoefficient(P, sk, ct, m, 0);
    expect(trace.message).toBe(9);
    expect(trace.signal).toBe(9 * delta(P));
    expect(trace.recovered - trace.signal).toBe(trace.error);
    expect(Math.abs(trace.error)).toBeLessThan(trace.ceiling);
    expect(trace.decoded).toBe(9);
  });

  it('invariantNoise is zero-ish for a correct decryption and huge for a wrong one', () => {
    const rng = Rng.fromSeed('bfv-invariant');
    const sk = keyGen(P, rng);
    const m = zeroPoly(P.n);
    m[0] = 3;
    const ct = encrypt(P, sk, m, rng);
    expect(invariantNoise(P, sk, ct, m)).toBeLessThan(0.5);
    const wrong = zeroPoly(P.n);
    wrong[0] = 4;
    expect(invariantNoise(P, sk, ct, wrong)).toBeGreaterThan(0.5);
  });

  it('refuses parameters whose arithmetic would leave the exact integer range', () => {
    // n * (q/2) * (t-1) must stay under 2^53. Reaching it needs a q far larger
    // than anything selectable, so the guard is exercised directly.
    const absurd = { ...P, q: 2 ** 44 };
    try {
      assertExactArithmetic(absurd);
      expect.unreachable('should have refused');
    } catch (e) {
      expect(isPirError(e)).toBe(true);
      if (isPirError(e)) expect(e.code).toBe('PARAM_UNSAFE');
    }
  });
});
