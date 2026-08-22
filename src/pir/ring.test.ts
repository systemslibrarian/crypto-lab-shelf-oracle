import { describe, expect, it } from 'vitest';
import {
  addPoly,
  centerLift,
  infinityNorm,
  mod,
  mulAccumulate,
  mulBySmall,
  negPoly,
  polyEquals,
  accumulatorToPoly,
  reduceAccumulator,
  subPoly,
  toCentered,
  zeroPoly,
} from './ring';

const Q = 67108859;

/** Multiply two ring elements by definition, for use as an independent oracle. */
function referenceMultiply(a: Int32Array, b: Int32Array, q: number): Int32Array {
  const n = a.length;
  const out = new Int32Array(n);
  for (let i = 0; i < n; i += 1) {
    for (let j = 0; j < n; j += 1) {
      const k = i + j;
      const term = (a[i] * b[j]) % q;
      if (k < n) out[k] = mod(out[k] + term, q);
      else out[k - n] = mod(out[k - n] - term, q);
    }
  }
  return out;
}

function monomial(n: number, degree: number, coefficient = 1): Int32Array {
  const p = zeroPoly(n);
  p[degree] = coefficient;
  return p;
}

describe('R_q = Z_q[X] / (X^n + 1)', () => {
  it('mod normalises negatives and never returns -0', () => {
    expect(mod(-1, 7)).toBe(6);
    expect(mod(-7, 7)).toBe(0);
    expect(Object.is(mod(-7, 7), -0)).toBe(false);
    expect(mod(15, 7)).toBe(1);
  });

  it('centerLift picks the representative nearest zero', () => {
    expect(centerLift(1, 17)).toBe(1);
    expect(centerLift(16, 17)).toBe(-1);
    expect(centerLift(9, 17)).toBe(-8);
    expect(centerLift(8, 17)).toBe(8);
  });

  /**
   * THE NEGACYCLIC PROPERTY, checked directly.
   *
   * X^(n-1) * X must be -1, not +1. A cyclic implementation round-trips through
   * encryption perfectly well and passes every "did I get my message back" test,
   * so nothing but this assertion distinguishes the two rings.
   */
  it('X^(n-1) * X = -1, not +1', () => {
    const n = 8;
    const s = new Int8Array(n);
    s[1] = 1; // the polynomial X
    const product = mulBySmall(monomial(n, n - 1), s, Q);
    expect(Array.from(product)).toEqual(Array.from(negPoly(monomial(n, 0), Q)));
    expect(product[0]).toBe(Q - 1);
  });

  it('X^n = -1 all the way round the ring', () => {
    const n = 16;
    // X^(n-d) * X^d = X^n = -1 for every split of the exponent. d runs to n-1
    // because X^n is not a representable monomial: reducing it is the point.
    for (let d = 1; d < n; d += 1) {
      const s = new Int8Array(n);
      s[d] = 1;
      const product = mulBySmall(monomial(n, n - d, 1), s, Q);
      expect(product[0]).toBe(Q - 1);
      for (let k = 1; k < n; k += 1) expect(product[k]).toBe(0);
    }
  });

  it('mulBySmall agrees with a definitional multiply', () => {
    const n = 32;
    const a = new Int32Array(n);
    for (let i = 0; i < n; i += 1) a[i] = (i * 7919 + 13) % Q;
    const s = new Int8Array(n);
    for (let i = 0; i < n; i += 1) s[i] = ((i * 5) % 3) - 1;
    const lifted = new Int32Array(n);
    for (let i = 0; i < n; i += 1) lifted[i] = mod(s[i], Q);
    expect(polyEquals(mulBySmall(a, s, Q), referenceMultiply(a, lifted, Q))).toBe(true);
  });

  it('mulAccumulate agrees with a definitional multiply', () => {
    const n = 32;
    const plain = new Int32Array(n);
    for (let i = 0; i < n; i += 1) plain[i] = i % 16;
    const cipher = new Int32Array(n);
    for (let i = 0; i < n; i += 1) cipher[i] = (i * 104729) % Q;

    const acc = new Float64Array(n);
    mulAccumulate(acc, plain, toCentered(cipher, Q), n);
    reduceAccumulator(acc, Q);
    expect(polyEquals(accumulatorToPoly(acc, Q), referenceMultiply(plain, cipher, Q))).toBe(true);
  });

  it('mulAccumulate is additive across records, which is what makes PIR work', () => {
    const n = 16;
    const c = new Int32Array(n);
    for (let i = 0; i < n; i += 1) c[i] = (i * 3571 + 11) % Q;
    const p1 = new Int32Array(n);
    const p2 = new Int32Array(n);
    for (let i = 0; i < n; i += 1) {
      p1[i] = i % 13;
      p2[i] = (i * 5) % 11;
    }
    const together = new Float64Array(n);
    mulAccumulate(together, p1, toCentered(c, Q), n);
    mulAccumulate(together, p2, toCentered(c, Q), n);
    reduceAccumulator(together, Q);

    const sumOfPlains = addPoly(p1, p2, Q);
    expect(polyEquals(accumulatorToPoly(together, Q), referenceMultiply(sumOfPlains, c, Q))).toBe(
      true
    );
  });

  it('add and sub are inverse coefficient-wise', () => {
    const a = new Int32Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const b = new Int32Array([Q - 1, 10, 0, 5, 5, 5, 5, 5]);
    expect(polyEquals(subPoly(addPoly(a, b, Q), b, Q), a)).toBe(true);
  });

  it('infinityNorm measures the balanced representative', () => {
    const a = new Int32Array([1, Q - 1, 5, Q - 100]);
    expect(infinityNorm(a, Q)).toBe(100);
  });
});
