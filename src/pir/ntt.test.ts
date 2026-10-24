import { describe, expect, it } from 'vitest';
import {
  accumulateProduct,
  finishNegacyclic,
  preparePolynomial,
  productAccumulator,
} from './ntt';
import { mod } from './ring';
import { Rng } from './rng';

function definitionalNegacyclic(
  terms: readonly (readonly [Int32Array, Int32Array])[],
  q: number
): Int32Array {
  const n = terms[0][0].length;
  const exact = new Float64Array(n);
  for (const [left, right] of terms) {
    for (let i = 0; i < n; i += 1) {
      for (let j = 0; j < n; j += 1) {
        const exponent = i + j;
        if (exponent < n) exact[exponent] += left[i] * right[j];
        else exact[exponent - n] -= left[i] * right[j];
      }
    }
  }
  return Int32Array.from(exact, (coefficient) => mod(coefficient, q));
}

describe('exact NTT/CRT products for key switching', () => {
  it('matches a definitional negacyclic oracle across accumulated products', () => {
    const rng = Rng.fromSeed('ntt-definition');
    const n = 32;
    const q = 67_108_859;
    const terms: Array<readonly [Int32Array, Int32Array]> = [];
    const accumulator = productAccumulator(n);
    for (let term = 0; term < 7; term += 1) {
      const digits = Int32Array.from({ length: n }, () => rng.uniformBelow(4));
      const key = Int32Array.from({ length: n }, () => rng.uniformBelow(q));
      terms.push([digits, key]);
      accumulateProduct(accumulator, preparePolynomial(digits, n), preparePolynomial(key, n));
    }
    const bound = n * (q - 1) * 3 * terms.length;
    expect(Array.from(finishNegacyclic(accumulator, q, bound))).toEqual(
      Array.from(definitionalNegacyclic(terms, q))
    );
  });

  it('gets the X^(n-1) times X sign right', () => {
    const n = 16;
    const q = 67_108_859;
    const left = new Int32Array(n);
    const right = new Int32Array(n);
    left[n - 1] = 1;
    right[1] = 1;
    const accumulator = productAccumulator(n);
    accumulateProduct(accumulator, preparePolynomial(left, n), preparePolynomial(right, n));
    const product = finishNegacyclic(accumulator, q, 1);
    expect(product[0]).toBe(q - 1);
    expect(Array.from(product.subarray(1))).toEqual(Array(n - 1).fill(0));
  });

  it('fails closed when the declared coefficient bound cannot fit the CRT basis', () => {
    const n = 16;
    const accumulator = productAccumulator(n);
    expect(() => finishNegacyclic(accumulator, 17, Number.MAX_SAFE_INTEGER)).toThrow(
      /does not fit the exact CRT interval/
    );
  });
});
