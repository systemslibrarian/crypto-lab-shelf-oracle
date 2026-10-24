import { mod } from './ring';

/**
 * Exact polynomial products for the query-expansion key switch.
 *
 * The direct PIR lesson deliberately uses readable schoolbook multiplication.
 * A Galois key switch, however, needs dozens of dense ring products for every
 * expanded selector ciphertext. Repeating the schoolbook loop there would make
 * the executable lesson unusable in a browser. This module therefore performs
 * those products with two ordinary NTTs and reconstructs every integer
 * coefficient with the Chinese remainder theorem before reducing modulo q.
 *
 * Both auxiliary primes are below 2^24, support transforms through 2^20, and
 * have verified primitive roots. Every modular product is below 2^48 and the
 * CRT product is below 2^47, so JavaScript's binary64 numbers represent every
 * integer touched here exactly. `finishNegacyclic` also checks the caller's
 * mathematical coefficient bound; an undersized CRT basis fails closed rather
 * than silently wrapping.
 */

interface NttPrime {
  readonly modulus: number;
  readonly primitiveRoot: number;
}
const PRIMES: readonly [NttPrime, NttPrime] = [
  { modulus: 7_340_033, primitiveRoot: 3 }, // 7 * 2^20 + 1
  { modulus: 13_631_489, primitiveRoot: 15 }, // 13 * 2^20 + 1
];

const CRT_MODULUS = PRIMES[0].modulus * PRIMES[1].modulus;
const CRT_HALF = Math.floor(CRT_MODULUS / 2);

function powMod(base: number, exponent: number, modulus: number): number {
  let x = mod(base, modulus);
  let e = exponent;
  let out = 1;
  while (e > 0) {
    if (e % 2 === 1) out = (out * x) % modulus;
    x = (x * x) % modulus;
    e = Math.floor(e / 2);
  }
  return out;
}
const P0_INVERSE_MOD_P1 = powMod(
  PRIMES[0].modulus,
  PRIMES[1].modulus - 2,
  PRIMES[1].modulus
);

function assertTransformLength(length: number): void {
  if (!Number.isInteger(length) || length < 2 || (length & (length - 1)) !== 0) {
    throw new RangeError(`NTT length ${length} is not a power of two`);
  }
  for (const prime of PRIMES) {
    if ((prime.modulus - 1) % length !== 0) {
      throw new RangeError(`NTT length ${length} is unsupported by modulus ${prime.modulus}`);
    }
  }
}

function transform(values: Float64Array, prime: NttPrime, inverse: boolean): void {
  const n = values.length;
  assertTransformLength(n);

  for (let i = 1, j = 0; i < n; i += 1) {
    let bit = n >> 1;
    while (j & bit) {
      j ^= bit;
      bit >>= 1;
    }
    j ^= bit;
    if (i < j) {
      const swap = values[i];
      values[i] = values[j];
      values[j] = swap;
    }
  }

  for (let width = 2; width <= n; width <<= 1) {
    let root = powMod(prime.primitiveRoot, (prime.modulus - 1) / width, prime.modulus);
    if (inverse) root = powMod(root, prime.modulus - 2, prime.modulus);
    const half = width >> 1;
    for (let start = 0; start < n; start += width) {
      let twiddle = 1;
      for (let j = 0; j < half; j += 1) {
        const even = values[start + j];
        const odd = (values[start + j + half] * twiddle) % prime.modulus;
        const sum = even + odd;
        const difference = even - odd;
        values[start + j] = sum >= prime.modulus ? sum - prime.modulus : sum;
        values[start + j + half] = difference < 0 ? difference + prime.modulus : difference;
        twiddle = (twiddle * root) % prime.modulus;
      }
    }
  }

  if (inverse) {
    const inverseLength = powMod(n, prime.modulus - 2, prime.modulus);
    for (let i = 0; i < n; i += 1) values[i] = (values[i] * inverseLength) % prime.modulus;
  }
}

/** One polynomial already transformed under both auxiliary primes. */
export interface PreparedPolynomial {
  readonly ringDegree: number;
  readonly residues: readonly [Float64Array, Float64Array];
}

/** A pair of pointwise-product accumulators, one per auxiliary prime. */
export interface ProductAccumulator {
  readonly ringDegree: number;
  readonly residues: readonly [Float64Array, Float64Array];
}

/** Transform a degree-(n-1) polynomial after zero-padding it to length 2n. */
export function preparePolynomial(values: ArrayLike<number>, ringDegree: number): PreparedPolynomial {
  if (values.length !== ringDegree) {
    throw new RangeError(`polynomial has ${values.length} coefficients; expected ${ringDegree}`);
  }
  const length = ringDegree * 2;
  assertTransformLength(length);
  const residues = PRIMES.map((prime) => {
    const out = new Float64Array(length);
    for (let i = 0; i < ringDegree; i += 1) out[i] = mod(values[i], prime.modulus);
    transform(out, prime, false);
    return out;
  }) as unknown as [Float64Array, Float64Array];
  return { ringDegree, residues };
}

/** Start an exact convolution sum in the NTT domain. */
export function productAccumulator(ringDegree: number): ProductAccumulator {
  const length = ringDegree * 2;
  assertTransformLength(length);
  return {
    ringDegree,
    residues: [new Float64Array(length), new Float64Array(length)],
  };
}

/** Add one polynomial product to an accumulator without leaving the NTT domain. */
export function accumulateProduct(
  accumulator: ProductAccumulator,
  left: PreparedPolynomial,
  right: PreparedPolynomial
): void {
  if (
    left.ringDegree !== accumulator.ringDegree ||
    right.ringDegree !== accumulator.ringDegree
  ) {
    throw new RangeError('NTT polynomial dimensions do not match');
  }
  for (let which = 0; which < PRIMES.length; which += 1) {
    const prime = PRIMES[which].modulus;
    const out = accumulator.residues[which];
    const a = left.residues[which];
    const b = right.residues[which];
    for (let i = 0; i < out.length; i += 1) {
      out[i] = (out[i] + (a[i] * b[i]) % prime) % prime;
    }
  }
}

function crtSigned(residue0: number, residue1: number): number {
  const p0 = PRIMES[0].modulus;
  const p1 = PRIMES[1].modulus;
  const difference = mod(residue1 - residue0, p1);
  const multiple = (difference * P0_INVERSE_MOD_P1) % p1;
  let reconstructed = residue0 + p0 * multiple;
  if (reconstructed > CRT_HALF) reconstructed -= CRT_MODULUS;
  return reconstructed;
}

/**
 * Finish a sum of linear convolutions and fold it modulo X^n + 1.
 *
 * `absoluteBound` must bound each true, signed negacyclic coefficient before
 * reduction modulo q. It is checked both against the CRT range and against the
 * reconstructed output, making exactness an executable precondition.
 */
export function finishNegacyclic(
  accumulator: ProductAccumulator,
  q: number,
  absoluteBound: number
): Int32Array {
  if (!Number.isSafeInteger(absoluteBound) || absoluteBound < 0 || absoluteBound >= CRT_HALF) {
    throw new RangeError(
      `coefficient bound ${absoluteBound} does not fit the exact CRT interval ${CRT_HALF}`
    );
  }
  const time = accumulator.residues.map((values, which) => {
    const out = values.slice();
    transform(out, PRIMES[which], true);
    return out;
  }) as [Float64Array, Float64Array];

  const n = accumulator.ringDegree;
  const out = new Int32Array(n);
  for (let i = 0; i < n; i += 1) {
    const r0 = mod(time[0][i] - time[0][i + n], PRIMES[0].modulus);
    const r1 = mod(time[1][i] - time[1][i + n], PRIMES[1].modulus);
    const coefficient = crtSigned(r0, r1);
    if (Math.abs(coefficient) > absoluteBound) {
      throw new Error(
        `CRT reconstruction ${coefficient} exceeds the proved coefficient bound ${absoluteBound}`
      );
    }
    out[i] = mod(coefficient, q);
  }
  return out;
}
