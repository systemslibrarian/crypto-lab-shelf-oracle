import type { PirParams } from './params';
import { ERROR_SIGMA } from './params';

/**
 * A modulus-bit comparison against a published table.
 *
 * SOURCE: *Homomorphic Encryption Security Standard*, Albrecht, Chase, Chen,
 * Ding, Goldwasser, Gorbunov, Halevi, Hoffstein, Laine, Lauter, Lokam,
 * Micciancio, Moody, Morrison, Sahai and Vaikuntanathan, HomomorphicEncryption.org,
 * Toronto, November 2018 — the UNIFORM TERNARY SECRET table, classical security,
 * discrete-Gaussian error standard deviation sigma about 3.19. Each row gives
 * the LARGEST log2(q) for which the stated security level is estimated to hold
 * at that ring degree under those assumptions.
 *
 * WHY A TABLE AND NOT AN ESTIMATOR. The honest alternative is to re-implement
 * the primal-uSVP / BKZ cost model and print a bit count of our own. That model
 * has moved several times since 2018 and a hand-rolled version of it here would
 * be a number this lab invented, dressed as a measurement. Quoting the published
 * table names the source, the assumptions and the date, and makes it checkable.
 *
 * DISTRIBUTION BOUNDARY. This lab deliberately samples centred-binomial error
 * with eta=21 (sigma about 3.24), not the table's discrete Gaussian. Equal or
 * nearby standard deviations do not make differently shaped distributions
 * interchangeable in a concrete security estimate. We therefore compare only
 * (n, ceil(log2(q))) with the published bit ceilings; we do not claim that the
 * table's security estimate transfers to this parameter tuple.
 *
 * WHAT THIS DOES NOT SAY. A row is a 2018 estimate, not a proof. It does not
 * account for subsequent attacks and says nothing about this implementation:
 * the arithmetic is not constant time, the secret key sits in ordinary
 * JavaScript memory, and nothing has been audited. Being at or below a published
 * modulus ceiling is only a reference comparison, not a security certification.
 */
export const HES_TERNARY_CLASSICAL: Readonly<Record<number, Readonly<Record<number, number>>>> = {
  // ring degree -> { security level in bits -> max log2(q) }
  1024: { 128: 27, 192: 19, 256: 14 },
  2048: { 128: 54, 192: 37, 256: 29 },
  4096: { 128: 109, 192: 75, 256: 58 },
  8192: { 128: 218, 192: 152, 256: 118 },
  16384: { 128: 438, 192: 305, 256: 237 },
  32768: { 128: 881, 192: 611, 256: 476 },
};

/** The security levels the table above carries, strongest first. */
export const HES_LEVELS = [256, 192, 128] as const;

export interface SecurityAssessment {
  /** Ring degree assessed. */
  readonly n: number;
  /** log2 of the ciphertext modulus in use, rounded up to the whole bit. */
  readonly logQ: number;
  /** Strongest table row whose modulus-bit ceiling is at least logQ, or 0. */
  readonly referenceLevel: number;
  /** The 128-bit ceiling for this ring degree, or null if n is not in the table. */
  readonly ceiling128: number | null;
  /** True when logQ is at or below the table's 128-bit modulus ceiling. */
  readonly atOrBelow128BitCeiling: boolean;
  /** A one-line, source-attributed summary for the page. */
  readonly summary: string;
}

/**
 * Assess a parameter set against the table.
 *
 * `logQ` is CEILED, not rounded: q = 2^26 - 5 is treated as a 26-bit modulus,
 * and anything above 2^26 as 27, so the comparison can never round a parameter
 * set INTO the table it just left.
 */
export function assessSecurity(p: PirParams): SecurityAssessment {
  const logQ = Math.ceil(Math.log2(p.q));
  const row = HES_TERNARY_CLASSICAL[p.n];
  if (!row) {
    return {
      n: p.n,
      logQ,
      referenceLevel: 0,
      ceiling128: null,
      atOrBelow128BitCeiling: false,
      summary:
        `Ring degree n = ${p.n} is not a row of the HES 2018 table (it starts at 1024), ` +
        `so no published modulus-bit comparison is available.`,
    };
  }
  let referenceLevel = 0;
  for (const candidate of HES_LEVELS) {
    if (logQ <= row[candidate]) {
      referenceLevel = candidate;
      break;
    }
  }
  const ceiling128 = row[128];
  const atOrBelow128BitCeiling = referenceLevel >= 128;
  const summary = atOrBelow128BitCeiling
    ? `n = ${p.n}, ceil(log2 q) = ${logQ} is at or below the HES 2018 ` +
      `${referenceLevel}-bit classical row's modulus ceiling of ${row[referenceLevel]} under its ` +
      `discrete-Gaussian-error model. This lab uses centred-binomial eta = 21 ` +
      `(sigma = ${ERROR_SIGMA.toFixed(2)}), so this is a bit-size comparison, not a transferred security estimate.`
    : `n = ${p.n}, log2 q = ${logQ} exceeds the HES 2018 table's 128-bit ceiling of ` +
      `log2 q = ${ceiling128} for this ring degree. No comparison with that published ceiling supports this choice; ` +
      `that fact alone does not prove the tuple insecure.`;
  return { n: p.n, logQ, referenceLevel, ceiling128, atOrBelow128BitCeiling, summary };
}
