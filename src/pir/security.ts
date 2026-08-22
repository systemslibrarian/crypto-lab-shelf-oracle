import type { PirParams } from './params';
import { ERROR_SIGMA } from './params';

/**
 * What the parameters are worth, taken from a published table rather than
 * asserted.
 *
 * SOURCE: *Homomorphic Encryption Security Standard*, Albrecht, Chase, Chen,
 * Ding, Goldwasser, Gorbunov, Halevi, Hoffstein, Laine, Lauter, Lokam,
 * Micciancio, Moody, Morrison, Sahai and Vaikuntanathan, HomomorphicEncryption.org,
 * Toronto, November 2018 — the UNIFORM TERNARY SECRET table, classical security,
 * error standard deviation sigma = 3.19. Each row gives the LARGEST log2(q) for
 * which the stated security level is estimated to hold at that ring degree.
 *
 * WHY A TABLE AND NOT AN ESTIMATOR. The honest alternative is to re-implement
 * the primal-uSVP / BKZ cost model and print a bit count of our own. That model
 * has moved several times since 2018 and a hand-rolled version of it here would
 * be a number this lab invented, dressed as a measurement. Quoting the published
 * table names the source, the assumptions and the date, and makes it checkable.
 *
 * WHAT THIS DOES NOT SAY. A row in this table is an estimate of the hardness of
 * the underlying RLWE instance in 2018. It is not a proof, it does not account
 * for advances since, and it says nothing whatsoever about this implementation:
 * the polynomial arithmetic here is not constant time, the secret key sits in
 * ordinary JavaScript memory, and nothing has been audited. "In the table" means
 * the parameters are not obviously broken, not that the demo is secure.
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
  /** The largest level in the table this (n, log q) pair satisfies, or 0. */
  readonly level: number;
  /** The 128-bit ceiling for this ring degree, or null if n is not in the table. */
  readonly ceiling128: number | null;
  /** True when the pair satisfies at least the 128-bit row. */
  readonly inTable: boolean;
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
      level: 0,
      ceiling128: null,
      inTable: false,
      summary:
        `Ring degree n = ${p.n} is not a row of the HES 2018 table (it starts at 1024), ` +
        `so no published estimate applies.`,
    };
  }
  let level = 0;
  for (const candidate of HES_LEVELS) {
    if (logQ <= row[candidate]) {
      level = candidate;
      break;
    }
  }
  const ceiling128 = row[128];
  const inTable = level >= 128;
  const summary = inTable
    ? `n = ${p.n}, log2 q = ${logQ}, uniform ternary secret, sigma = ${ERROR_SIGMA.toFixed(2)} ` +
      `sits inside the HES 2018 table's ${level}-bit classical row (ceiling log2 q = ${row[level]}).`
    : `n = ${p.n}, log2 q = ${logQ} exceeds the HES 2018 table's 128-bit ceiling of ` +
      `log2 q = ${ceiling128} for this ring degree. No published estimate covers it.`;
  return { n: p.n, logQ, level, ceiling128, inTable, summary };
}
