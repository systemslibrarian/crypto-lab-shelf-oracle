import { PirError } from './errors';

/**
 * The parameter surface of the lab, and the guards that refuse to run outside it.
 *
 * Everything the learner can move lives here, and every one of these knobs
 * changes real arithmetic — none of them is a display setting.
 */
export interface PirParams {
  /** Ring degree. The ring is R_q = Z_q[X] / (X^n + 1); n is a power of two. */
  readonly n: number;
  /** Ciphertext modulus. Prime, though BFV does not require primality. */
  readonly q: number;
  /** Plaintext modulus. Records live in Z_t coefficient by coefficient. */
  readonly t: number;
  /** Centred-binomial parameter of the error distribution; sigma = sqrt(eta/2). */
  readonly eta: number;
  /** How many of the n coefficients a record occupies. Record bytes = coeffsUsed / 2. */
  readonly coeffsUsed: number;
}

/**
 * The ring degree, fixed at 1024.
 *
 * 1024 is the SMALLEST entry in the Homomorphic Encryption Security Standard's
 * table, which is the whole reason it was chosen: a lab that ran at n = 256
 * would be quoting no standard at all. Anything larger is out of reach of a
 * schoolbook O(n^2) multiply running inside a page — see `ring.ts` for why the
 * multiply is schoolbook and what the real thing does instead.
 */
export const RING_DEGREE = 1024;

/**
 * The plaintext modulus, fixed at 17.
 *
 * Records are packed FOUR BITS to a coefficient, so a coefficient carries a
 * nibble in [0, 16) and 17 leaves a value spare. Bigger t would carry more
 * bytes per ciphertext — and would multiply the noise, because the error of
 * every one of the N records is scaled by that record's own coefficients when
 * the server multiplies. At t = 257 (a byte per coefficient) the noise from a
 * 64-record shelf overruns the decryption ceiling at every modulus this lab
 * offers, which is why the record-size knob moves `coeffsUsed` instead: it is
 * the same trade — more payload, more noise — expressed in a way that stays
 * decodable at the top of the range.
 */
export const PLAIN_MODULUS = 17;

/** Bits of payload per plaintext coefficient. */
export const BITS_PER_COEFF = 4;

/**
 * Error distribution parameter. sigma = sqrt(21/2) = 3.2404..., at or above the
 * sigma = 3.19 the HES table is stated for, with hard support [-21, 21].
 */
export const ERROR_ETA = 21;

/** Standard deviation of the centred binomial the lab samples its error from. */
export const ERROR_SIGMA = Math.sqrt(ERROR_ETA / 2);

export interface ModulusOption {
  readonly logQ: number;
  readonly q: number;
  readonly label: string;
}

/**
 * The selectable ciphertext moduli, each the largest prime below 2^logQ.
 *
 * The top entry is deliberately outside the standard. At n = 1024 the HES
 * 128-bit classical table stops at log q = 27, so 2^30 buys a great deal of
 * noise budget and pays for it by leaving the table — which is `PARAM_UNSAFE`,
 * and is the honest shape of the trade rather than a scolding banner.
 */
export const MODULI: readonly ModulusOption[] = [
  { logQ: 18, q: 262139, label: '2^18' },
  { logQ: 20, q: 1048573, label: '2^20' },
  { logQ: 22, q: 4194301, label: '2^22' },
  { logQ: 24, q: 16777213, label: '2^24' },
  { logQ: 26, q: 67108859, label: '2^26' },
  { logQ: 30, q: 1073741789, label: '2^30' },
];

/** The modulus a fresh page loads with: the largest that stays inside the table. */
export const DEFAULT_MODULUS = MODULI[4];

/** Selectable record sizes, in bytes. Two nibbles per byte, so 2 coefficients each. */
export const RECORD_SIZES = [128, 256, 512] as const;

/** The record size a fresh page loads with. */
export const DEFAULT_RECORD_BYTES = 512;

/** Selectable shelf sizes for the cost and exhaustion exhibits. */
export const SHELF_SIZES = [16, 32, 64, 128, 256] as const;

/** The shelf size a fresh page loads with — the authored catalog's real length. */
export const DEFAULT_SHELF_SIZE = 64;

/** Build a parameter set from the two knobs that vary. */
export function makeParams(q: number, recordBytes: number): PirParams {
  return {
    n: RING_DEGREE,
    q,
    t: PLAIN_MODULUS,
    eta: ERROR_ETA,
    coeffsUsed: recordBytes * (8 / BITS_PER_COEFF),
  };
}

/** The default parameter set. */
export function defaultParams(): PirParams {
  return makeParams(DEFAULT_MODULUS.q, DEFAULT_RECORD_BYTES);
}

/** Delta = floor(q / t), the scaling factor a plaintext coefficient is lifted by. */
export function delta(p: PirParams): number {
  return Math.floor(p.q / p.t);
}

/**
 * Refuse a parameter set whose worst-case intermediate product could leave the
 * range where a JavaScript number is an exact integer.
 *
 * This is the one guard that is about the IMPLEMENTATION rather than the
 * cryptography, and it is fail-closed for a specific reason: past 2^53 the
 * arithmetic silently rounds. Nothing throws, no coefficient looks wrong, and
 * the demo would go on producing ciphertexts that decrypt to plausible garbage
 * while claiming to be exact. `ring.ts` accumulates n products of a
 * centre-lifted ciphertext coefficient (magnitude at most q/2) by a plaintext
 * coefficient (at most t - 1) before it reduces, so that product is the bound.
 *
 * At the shipped parameters the bound is 1024 * 2^25 * 16 — a shade under 2^39,
 * so 2^14 of headroom. Since the bound is linear in each of n, q and t, that is
 * fourteen doublings shared between the three of them, and the top modulus this
 * lab already offers spends four: at q = 2^30 the bound is 2^43 and only 2^10
 * remains. Comfortable, then, but a long way from unlimited — which is why this
 * is a computed guard rather than a comment.
 */
export function assertExactArithmetic(p: PirParams): void {
  const worst = p.n * Math.ceil(p.q / 2) * (p.t - 1);
  if (worst > Number.MAX_SAFE_INTEGER) {
    throw new PirError(
      'PARAM_UNSAFE',
      `n * (q/2) * (t-1) = ${worst.toExponential(3)} exceeds 2^53, where JavaScript ` +
        `integers stop being exact. This implementation would round silently.`
    );
  }
}

/** Refuse a shelf position the catalog does not have. */
export function assertIndexInRange(index: number, shelfSize: number): void {
  if (!Number.isInteger(index) || index < 0 || index >= shelfSize) {
    throw new PirError(
      'INDEX_OUT_OF_RANGE',
      `shelf position ${index} is outside 0 .. ${shelfSize - 1}`
    );
  }
}

/**
 * Refuse a query whose length disagrees with the shelf the server holds.
 *
 * A short query would answer over a prefix of the shelf and a long one would
 * read past its end; both return a ciphertext that decrypts to something, which
 * is why this is checked before any homomorphic work rather than after.
 */
export function assertDimensionsMatch(queryLength: number, shelfSize: number): void {
  if (queryLength !== shelfSize) {
    throw new PirError(
      'DIM_MISMATCH',
      `the query carries ${queryLength} ciphertexts but the shelf holds ${shelfSize} records`
    );
  }
}
