/**
 * The four failure codes this lab can raise.
 *
 * Every one is reachable from the page by doing something a real client or
 * server could do. They divide into REFUSALS and REPORTS, and the difference is
 * not cosmetic — it is whether stopping is even possible.
 *
 * REFUSALS throw `PirError` and no answer is produced: `DIM_MISMATCH`,
 * `INDEX_OUT_OF_RANGE`, and `PARAM_UNSAFE` when it fires from the exact-integer
 * guard in `assertExactArithmetic`. Each of those is a condition the code can
 * detect before it computes anything wrong.
 *
 * REPORTS are returned rather than thrown, because there is nothing to stop.
 * `NOISE_BUDGET_EXHAUSTED` is the important one: the ciphertext decrypts
 * perfectly well and simply yields the wrong bytes, so all anyone can do is
 * measure it and say so. `PARAM_UNSAFE` also reports rather than refuses when it
 * comes from the security table — the parameters still compute correct answers,
 * they just leave the published estimate behind, and refusing would delete the
 * exhibit that shows what leaving it buys.
 *
 * Naming them is the whole point either way: a PIR answer that is quietly wrong
 * is indistinguishable from one that is quietly right, because the client cannot
 * see the database.
 */
export type FailureCode =
  /** The accumulated RLWE noise passed the decryption ceiling. The returned
   *  ciphertext still decrypts — to garbage. Raised when the measured invariant
   *  noise budget reaches zero, or when the decoded record fails its own
   *  integrity tag. */
  | 'NOISE_BUDGET_EXHAUSTED'
  /** The encrypted selection vector is not the same length as the database the
   *  server holds. Refused before any homomorphic work, because a shorter query
   *  silently answers over a prefix of the shelf and a longer one reads past it. */
  | 'DIM_MISMATCH'
  /** The (ring degree, ciphertext modulus, secret distribution) triple is not a
   *  row of the Homomorphic Encryption Security Standard's 128-bit table, or it
   *  would push this implementation's integer arithmetic past 2^53 where
   *  JavaScript numbers stop being exact. */
  | 'PARAM_UNSAFE'
  /** The requested shelf position does not exist in the catalog. */
  | 'INDEX_OUT_OF_RANGE';

/** Every failure code, in the order the page lists them. */
export const FAILURE_CODES: readonly FailureCode[] = [
  'NOISE_BUDGET_EXHAUSTED',
  'DIM_MISMATCH',
  'PARAM_UNSAFE',
  'INDEX_OUT_OF_RANGE',
];

/**
 * A refusal, not a return value.
 *
 * `detail` is the human sentence the page prints beside the code; `code` is what
 * tests assert on, so the wording can change without a test agreeing with a bug.
 */
export class PirError extends Error {
  readonly code: FailureCode;
  readonly detail: string;

  constructor(code: FailureCode, detail: string) {
    super(`${code}: ${detail}`);
    this.name = 'PirError';
    this.code = code;
    this.detail = detail;
  }
}

/** Narrow an unknown thrown value to a PirError. */
export function isPirError(e: unknown): e is PirError {
  return e instanceof PirError;
}
