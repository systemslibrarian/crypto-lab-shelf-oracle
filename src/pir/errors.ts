/**
 * The four failure codes this lab can raise, and the fail-closed error that
 * carries them.
 *
 * Every one of them is reachable from the page by doing something a real client
 * or server could do, and every one of them stops the protocol rather than
 * returning a value that looks plausible. That is the whole point of naming
 * them: a PIR answer that is quietly wrong is indistinguishable from a PIR
 * answer that is quietly right, because the client cannot see the database.
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
