import {
  encryptScalar,
  noiseBudgetBits,
  sampleError,
  sampleUniform,
  type Ciphertext,
  type SecretKey,
} from './bfv';
import { PirError } from './errors';
import { assertDimensionsMatch, assertIndexInRange, type PirParams } from './params';
import {
  accumulatorToPoly,
  centerLift,
  mulAccumulate,
  reduceAccumulator,
  toCentered,
} from './ring';
import type { Rng } from './rng';
import { coefficientsToBytes, tagMatches, TAG_BYTES } from './records';
import { decrypt } from './bfv';

/**
 * Single-server computational PIR, RLWE-based, in the direct one-hot form —
 * SealPIR (Angel, Chen, Laine and Setty, *PIR with Compressed Queries and
 * Amortized Query Processing*, IEEE S&P 2018) reduced to its core.
 *
 * THE PROTOCOL, IN THREE LINES.
 *   1. The client encrypts a selection vector b of length N under BFV:
 *      b_i = 1 at the wanted shelf position, 0 everywhere else.
 *   2. The server computes sum_i R_i * Enc(b_i) over its plaintext records R_i,
 *      homomorphically. One ciphertext comes back.
 *   3. The client decrypts it and gets R_index.
 *
 * WHY THE SERVER LEARNS NOTHING. Enc(0) and Enc(1) are indistinguishable to
 * anyone without the secret key under the RLWE assumption, so the query carries
 * no information about the index that an adversary bounded by that assumption
 * can extract. This is COMPUTATIONAL privacy, and that word is the entire
 * difference from Oblivious Shelf and Patron Shield: those two are
 * information-theoretic, and pay for it with a second server that must not
 * collude. Here there is one server and no collusion assumption, and the price
 * is the noise budget the meter on this page is counting down.
 *
 * WHAT THIS IS NOT. Full SealPIR does two more things that are out of scope in a
 * browser and named rather than faked:
 *   - QUERY EXPANSION. A real client sends ONE ciphertext plus Galois keys and
 *     the server expands it into the N-element selection vector with plaintext
 *     substitutions. That turns an O(N) upload into an O(1) one. This lab sends
 *     all N ciphertexts, which is why its upload column is enormous, and the
 *     head-to-head exhibit says so instead of quietly reporting SealPIR's number.
 *   - MULTI-DIMENSIONAL INDEXING. Treating the database as a d-dimensional cube
 *     turns N plaintext multiplications into d * N^(1/d), at the cost of
 *     ciphertext-by-ciphertext multiplications and therefore relinearization.
 *     One dimension is what fits the noise budget available here.
 */

/**
 * The client's query.
 *
 * `ciphertexts` is what crosses the wire. `plainSelection` is the one-hot vector
 * the client built it from — held here so the page can draw the greyed-out
 * plaintext beside the opaque ciphertexts, and passed to NO server function.
 * That separation is enforced by the shape of `serverAnswer`, which takes
 * ciphertexts and records and nothing else.
 */
export interface PirQuery {
  readonly ciphertexts: readonly Ciphertext[];
  readonly plainSelection: Uint8Array;
}

/**
 * How the selection vector's randomness was drawn.
 *
 * 'fresh' is the protocol. 'reused' hands every one of the N encryptions the
 * SAME uniform element and the SAME error polynomial, which makes Enc(1) differ
 * from Enc(0) by exactly Delta in one coefficient and is therefore trivially
 * distinguishable. It exists so a learner can cause that failure and watch a
 * real distinguisher go from chance to certain. It is never the default, it is
 * labelled broken everywhere it appears, and nothing else in the lab calls it.
 */
export type QueryRandomness = 'fresh' | 'reused';

/**
 * Build the encrypted selection vector.
 *
 * `weights` overrides the one-hot vector, which is how the malformed-query
 * exhibit sends a two-hot selection: the server cannot tell, because it cannot
 * read the query at all, and the client gets the SUM of two records back. That
 * is a real property of unauthenticated PIR and not a bug in this code.
 */
export function buildQuery(
  p: PirParams,
  sk: SecretKey,
  index: number,
  shelfSize: number,
  rng: Rng,
  options: { randomness?: QueryRandomness; weights?: Uint8Array } = {}
): PirQuery {
  assertIndexInRange(index, shelfSize);
  const selection = options.weights ?? new Uint8Array(shelfSize);
  if (!options.weights) selection[index] = 1;
  if (selection.length !== shelfSize) {
    throw new PirError(
      'DIM_MISMATCH',
      `selection vector has ${selection.length} entries but the shelf holds ${shelfSize}`
    );
  }

  const shared =
    options.randomness === 'reused'
      ? { a: sampleUniform(p, rng), e: sampleError(p, rng) }
      : undefined;

  const ciphertexts: Ciphertext[] = [];
  for (let i = 0; i < shelfSize; i += 1) {
    ciphertexts.push(encryptScalar(p, sk, selection[i], rng, shared));
  }
  return { ciphertexts, plainSelection: selection };
}

/**
 * The server's running state while it folds the shelf into one ciphertext.
 *
 * Held as centre-lifted Float64Arrays rather than reduced Int32Arrays because
 * the accumulation is exact up to 2^53 and reducing after every record is the
 * only reduction needed — see `ring.ts`.
 */
export interface AnswerState {
  readonly acc0: Float64Array;
  readonly acc1: Float64Array;
  readonly shelfSize: number;
  /** How many records have been folded in. The page steps this. */
  folded: number;
}

/**
 * Start an answer, refusing a query that does not match the shelf.
 *
 * DIM_MISMATCH is raised HERE — before a single multiplication — because a
 * mismatched query still produces a ciphertext. A query one element short
 * answers over a prefix of the shelf; one element long reads a record that is
 * not there. Both decrypt to something that looks like a record.
 */
export function beginAnswer(p: PirParams, shelfSize: number, queryLength: number): AnswerState {
  assertDimensionsMatch(queryLength, shelfSize);
  return {
    acc0: new Float64Array(p.n),
    acc1: new Float64Array(p.n),
    shelfSize,
    folded: 0,
  };
}

/**
 * Fold one record into the answer: acc += record * ciphertext.
 *
 * Both ciphertext components are multiplied by the SAME plaintext record, which
 * is what makes the result a valid encryption of `record * b_i` rather than two
 * unrelated polynomials.
 */
export function foldRecord(
  p: PirParams,
  state: AnswerState,
  record: Int32Array,
  ct: Ciphertext
): void {
  mulAccumulate(state.acc0, record, toCentered(ct.c0, p.q), p.n);
  mulAccumulate(state.acc1, record, toCentered(ct.c1, p.q), p.n);
  reduceAccumulator(state.acc0, p.q);
  reduceAccumulator(state.acc1, p.q);
  state.folded += 1;
}

/** Close the accumulator into a ciphertext. */
export function finishAnswer(p: PirParams, state: AnswerState): Ciphertext {
  return {
    c0: accumulatorToPoly(state.acc0, p.q),
    c1: accumulatorToPoly(state.acc1, p.q),
  };
}

/**
 * The whole server side, in one call.
 *
 * NOTE THE SIGNATURE. Parameters, the server's own records, and the query. No
 * secret key, no index, no plaintext selection vector — there is no argument
 * through which the index could reach this function, which is the architectural
 * form of the claim the page makes. `pir.test.ts` asserts the answer is
 * unchanged when the client's private state is discarded entirely.
 */
export function serverAnswer(
  p: PirParams,
  shelf: readonly Int32Array[],
  query: readonly Ciphertext[]
): Ciphertext {
  const state = beginAnswer(p, shelf.length, query.length);
  for (let i = 0; i < shelf.length; i += 1) foldRecord(p, state, shelf[i], query[i]);
  return finishAnswer(p, state);
}

/**
 * What a PARTIAL answer should decrypt to, after `folded` records.
 *
 * The meter on the page falls while the server is still working, which means
 * the noise has to be measured against the partial sum rather than against the
 * final record. Until the selected record is folded in, the accumulator is an
 * encryption of ZERO — and its noise is already growing, because every record
 * multiplied in so far contributed its own ciphertext's error even though it
 * contributed no message. That is the honest shape of the meter, and it is only
 * visible if the expected plaintext is recomputed at every step.
 */
export function partialMessage(
  p: PirParams,
  shelf: readonly Int32Array[],
  selection: Uint8Array,
  folded: number
): Int32Array {
  const out = new Int32Array(p.n);
  for (let i = 0; i < folded; i += 1) {
    const w = selection[i] % p.t;
    if (w === 0) continue;
    const record = shelf[i];
    for (let k = 0; k < p.n; k += 1) out[k] = (out[k] + w * record[k]) % p.t;
  }
  return out;
}

export interface DecodedAnswer {
  /** The record bytes as decoded. Garbage if the budget ran out. */
  readonly bytes: Uint8Array;
  /** Coefficients that came back outside [0, 16) — impossible for a real record. */
  readonly outOfRange: number;
  /** Whether the record's own SHA-256 tag checks out. */
  readonly tagOk: boolean;
  /** Measured invariant noise budget of the answer, in bits. */
  readonly budgetBits: number;
  /** Non-null when the answer is not trustworthy. */
  readonly failure: PirError | null;
}

/**
 * Decrypt an answer and say honestly whether it can be believed.
 *
 * `trueRecordCoefficients` is the teacher's copy of the record, used only to
 * MEASURE the noise budget — a real client has no such thing. The tag check and
 * the out-of-range count, by contrast, are things a real client genuinely could
 * do, which is why both are reported separately.
 */
export async function decodeAnswer(
  p: PirParams,
  sk: SecretKey,
  answer: Ciphertext,
  recordBytes: number,
  trueRecordCoefficients: Int32Array
): Promise<DecodedAnswer> {
  const coefficients = decrypt(p, sk, answer);
  const { bytes, outOfRange } = coefficientsToBytes(coefficients, recordBytes);
  const tagOk = await tagMatches(bytes);
  const budgetBits = noiseBudgetBits(p, sk, answer, trueRecordCoefficients);

  let failure: PirError | null = null;
  if (!tagOk || outOfRange > 0 || budgetBits <= 0) {
    failure = new PirError(
      'NOISE_BUDGET_EXHAUSTED',
      `the answer decrypted with ${budgetBits.toFixed(2)} bits of budget left, ` +
        `${outOfRange} coefficient(s) outside the encodable range, and its ` +
        `${TAG_BYTES}-byte integrity tag ${tagOk ? 'intact' : 'broken'}`
    );
  }
  return { bytes, outOfRange, tagOk, budgetBits, failure };
}

/**
 * A real distinguishing attack on a query, run by the page.
 *
 * The statistic: take each ciphertext's constant c0 coefficient, centre it on
 * the median of all of them, and pick the largest deviation. Against a properly
 * randomized query every c0 is uniform and independent of the plaintext, so this
 * is a coin flip weighted 1/N. Against a query whose randomness was reused, the
 * zeros are all IDENTICAL and the one is exactly Delta away, so it is right
 * every time.
 *
 * It is deliberately the simplest attack that works, because the point is not
 * that this particular statistic is clever — it is that no statistic can do
 * better than 1/N on the honest query, and the crudest one possible saturates on
 * the broken query.
 */
export function distinguishIndex(p: PirParams, ciphertexts: readonly Ciphertext[]): number {
  const heads = ciphertexts.map((ct) => centerLift(ct.c0[0], p.q));
  const sorted = [...heads].sort((a, b) => a - b);
  const median = sorted[Math.floor(sorted.length / 2)];
  let best = 0;
  let bestScore = -1;
  for (let i = 0; i < heads.length; i += 1) {
    const score = Math.abs(centerLift(heads[i] - median, p.q));
    if (score > bestScore) {
      bestScore = score;
      best = i;
    }
  }
  return best;
}
