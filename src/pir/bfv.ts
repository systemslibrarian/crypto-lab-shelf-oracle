import { assertExactArithmetic, delta, type PirParams } from './params';
import type { Rng } from './rng';
import {
  addPoly,
  centerLift,
  mod,
  mulBySmall,
  negPoly,
  zeroPoly,
} from './ring';

/**
 * Textbook BFV (Fan & Vercauteren, "Somewhat Practical Fully Homomorphic
 * Encryption", IACR ePrint 2012/144), reduced to exactly what single-server PIR
 * needs.
 *
 * WHAT IS HERE: key generation, encryption, decryption, ciphertext addition,
 * and plaintext-by-ciphertext multiplication. That is the complete operation
 * set of the SealPIR inner product — the server multiplies each of its own
 * PLAINTEXT records by an encrypted selection bit and adds the results.
 *
 * WHAT IS DELIBERATELY ABSENT: ciphertext-by-ciphertext multiplication, and
 * therefore relinearization and key switching. Not an omission — a consequence.
 * The one-hot form of PIR never multiplies two ciphertexts, which is precisely
 * why it fits in a 2^26 modulus at all: a plaintext multiply grows the noise by
 * a factor bounded by the plaintext's own size, where a ciphertext multiply
 * grows it by a factor of q. FHE Arena is the lab that shows the expensive kind.
 *
 * NOISE. A fresh ciphertext satisfies c0 + c1*s = Delta*m + e (mod q) with e
 * small. Every operation adds to e; decryption is correct while e stays under
 * the ceiling. Nothing here estimates the noise — `invariantNoiseBudget` DECRYPTS
 * and MEASURES it, which is only possible because this page holds the secret key
 * and the true plaintext. A real client can do neither, and the page says so
 * where the meter is drawn.
 */

/** A two-component BFV ciphertext. Never three: nothing here multiplies ciphertexts. */
export interface Ciphertext {
  readonly c0: Int32Array;
  readonly c1: Int32Array;
}

/** The secret key: a uniform ternary ring element, held as signed bytes. */
export interface SecretKey {
  readonly s: Int8Array;
}

/** Sample the uniform ternary secret key. */
export function keyGen(p: PirParams, rng: Rng): SecretKey {
  assertExactArithmetic(p);
  const s = new Int8Array(p.n);
  for (let i = 0; i < p.n; i += 1) s[i] = rng.ternary();
  return { s };
}

/** Sample a uniform ring element — the `a` half of every RLWE sample. */
export function sampleUniform(p: PirParams, rng: Rng): Int32Array {
  const a = new Int32Array(p.n);
  for (let i = 0; i < p.n; i += 1) a[i] = rng.uniformBelow(p.q);
  return a;
}

/** Sample a centred-binomial error polynomial. */
export function sampleError(p: PirParams, rng: Rng): Int8Array {
  const e = new Int8Array(p.n);
  for (let i = 0; i < p.n; i += 1) e[i] = rng.cbd(p.eta);
  return e;
}

/** Lift a signed small polynomial into R_q. */
function liftSmall(small: Int8Array, q: number): Int32Array {
  const out = new Int32Array(small.length);
  for (let i = 0; i < small.length; i += 1) out[i] = mod(small[i], q);
  return out;
}

/**
 * Encrypt a plaintext polynomial under the secret key.
 *
 * c1 = a (uniform), c0 = -(a * s) + Delta * m + e.
 *
 * `randomness` exists so the deliberately-broken exhibit can hand the SAME
 * (a, e) pair to every encryption and show what that costs. It is never used
 * on the honest path — `encrypt` draws fresh randomness per call, which is the
 * property the whole scheme rests on.
 */
export function encrypt(
  p: PirParams,
  sk: SecretKey,
  m: Int32Array,
  rng: Rng,
  randomness?: { a: Int32Array; e: Int8Array }
): Ciphertext {
  const a = randomness ? randomness.a : sampleUniform(p, rng);
  const e = randomness ? randomness.e : sampleError(p, rng);
  const d = delta(p);

  const scaled = new Int32Array(p.n);
  for (let i = 0; i < p.n; i += 1) scaled[i] = mod(mod(m[i], p.t) * d, p.q);

  const as = mulBySmall(a, sk.s, p.q);
  const c0 = addPoly(addPoly(negPoly(as, p.q), scaled, p.q), liftSmall(e, p.q), p.q);
  return { c0, c1: a };
}

/** Encrypt a single integer as the constant coefficient, everything else zero. */
export function encryptScalar(
  p: PirParams,
  sk: SecretKey,
  value: number,
  rng: Rng,
  randomness?: { a: Int32Array; e: Int8Array }
): Ciphertext {
  const m = zeroPoly(p.n);
  m[0] = mod(value, p.t);
  return encrypt(p, sk, m, rng, randomness);
}

/**
 * The raw decryption value c0 + c1*s (mod q), before decoding.
 *
 * Kept separate from `decrypt` because the page shows it: this polynomial is
 * Delta*m + e, and holding it beside Delta*m is how the noise stops being an
 * abstraction.
 */
export function decryptRaw(p: PirParams, sk: SecretKey, ct: Ciphertext): Int32Array {
  return addPoly(ct.c0, mulBySmall(ct.c1, sk.s, p.q), p.q);
}

/**
 * Decrypt and decode: round(t * v / q) mod t, coefficient by coefficient.
 *
 * This is the scale-invariant BFV decoding rather than round(v / Delta). The
 * two differ by a term of order (q mod t) / t, which is under 17 here and
 * therefore invisible in practice — but the scale-invariant form is the one
 * whose error bound is stated in the literature, and using it lets the noise
 * measurement below be SEAL's definition rather than an approximation of it.
 */
export function decrypt(p: PirParams, sk: SecretKey, ct: Ciphertext): Int32Array {
  const v = decryptRaw(p, sk, ct);
  const out = new Int32Array(p.n);
  for (let i = 0; i < p.n; i += 1) {
    out[i] = mod(Math.round((p.t * centerLift(v[i], p.q)) / p.q), p.t);
  }
  return out;
}

/** Add two ciphertexts. Enc(m1) + Enc(m2) decrypts to m1 + m2 mod t. */
export function addCiphertext(p: PirParams, a: Ciphertext, b: Ciphertext): Ciphertext {
  return { c0: addPoly(a.c0, b.c0, p.q), c1: addPoly(a.c1, b.c1, p.q) };
}

/**
 * The invariant noise of a ciphertext, given the plaintext it should hold.
 *
 * Microsoft SEAL's definition: v = (t/q) * (c0 + c1*s) - m, reduced to the
 * representative nearest zero modulo t. Decryption is correct exactly while
 * ||v||_inf < 1/2, so this single number is the whole correctness story, and it
 * is a MEASUREMENT — the ciphertext is decrypted and compared against the truth.
 *
 * Requires the secret key AND the true plaintext, neither of which a real client
 * has for a record it has not yet seen. This is the teacher's instrument.
 */
export function invariantNoise(
  p: PirParams,
  sk: SecretKey,
  ct: Ciphertext,
  trueMessage: Int32Array
): number {
  const v = decryptRaw(p, sk, ct);
  let worst = 0;
  for (let i = 0; i < p.n; i += 1) {
    let d = (p.t * centerLift(v[i], p.q)) / p.q - mod(trueMessage[i], p.t);
    d -= p.t * Math.round(d / p.t);
    const abs = Math.abs(d);
    if (abs > worst) worst = abs;
  }
  return worst;
}

/**
 * The remaining noise budget in bits: -log2(2 * ||v||_inf).
 *
 * Zero means the next coefficient to drift decodes to the wrong value. Clamped
 * at zero from below (a budget of "-3 bits" is not a smaller number, it is
 * garbage) and at a fresh ciphertext's budget from above.
 */
export function noiseBudgetBits(
  p: PirParams,
  sk: SecretKey,
  ct: Ciphertext,
  trueMessage: Int32Array
): number {
  const v = invariantNoise(p, sk, ct, trueMessage);
  if (v <= 0) return maxBudgetBits(p);
  return Math.min(maxBudgetBits(p), Math.max(0, -Math.log2(2 * v)));
}

/**
 * The ceiling the meter is drawn against: log2(Delta), where Delta = floor(q/t).
 *
 * Delta is exactly the room one plaintext coefficient has before it collides
 * with its neighbour, so log2(Delta) is the most budget the modulus can offer.
 *
 * A FRESH CIPHERTEXT DOES NOT REACH IT, and that is worth seeing rather than
 * smoothing over: encryption samples its own error, so at the shipped
 * parameters a brand-new ciphertext measures about 16.5 bits against a 21.91-bit
 * ceiling — roughly five bits already spent before the server does anything at
 * all. The one thing that DOES read at the ceiling is an empty accumulator,
 * which holds no error because it holds nothing.
 */
export function maxBudgetBits(p: PirParams): number {
  return Math.log2(delta(p));
}

/**
 * The heuristic noise-growth prediction for a PIR answer over `records`
 * records, in bits of budget consumed.
 *
 * Each of the N plaintext-by-ciphertext products contributes an error term
 * p_i * e_i whose coefficients are sums of `coeffsUsed` independent products of
 * a plaintext coefficient (mean square (t-1)(2t-1)/6 over a uniform nibble) by
 * an error sample (variance eta/2). Treating those as independent gives a
 * standard deviation that grows as sqrt(N * coeffsUsed), which is the sqrt(N)
 * the page plots against the measured value.
 *
 * PREDICTION, NOT MEASUREMENT — and the page labels it so. It is drawn beside
 * the measured budget precisely so a learner can see the two agree, and see
 * where they part company.
 */
export function predictedBudgetBits(p: PirParams, records: number): number {
  const nibble = p.t - 1; // nibbles are drawn from [0, 16); t = 17 leaves one spare
  const meanSquarePlain = ((nibble - 1) * (2 * nibble - 1)) / 6;
  const errorVariance = p.eta / 2;
  const sigma = Math.sqrt(records * p.coeffsUsed * meanSquarePlain * errorVariance);
  // Six standard deviations, expressed as invariant noise (scaled by t/q).
  const invariant = (p.t * 6 * sigma) / p.q;
  if (invariant <= 0) return maxBudgetBits(p);
  return Math.max(0, -Math.log2(2 * invariant));
}

/**
 * Open up the decryption identity for one coefficient so it can be shown rather
 * than described: c0 + c1*s = Delta*m + e (mod q).
 */
export interface NoiseTrace {
  readonly coefficient: number;
  readonly delta: number;
  readonly message: number;
  /**
   * Delta * m — the signal decryption is trying to see, in the canonical
   * representation [0, q).
   *
   * Canonical rather than centre-lifted DELIBERATELY. m < t and Delta =
   * floor(q/t), so Delta * m is always below q and the canonical value IS the
   * product, exactly as written. Centre-lifting it would print a large negative
   * number for any m above t/2 — arithmetically correct, and unreadable next to
   * a line that claims to show "Delta times nine".
   */
  readonly signal: number;
  /** c0 + c1*s in [0, q) — the signal with the noise still on it. */
  readonly recovered: number;
  /** recovered - signal, centre-lifted: the noise, signed. */
  readonly error: number;
  /** The ceiling: half of Delta. Past this the rounding lands on the wrong m. */
  readonly ceiling: number;
  /** What the coefficient actually decodes to. */
  readonly decoded: number;
}

export function traceCoefficient(
  p: PirParams,
  sk: SecretKey,
  ct: Ciphertext,
  trueMessage: Int32Array,
  coefficient: number
): NoiseTrace {
  const d = delta(p);
  const v = decryptRaw(p, sk, ct);
  const recovered = mod(v[coefficient], p.q);
  const message = mod(trueMessage[coefficient], p.t);
  const signal = mod(message * d, p.q);
  return {
    coefficient,
    delta: d,
    message,
    signal,
    recovered,
    error: centerLift(recovered - signal, p.q),
    ceiling: d / 2,
    decoded: mod(Math.round((p.t * centerLift(recovered, p.q)) / p.q), p.t),
  };
}
