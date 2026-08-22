/**
 * Arithmetic in R_q = Z_q[X] / (X^n + 1) — the negacyclic ring every RLWE
 * scheme lives in.
 *
 * NEGACYCLIC is the whole content of this file. Reducing modulo X^n + 1 means
 * X^n = -1, so a product term that lands at degree n + k does not wrap round to
 * degree k the way it would modulo X^n - 1: it wraps round AND CHANGES SIGN.
 * Every loop below that writes to `i + j - n` therefore subtracts. Getting that
 * one sign wrong produces a ring that is still perfectly self-consistent and
 * still round-trips through encrypt/decrypt, so no correctness test that only
 * asks "did I get my message back" can see it — which is why `ring.test.ts`
 * checks X^(n-1) * X = -1 directly.
 *
 * SCHOOLBOOK, ON PURPOSE. Every multiply here is O(n^2). Real implementations
 * do this with a negacyclic number-theoretic transform in O(n log n) and keep
 * ciphertexts in the evaluation domain between operations. That is the single
 * largest engineering difference between this page and a library like Microsoft
 * SEAL, and it is out of scope here rather than hidden: at n = 1024 a full
 * 64-record answer takes well under a tenth of a second in schoolbook form, and
 * the loop below is readable in a way an NTT butterfly is not.
 *
 * EXACTNESS. Coefficients are held canonically in [0, q) in an Int32Array;
 * accumulation happens in a Float64Array WITHOUT reduction, because a double
 * represents every integer up to 2^53 exactly and the worst-case accumulated
 * magnitude at the shipped parameters is about 2^39. `assertExactArithmetic` in
 * `params.ts` is the guard that keeps that true if the parameters move.
 */

/** Reduce into [0, m). Returns +0 rather than -0 so decoded values compare cleanly. */
export function mod(x: number, m: number): number {
  const r = x % m;
  return (r < 0 ? r + m : r) + 0;
}

/** Map [0, q) onto the balanced representatives (-q/2, q/2]. */
export function centerLift(x: number, q: number): number {
  const r = mod(x, q);
  return r > q / 2 ? r - q : r;
}

/** A zero polynomial with n coefficients. */
export function zeroPoly(n: number): Int32Array {
  return new Int32Array(n);
}

/** Coefficient-wise addition in R_q. */
export function addPoly(a: Int32Array, b: Int32Array, q: number): Int32Array {
  const out = new Int32Array(a.length);
  for (let i = 0; i < a.length; i += 1) out[i] = mod(a[i] + b[i], q);
  return out;
}

/** Coefficient-wise subtraction in R_q. */
export function subPoly(a: Int32Array, b: Int32Array, q: number): Int32Array {
  const out = new Int32Array(a.length);
  for (let i = 0; i < a.length; i += 1) out[i] = mod(a[i] - b[i], q);
  return out;
}

/** Coefficient-wise negation in R_q. */
export function negPoly(a: Int32Array, q: number): Int32Array {
  const out = new Int32Array(a.length);
  for (let i = 0; i < a.length; i += 1) out[i] = mod(-a[i], q);
  return out;
}

/**
 * Multiply a ring element by a SMALL SIGNED polynomial — a ternary secret key,
 * or a centred-binomial error — accumulating exactly, then reducing.
 *
 * This is the only shape of multiply RLWE key generation, encryption and
 * decryption need here, and it is why this lab never has to reduce a product of
 * two full-width coefficients: one side is always bounded by eta (21) or by 1.
 */
export function mulBySmall(a: Int32Array, small: Int8Array, q: number): Int32Array {
  const n = a.length;
  const acc = new Float64Array(n);
  for (let i = 0; i < n; i += 1) {
    const si = small[i];
    if (si === 0) continue;
    const lim = n - i;
    for (let j = 0; j < lim; j += 1) acc[i + j] += si * a[j];
    // X^n = -1: everything past degree n - 1 folds back with a sign flip.
    for (let j = lim; j < n; j += 1) acc[i + j - n] -= si * a[j];
  }
  const out = new Int32Array(n);
  for (let i = 0; i < n; i += 1) out[i] = mod(acc[i], q);
  return out;
}

/**
 * Accumulate `plain * cipher` into `acc`, negacyclically, without reducing.
 *
 * THE INNER LOOP OF THE WHOLE LAB. `plain` is one record's coefficients, each
 * in [0, t); `cipher` is one component of one query ciphertext, centre-lifted so
 * the accumulator stays balanced around zero rather than drifting up towards
 * n * q. Called 2N times per answer — once per component, once per record — and
 * `acc` is reduced by `reduceAccumulator` after each record.
 *
 * `plain[i] === 0` is skipped. That is a real timing side channel: the server's
 * work depends on how many zero nibbles a record holds. It costs nothing to
 * exploit here because the server's own data is public in this demo, but it is
 * exactly the kind of shortcut a deployment must not take, and it is named in
 * the page's honest-scope panel rather than quietly enjoyed.
 */
export function mulAccumulate(
  acc: Float64Array,
  plain: Int32Array,
  cipherCentered: Float64Array,
  n: number
): void {
  for (let i = 0; i < n; i += 1) {
    const pi = plain[i];
    if (pi === 0) continue;
    const lim = n - i;
    for (let j = 0; j < lim; j += 1) acc[i + j] += pi * cipherCentered[j];
    for (let j = lim; j < n; j += 1) acc[i + j - n] -= pi * cipherCentered[j];
  }
}

/** Centre-lift a canonical polynomial into a Float64Array for accumulation. */
export function toCentered(a: Int32Array, q: number): Float64Array {
  const out = new Float64Array(a.length);
  for (let i = 0; i < a.length; i += 1) out[i] = centerLift(a[i], q);
  return out;
}

/** Reduce an accumulator in place, keeping it centre-lifted. */
export function reduceAccumulator(acc: Float64Array, q: number): void {
  for (let i = 0; i < acc.length; i += 1) acc[i] = centerLift(acc[i], q);
}

/** Snapshot an accumulator as a canonical ring element. */
export function accumulatorToPoly(acc: Float64Array, q: number): Int32Array {
  const out = new Int32Array(acc.length);
  for (let i = 0; i < acc.length; i += 1) out[i] = mod(acc[i], q);
  return out;
}

/** The largest absolute centre-lifted coefficient — the infinity norm on R_q. */
export function infinityNorm(a: Int32Array, q: number): number {
  let m = 0;
  for (let i = 0; i < a.length; i += 1) {
    const v = Math.abs(centerLift(a[i], q));
    if (v > m) m = v;
  }
  return m;
}

/** Byte-for-byte equality of two ring elements. */
export function polyEquals(a: Int32Array, b: Int32Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
  return true;
}
