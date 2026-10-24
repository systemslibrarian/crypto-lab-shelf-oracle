import {
  addCiphertext,
  encrypt,
  sampleError,
  sampleUniform,
  type Ciphertext,
  type SecretKey,
} from './bfv';
import {
  accumulateProduct,
  finishNegacyclic,
  preparePolynomial,
  productAccumulator,
  type PreparedPolynomial,
} from './ntt';
import { assertIndexInRange, type PirParams } from './params';
import { addPoly, mod, mulBySmall, negPoly, zeroPoly } from './ring';
import type { Rng } from './rng';
import {
  ciphertextBytes,
  deserializeCiphertext,
  serializeCiphertext,
} from './serialize';

/**
 * SealPIR-style compressed query expansion, bounded to one BFV ciphertext.
 *
 * The client encrypts 2^-ell * X^index, where ell = log2(m). The server applies
 * the odd automorphisms n/2^i + 1, key-switches each result back to the client's
 * key, and combines shifted copies exactly as `expand_query` in Microsoft's
 * SealPIR implementation does. For power-of-two m <= n, the output decrypts to
 * m scalar ciphertexts: one Enc(1), all others Enc(0).
 *
 * Unlike the direct lesson this path genuinely needs key switching. Evaluation
 * keys are noisy RLWE samples, not secret-key material disguised as a shortcut.
 * Their reusable serialized size is counted separately from the per-query
 * ciphertext because query compression moves cost; it does not erase it.
 */

/** Binary gadget decomposition: larger setup, but materially less switch noise. */
export const KEY_SWITCH_BASE = 2;

/**
 * The executable expansion lesson's declared bound.
 *
 * Sixteen 512-byte records fit the existing n=1024 plaintext exactly. The
 * largest prime below 2^27 keeps one more bit of switching headroom than the
 * direct lesson's default while staying at the HES table's published
 * log2(q)=27 ceiling for n=1024. HES uses a different error distribution, so
 * this is only a bit-size comparison; it is not a transferred security estimate
 * and does not make the implementation secure.
 */
export const EXPANSION_SELECTION_LENGTH = 16;
export const EXPANSION_RECORD_BYTES = 512;
export const EXPANSION_MODULUS = 134_217_689;

export interface GaloisEvaluationKey {
  readonly element: number;
  /** Raw RLWE encryptions of B^j * sigma_element(s), under s. */
  readonly digits: readonly Ciphertext[];
}
export interface EvaluationKeySet {
  readonly ringDegree: number;
  readonly q: number;
  readonly t: number;
  readonly base: number;
  readonly digitCount: number;
  readonly keys: readonly GaloisEvaluationKey[];
}

export interface CompressedQuery {
  readonly ciphertext: Ciphertext;
  readonly selectionLength: number;
}

export interface BuiltCompressedQuery extends CompressedQuery {
  /** The coefficient encrypted at X^index: (selectionLength)^-1 mod t. */
  readonly inverseScale: number;
}

export interface ExpansionRound {
  readonly round: number;
  readonly galoisElement: number;
  readonly inputs: number;
  readonly outputs: number;
  readonly automorphisms: number;
  readonly keySwitches: number;
  readonly keySwitchConvolutions: number;
  readonly ciphertextAdds: number;
  readonly monomialShifts: number;
}

export interface ExpansionTotals {
  readonly rounds: number;
  readonly automorphisms: number;
  readonly keySwitches: number;
  readonly keySwitchConvolutions: number;
  readonly ciphertextAdds: number;
  readonly monomialShifts: number;
}

export interface ExpansionResult {
  readonly ciphertexts: readonly Ciphertext[];
  readonly rounds: readonly ExpansionRound[];
  readonly totals: ExpansionTotals;
}

interface PreparedSwitchDigit {
  readonly c0: PreparedPolynomial;
  readonly c1: PreparedPolynomial;
}

const preparedCache = new WeakMap<
  EvaluationKeySet,
  Map<number, readonly PreparedSwitchDigit[]>
>();

function assertPowerOfTwoLength(p: PirParams, length: number): void {
  if (
    !Number.isInteger(length) ||
    length < 2 ||
    length > p.n ||
    (length & (length - 1)) !== 0
  ) {
    throw new RangeError(`selection length ${length} must be a power of two in 2 .. ${p.n}`);
  }
}

function digitCount(q: number, base: number): number {
  let count = 0;
  let power = 1;
  while (power < q) {
    count += 1;
    power *= base;
  }
  return count;
}

function inverseMod(value: number, modulus: number): number {
  let oldR = mod(value, modulus);
  let r = modulus;
  let oldS = 1;
  let s = 0;
  while (r !== 0) {
    const quotient = Math.floor(oldR / r);
    [oldR, r] = [r, oldR - quotient * r];
    [oldS, s] = [s, oldS - quotient * s];
  }
  if (oldR !== 1) throw new RangeError(`${value} has no inverse modulo ${modulus}`);
  return mod(oldS, modulus);
}

/** The odd substitution elements used by SealPIR's expansion rounds. */
export function requiredGaloisElements(
  p: PirParams,
  selectionLength: number
): readonly number[] {
  assertPowerOfTwoLength(p, selectionLength);
  const rounds = Math.log2(selectionLength);
  return Array.from({ length: rounds }, (_, i) => p.n / 2 ** i + 1);
}

/** Apply X -> X^element in R_q. `element` must be odd. */
export function applyAutomorphism(
  polynomial: Int32Array,
  element: number,
  q: number
): Int32Array {
  const n = polynomial.length;
  if (!Number.isInteger(element) || element < 1 || element >= 2 * n || element % 2 === 0) {
    throw new RangeError(`automorphism element ${element} must be odd and lie in 1 .. ${2 * n - 1}`);
  }
  const out = new Int32Array(n);
  for (let i = 0; i < n; i += 1) {
    const exponent = (i * element) % (2 * n);
    if (exponent < n) out[exponent] = polynomial[i];
    else out[exponent - n] = mod(-polynomial[i], q);
  }
  return out;
}

function applyAutomorphismSmall(polynomial: Int8Array, element: number): Int8Array {
  const n = polynomial.length;
  const out = new Int8Array(n);
  for (let i = 0; i < n; i += 1) {
    const exponent = (i * element) % (2 * n);
    if (exponent < n) out[exponent] = polynomial[i];
    else out[exponent - n] = -polynomial[i];
  }
  return out;
}

/** Multiply by X^power in R_q, including the X^n = -1 sign. */
export function multiplyPowerOfX(
  polynomial: Int32Array,
  power: number,
  q: number
): Int32Array {
  const n = polynomial.length;
  const shift = mod(power, 2 * n);
  const out = new Int32Array(n);
  for (let i = 0; i < n; i += 1) {
    const exponent = (i + shift) % (2 * n);
    if (exponent < n) out[exponent] = polynomial[i];
    else out[exponent - n] = mod(-polynomial[i], q);
  }
  return out;
}

function shiftCiphertext(p: PirParams, ct: Ciphertext, power: number): Ciphertext {
  return {
    c0: multiplyPowerOfX(ct.c0, power, p.q),
    c1: multiplyPowerOfX(ct.c1, power, p.q),
  };
}

function rawSwitchSample(
  p: PirParams,
  targetSecret: Int8Array,
  targetPower: number,
  sk: SecretKey,
  rng: Rng
): Ciphertext {
  const a = sampleUniform(p, rng);
  const error = sampleError(p, rng);
  const target = new Int32Array(p.n);
  for (let i = 0; i < p.n; i += 1) target[i] = mod(targetSecret[i] * targetPower, p.q);
  const as = mulBySmall(a, sk.s, p.q);
  const liftedError = new Int32Array(p.n);
  for (let i = 0; i < p.n; i += 1) liftedError[i] = mod(error[i], p.q);
  return {
    c0: addPoly(addPoly(target, negPoly(as, p.q), p.q), liftedError, p.q),
    c1: a,
  };
}

/** Generate exactly the Galois keys needed to expand `selectionLength` slots. */
export function generateEvaluationKeys(
  p: PirParams,
  sk: SecretKey,
  selectionLength: number,
  rng: Rng
): EvaluationKeySet {
  const elements = requiredGaloisElements(p, selectionLength);
  const digits = digitCount(p.q, KEY_SWITCH_BASE);
  const keys = elements.map((element) => {
    const substitutedSecret = applyAutomorphismSmall(sk.s, element);
    let power = 1;
    const samples: Ciphertext[] = [];
    for (let j = 0; j < digits; j += 1) {
      samples.push(rawSwitchSample(p, substitutedSecret, power, sk, rng));
      power = mod(power * KEY_SWITCH_BASE, p.q);
    }
    return { element, digits: samples };
  });
  return {
    ringDegree: p.n,
    q: p.q,
    t: p.t,
    base: KEY_SWITCH_BASE,
    digitCount: digits,
    keys,
  };
}

/**
 * Encrypt one block of the compressed query.
 *
 * `index = null` encrypts an all-zero block. That lets a larger teaching
 * database be covered by several fixed-size ciphertext blocks without a
 * plaintext field telling the server which block contains the selected
 * monomial. The server envelope deliberately carries no plaintext index; the
 * choice is encoded only in the ciphertexts.
 */
export function buildCompressedQuery(
  p: PirParams,
  sk: SecretKey,
  index: number | null,
  selectionLength: number,
  rng: Rng
): BuiltCompressedQuery {
  assertPowerOfTwoLength(p, selectionLength);
  if (index !== null) assertIndexInRange(index, selectionLength);
  const inverseScale = inverseMod(selectionLength, p.t);
  const monomial = zeroPoly(p.n);
  if (index !== null) monomial[index] = inverseScale;
  return {
    ciphertext: encrypt(p, sk, monomial, rng),
    selectionLength,
    inverseScale,
  };
}

function assertKeySet(p: PirParams, keySet: EvaluationKeySet): void {
  if (
    keySet.ringDegree !== p.n ||
    keySet.q !== p.q ||
    keySet.t !== p.t ||
    keySet.base !== KEY_SWITCH_BASE ||
    keySet.digitCount !== digitCount(p.q, KEY_SWITCH_BASE)
  ) {
    throw new RangeError('evaluation keys do not match the active BFV parameters');
  }
}

function decomposePolynomial(
  polynomial: Int32Array,
  base: number,
  digits: number
): readonly Int32Array[] {
  const out = Array.from({ length: digits }, () => new Int32Array(polynomial.length));
  for (let i = 0; i < polynomial.length; i += 1) {
    let value = polynomial[i];
    for (let j = 0; j < digits; j += 1) {
      out[j][i] = value % base;
      value = Math.floor(value / base);
    }
    if (value !== 0) throw new RangeError('key-switch decomposition was too short');
  }
  return out;
}

function preparedSwitchKey(
  keySet: EvaluationKeySet,
  key: GaloisEvaluationKey
): readonly PreparedSwitchDigit[] {
  let byElement = preparedCache.get(keySet);
  if (!byElement) {
    byElement = new Map();
    preparedCache.set(keySet, byElement);
  }
  const existing = byElement.get(key.element);
  if (existing) return existing;
  const prepared = key.digits.map((digit) => ({
    c0: preparePolynomial(digit.c0, keySet.ringDegree),
    c1: preparePolynomial(digit.c1, keySet.ringDegree),
  }));
  byElement.set(key.element, prepared);
  return prepared;
}

function keySwitch(
  p: PirParams,
  substituted: Ciphertext,
  keySet: EvaluationKeySet,
  key: GaloisEvaluationKey
): Ciphertext {
  if (key.digits.length !== keySet.digitCount) {
    throw new RangeError(`evaluation key ${key.element} has the wrong digit count`);
  }
  const decomposition = decomposePolynomial(substituted.c1, keySet.base, keySet.digitCount);
  const preparedKey = preparedSwitchKey(keySet, key);
  const c0Products = productAccumulator(p.n);
  const c1Products = productAccumulator(p.n);
  for (let j = 0; j < decomposition.length; j += 1) {
    const preparedDigit = preparePolynomial(decomposition[j], p.n);
    accumulateProduct(c0Products, preparedDigit, preparedKey[j].c0);
    accumulateProduct(c1Products, preparedDigit, preparedKey[j].c1);
  }

  // Each negacyclic output coefficient sums exactly n products per digit.
  // Key coefficients are canonical in [0,q), digits in [0,B), and all digit
  // products are accumulated before CRT reconstruction.
  const bound = p.n * (p.q - 1) * (keySet.base - 1) * keySet.digitCount;
  const switched0 = finishNegacyclic(c0Products, p.q, bound);
  const switched1 = finishNegacyclic(c1Products, p.q, bound);
  return { c0: addPoly(substituted.c0, switched0, p.q), c1: switched1 };
}

/** Apply one Galois automorphism and key-switch its ciphertext back under s. */
export function applyGalois(
  p: PirParams,
  ct: Ciphertext,
  element: number,
  keySet: EvaluationKeySet
): Ciphertext {
  assertKeySet(p, keySet);
  const key = keySet.keys.find((candidate) => candidate.element === element);
  if (!key) throw new RangeError(`missing evaluation key for Galois element ${element}`);
  const substituted = {
    c0: applyAutomorphism(ct.c0, element, p.q),
    c1: applyAutomorphism(ct.c1, element, p.q),
  };
  return keySwitch(p, substituted, keySet, key);
}

/** Expand one compressed monomial query into the encrypted one-hot vector. */
export function expandCompressedQuery(
  p: PirParams,
  query: CompressedQuery,
  keySet: EvaluationKeySet
): ExpansionResult {
  assertPowerOfTwoLength(p, query.selectionLength);
  assertKeySet(p, keySet);
  const elements = requiredGaloisElements(p, query.selectionLength);
  for (const element of elements) {
    if (!keySet.keys.some((key) => key.element === element)) {
      throw new RangeError(`missing evaluation key for Galois element ${element}`);
    }
  }

  let current: Ciphertext[] = [query.ciphertext];
  const rounds: ExpansionRound[] = [];
  for (let round = 0; round < elements.length; round += 1) {
    const element = elements[round];
    const next = new Array<Ciphertext>(current.length * 2);
    const indexRaw = 2 * p.n - 2 ** round;
    const indexRotated = (indexRaw * element) % (2 * p.n);
    for (let a = 0; a < current.length; a += 1) {
      const rotated = applyGalois(p, current[a], element, keySet);
      next[a] = addCiphertext(p, current[a], rotated);
      next[a + current.length] = addCiphertext(
        p,
        shiftCiphertext(p, current[a], indexRaw),
        shiftCiphertext(p, rotated, indexRotated)
      );
    }
    rounds.push({
      round: round + 1,
      galoisElement: element,
      inputs: current.length,
      outputs: next.length,
      automorphisms: current.length,
      keySwitches: current.length,
      keySwitchConvolutions: current.length * keySet.digitCount * 2,
      ciphertextAdds: current.length * 2,
      monomialShifts: current.length * 2,
    });
    current = next;
  }

  const totals = rounds.reduce<ExpansionTotals>(
    (sum, round) => ({
      rounds: sum.rounds + 1,
      automorphisms: sum.automorphisms + round.automorphisms,
      keySwitches: sum.keySwitches + round.keySwitches,
      keySwitchConvolutions: sum.keySwitchConvolutions + round.keySwitchConvolutions,
      ciphertextAdds: sum.ciphertextAdds + round.ciphertextAdds,
      monomialShifts: sum.monomialShifts + round.monomialShifts,
    }),
    {
      rounds: 0,
      automorphisms: 0,
      keySwitches: 0,
      keySwitchConvolutions: 0,
      ciphertextAdds: 0,
      monomialShifts: 0,
    }
  );
  return { ciphertexts: current, rounds, totals };
}

const KEY_MAGIC = [0x53, 0x4f, 0x45, 0x4b] as const; // "SOEK"
const KEY_VERSION = 1;
const KEY_HEADER_BYTES = 16;

function assertCanonicalSample(p: PirParams, sample: Ciphertext): void {
  if (sample.c0.length !== p.n || sample.c1.length !== p.n) {
    throw new RangeError('evaluation-key ciphertext has the wrong ring dimension');
  }
  for (const component of [sample.c0, sample.c1]) {
    for (let i = 0; i < component.length; i += 1) {
      if (!Number.isInteger(component[i]) || component[i] < 0 || component[i] >= p.q) {
        throw new RangeError(`evaluation-key coefficient ${component[i]} is not canonical modulo q`);
      }
    }
  }
}

function assertKeyStructure(p: PirParams, keySet: EvaluationKeySet): void {
  const seen = new Set<number>();
  for (const key of keySet.keys) {
    if (key.element % 2 === 0 || key.element < 1 || key.element >= 2 * p.n) {
      throw new RangeError(`invalid Galois element ${key.element}`);
    }
    if (seen.has(key.element)) throw new RangeError(`duplicate Galois element ${key.element}`);
    seen.add(key.element);
    if (key.digits.length !== keySet.digitCount) {
      throw new RangeError(`evaluation key ${key.element} has the wrong digit count`);
    }
    for (const sample of key.digits) assertCanonicalSample(p, sample);
  }
}

/** Serialize the reusable evaluation-key setup actually sent to the server. */
export function serializeEvaluationKeys(p: PirParams, keySet: EvaluationKeySet): Uint8Array {
  assertKeySet(p, keySet);
  assertKeyStructure(p, keySet);
  if (keySet.keys.length > 255 || keySet.digitCount > 255 || keySet.base > 255) {
    throw new RangeError('evaluation-key dimensions exceed the teaching wire format');
  }
  const perCiphertext = ciphertextBytes(p);
  const perKey = 2 + keySet.digitCount * perCiphertext;
  const out = new Uint8Array(KEY_HEADER_BYTES + keySet.keys.length * perKey);
  out.set(KEY_MAGIC, 0);
  const view = new DataView(out.buffer);
  view.setUint8(4, KEY_VERSION);
  view.setUint8(5, keySet.base);
  view.setUint8(6, keySet.digitCount);
  view.setUint8(7, keySet.keys.length);
  view.setUint16(8, keySet.ringDegree, true);
  view.setUint16(10, keySet.t, true);
  view.setUint32(12, keySet.q, true);
  let offset = KEY_HEADER_BYTES;
  for (const key of keySet.keys) {
    view.setUint16(offset, key.element, true);
    offset += 2;
    for (const sample of key.digits) {
      out.set(serializeCiphertext(p, sample), offset);
      offset += perCiphertext;
    }
  }
  return out;
}

/** Deserialize and structurally validate the evaluation-key setup. */
export function deserializeEvaluationKeys(
  p: PirParams,
  bytes: Uint8Array
): EvaluationKeySet {
  if (bytes.length < KEY_HEADER_BYTES) throw new RangeError('evaluation-key payload is truncated');
  for (let i = 0; i < KEY_MAGIC.length; i += 1) {
    if (bytes[i] !== KEY_MAGIC[i]) throw new RangeError('evaluation-key payload has the wrong magic');
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const version = view.getUint8(4);
  const base = view.getUint8(5);
  const digits = view.getUint8(6);
  const keyCount = view.getUint8(7);
  const ringDegree = view.getUint16(8, true);
  const t = view.getUint16(10, true);
  const q = view.getUint32(12, true);
  if (version !== KEY_VERSION) throw new RangeError(`unsupported evaluation-key version ${version}`);
  const candidate = {
    ringDegree,
    q,
    t,
    base,
    digitCount: digits,
    keys: [] as GaloisEvaluationKey[],
  };
  assertKeySet(p, candidate);
  const perCiphertext = ciphertextBytes(p);
  const expected = KEY_HEADER_BYTES + keyCount * (2 + digits * perCiphertext);
  if (bytes.length !== expected) {
    throw new RangeError(`evaluation-key payload has ${bytes.length} bytes; expected ${expected}`);
  }
  let offset = KEY_HEADER_BYTES;
  for (let k = 0; k < keyCount; k += 1) {
    const element = view.getUint16(offset, true);
    offset += 2;
    const samples: Ciphertext[] = [];
    for (let j = 0; j < digits; j += 1) {
      samples.push(deserializeCiphertext(p, bytes.subarray(offset, offset + perCiphertext)));
      offset += perCiphertext;
    }
    candidate.keys.push({ element, digits: samples });
  }
  assertKeyStructure(p, candidate);
  return candidate;
}
