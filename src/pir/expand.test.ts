import { describe, expect, it } from 'vitest';
import { addCiphertext, decrypt, decryptRaw, keyGen, noiseBudgetBits } from './bfv';
import {
  applyAutomorphism,
  buildCompressedQuery,
  deserializeEvaluationKeys,
  EXPANSION_MODULUS,
  EXPANSION_RECORD_BYTES,
  EXPANSION_SELECTION_LENGTH,
  expandCompressedQuery,
  generateEvaluationKeys,
  KEY_SWITCH_BASE,
  multiplyPowerOfX,
  requiredGaloisElements,
  serializeEvaluationKeys,
  type EvaluationKeySet,
} from './expand';
import { DEFAULT_RECORD_BYTES, defaultParams, makeParams } from './params';
import { buildQuery, decodeAnswer, serverAnswer } from './pir';
import { bytesToCoefficients, buildRecord, shelfToPlaintexts } from './records';
import { Rng } from './rng';
import {
  ciphertextBytes,
  deserializeCiphertext,
  serializeCiphertext,
  serializeQuery,
} from './serialize';
import { entryText, shelfEntries } from '../data/catalog';
import { centerLift, mod } from './ring';
import { assessSecurity } from './security';

const P = defaultParams();

async function buildShelf(size: number, recordBytes: number): Promise<Uint8Array[]> {
  return Promise.all(shelfEntries(size).map((entry) => buildRecord(entryText(entry), recordBytes)));
}

function cloneKeySet(keySet: EvaluationKeySet): EvaluationKeySet {
  return {
    ...keySet,
    keys: keySet.keys.map((key) => ({
      element: key.element,
      digits: key.digits.map((ct) => ({ c0: ct.c0.slice(), c1: ct.c1.slice() })),
    })),
  };
}

function isPrime(value: number): boolean {
  if (value < 2 || value % 2 === 0) return value === 2;
  for (let divisor = 3; divisor * divisor <= value; divisor += 2) {
    if (value % divisor === 0) return false;
  }
  return true;
}

describe('SealPIR-style compressed query expansion', () => {
  it('keeps the expansion modulus at the published 27-bit HES bit ceiling', () => {
    expect(isPrime(EXPANSION_MODULUS)).toBe(true);
    for (let candidate = EXPANSION_MODULUS + 2; candidate < 2 ** 27; candidate += 2) {
      expect(isPrime(candidate), `${candidate} must not be a larger prime below 2^27`).toBe(false);
    }
    const assessment = assessSecurity(makeParams(EXPANSION_MODULUS, EXPANSION_RECORD_BYTES));
    expect(assessment.logQ).toBe(27);
    expect(assessment.atOrBelow128BitCeiling).toBe(true);
    expect(assessment.referenceLevel).toBe(128);
    expect(assessment.ceiling128).toBe(27);
    expect(assessment.summary).toContain('not a transferred security estimate');
  });

  it('uses the published odd substitution schedule', () => {
    expect(requiredGaloisElements(P, 8)).toEqual([1025, 513, 257]);
    expect(requiredGaloisElements(P, 64)).toEqual([1025, 513, 257, 129, 65, 33]);
  });

  it('applies ring automorphisms and monomial shifts with the negacyclic sign', () => {
    const polynomial = new Int32Array(P.n);
    polynomial[1] = 5;
    polynomial[P.n - 1] = 7;
    const substituted = applyAutomorphism(polynomial, P.n + 1, P.q);
    // X -> X^(n+1): X maps to -X, while X^(n-1) maps to -X^(n-1).
    expect(substituted[1]).toBe(P.q - 5);
    expect(substituted[P.n - 1]).toBe(P.q - 7);

    const top = new Int32Array(P.n);
    top[P.n - 1] = 9;
    const shifted = multiplyPowerOfX(top, 1, P.q);
    expect(shifted[0]).toBe(P.q - 9);
  });

  it('serializes reusable evaluation keys and expands all 16 positions to real one-hot vectors', () => {
    const rng = Rng.fromSeed('expand-one-hot');
    const p = makeParams(EXPANSION_MODULUS, EXPANSION_RECORD_BYTES);
    const sk = keyGen(p, rng);
    const length = EXPANSION_SELECTION_LENGTH;
    const keySet = generateEvaluationKeys(p, sk, length, rng);
    const wire = serializeEvaluationKeys(p, keySet);
    const roundTripped = deserializeEvaluationKeys(p, wire);

    expect(keySet.base).toBe(KEY_SWITCH_BASE);
    for (let index = 0; index < length; index += 1) {
      const query = buildCompressedQuery(p, sk, index, length, rng);
      const expanded = expandCompressedQuery(p, query, roundTripped);
      expect(wire.length).toBeGreaterThan(serializeCiphertext(p, query.ciphertext).length);
      expect(expanded.ciphertexts).toHaveLength(length);
      for (let i = 0; i < length; i += 1) {
        const plaintext = decrypt(p, sk, expanded.ciphertexts[i]);
        expect(plaintext[0], `index ${index}, selector ${i}`).toBe(i === index ? 1 : 0);
        expect(Array.from(plaintext.subarray(1)).every((value) => value === 0)).toBe(true);
      }
      expect(expanded.totals).toEqual({
        rounds: 4,
        automorphisms: 15,
        keySwitches: 15,
        keySwitchConvolutions: 15 * keySet.digitCount * 2,
        ciphertextAdds: 30,
        monomialShifts: 30,
      });
    }
  });

  it('each switch hint is a noisy raw RLWE encryption of B^j · sigma(s)', () => {
    const rng = Rng.fromSeed('expand-key-equation');
    const sk = keyGen(P, rng);
    const keySet = generateEvaluationKeys(P, sk, 4, rng);
    const secret = Int32Array.from(sk.s, (coefficient) => mod(coefficient, P.q));
    for (const key of keySet.keys) {
      const substituted = applyAutomorphism(secret, key.element, P.q);
      let power = 1;
      for (const sample of key.digits) {
        const raw = decryptRaw(P, sk, sample);
        for (let i = 0; i < P.n; i += 1) {
          const target = mod(power * substituted[i], P.q);
          expect(Math.abs(centerLift(raw[i] - target, P.q))).toBeLessThanOrEqual(P.eta);
        }
        power = mod(power * keySet.base, P.q);
      }
    }
  });

  it('retrieves one full-catalog record without sending its block or index in plaintext', async () => {
    const rng = Rng.fromSeed('expand-retrieve');
    const recordBytes = EXPANSION_RECORD_BYTES;
    expect(recordBytes).toBe(DEFAULT_RECORD_BYTES);
    const p = makeParams(EXPANSION_MODULUS, recordBytes);
    const sk = keyGen(p, rng);
    const shelf = await buildShelf(64, recordBytes);
    const plaintexts = shelfToPlaintexts(shelf, p);
    const index = 41;

    const directQuery = buildQuery(p, sk, index, shelf.length, rng);
    const directAnswer = serverAnswer(p, plaintexts, directQuery.ciphertexts);

    const keys = deserializeEvaluationKeys(
      p,
      serializeEvaluationKeys(
        p,
        generateEvaluationKeys(p, sk, EXPANSION_SELECTION_LENGTH, rng)
      )
    );
    const selectedBlock = Math.floor(index / EXPANSION_SELECTION_LENGTH);
    const localIndex = index % EXPANSION_SELECTION_LENGTH;
    const blockCount = shelf.length / EXPANSION_SELECTION_LENGTH;
    const compressedQueries = Array.from({ length: blockCount }, (_, block) =>
      buildCompressedQuery(
        p,
        sk,
        block === selectedBlock ? localIndex : null,
        EXPANSION_SELECTION_LENGTH,
        rng
      )
    );
    for (const query of compressedQueries) {
      expect(Object.prototype.hasOwnProperty.call(query, 'index')).toBe(false);
    }
    const expandedBlocks = compressedQueries.map((query) => {
      const wire = serializeCiphertext(p, query.ciphertext);
      const serverQuery = {
        ciphertext: deserializeCiphertext(p, wire),
        selectionLength: query.selectionLength,
      };
      expect(Object.keys(serverQuery).sort()).toEqual(['ciphertext', 'selectionLength']);
      return expandCompressedQuery(p, serverQuery, keys).ciphertexts;
    });
    expect(expandedBlocks.flat()).toHaveLength(shelf.length);
    const compressedAnswers = expandedBlocks.map((selectors, block) =>
      serverAnswer(
        p,
        plaintexts.slice(
          block * EXPANSION_SELECTION_LENGTH,
          (block + 1) * EXPANSION_SELECTION_LENGTH
        ),
        selectors
      )
    );
    const compressedAnswer = compressedAnswers[selectedBlock];
    const truth = bytesToCoefficients(shelf[index], p.n);
    const direct = await decodeAnswer(p, sk, directAnswer, recordBytes, truth);
    const compressed = await decodeAnswer(p, sk, compressedAnswer, recordBytes, truth);
    const combinedAnswer = compressedAnswers.reduce((sum, answer) =>
      addCiphertext(p, sum, answer)
    );
    const combined = await decodeAnswer(p, sk, combinedAnswer, recordBytes, truth);

    expect(direct.failure).toBeNull();
    expect(compressed.failure).toBeNull();
    expect(combined.failure?.code).toBe('NOISE_BUDGET_EXHAUSTED');
    expect(noiseBudgetBits(p, sk, combinedAnswer, truth)).toBeLessThanOrEqual(0);
    expect(Array.from(compressed.bytes)).toEqual(Array.from(direct.bytes));
    expect(Array.from(compressed.bytes)).toEqual(Array.from(shelf[index]));
    const compressedBudget = noiseBudgetBits(p, sk, compressedAnswer, truth);
    const directBudget = noiseBudgetBits(p, sk, directAnswer, truth);
    expect(compressedBudget).toBeGreaterThan(0);
    expect(compressedBudget).toBeLessThan(directBudget);
    for (let block = 0; block < compressedAnswers.length; block += 1) {
      if (block === selectedBlock) continue;
      expect(Array.from(decrypt(p, sk, compressedAnswers[block]))).toEqual(
        Array(p.n).fill(0)
      );
    }

    // The costs come from buffers and executed counters, not paper figures.
    expect(serializeQuery(p, directQuery.ciphertexts).length).toBe(
      shelf.length * ciphertextBytes(p)
    );
    expect(
      compressedQueries.reduce(
        (bytes, query) => bytes + serializeCiphertext(p, query.ciphertext).length,
        0
      )
    ).toBe(blockCount * ciphertextBytes(p));
    expect(
      compressedAnswers.reduce(
        (bytes, answer) => bytes + serializeCiphertext(p, answer).length,
        0
      )
    ).toBe(blockCount * serializeCiphertext(p, directAnswer).length);
    expect(serializeCiphertext(p, compressedAnswer).length).toBe(
      serializeCiphertext(p, directAnswer).length
    );
  });

  it(
    'shows that summing the four block responses has a sample-dependent, inadequate margin',
    async () => {
      const p = makeParams(EXPANSION_MODULUS, EXPANSION_RECORD_BYTES);
      const shelf = await buildShelf(64, EXPANSION_RECORD_BYTES);
      const plaintexts = shelfToPlaintexts(shelf, p);
      const index = 41;
      const selectedBlock = Math.floor(index / EXPANSION_SELECTION_LENGTH);
      const localIndex = index % EXPANSION_SELECTION_LENGTH;
      const truth = bytesToCoefficients(shelf[index], p.n);
      let exhausted = 0;
      const survivingBudgets: number[] = [];

      for (let seed = 0; seed < 8; seed += 1) {
        const rng = Rng.fromSeed(`audit-combine-${seed}`);
        const sk = keyGen(p, rng);
        const keys = generateEvaluationKeys(p, sk, EXPANSION_SELECTION_LENGTH, rng);
        const queries = Array.from({ length: 4 }, (_, block) =>
          buildCompressedQuery(
            p,
            sk,
            block === selectedBlock ? localIndex : null,
            EXPANSION_SELECTION_LENGTH,
            rng
          )
        );
        const answers = queries.map((query, block) => {
          const selectors = expandCompressedQuery(p, query, keys).ciphertexts;
          return serverAnswer(
            p,
            plaintexts.slice(
              block * EXPANSION_SELECTION_LENGTH,
              (block + 1) * EXPANSION_SELECTION_LENGTH
            ),
            selectors
          );
        });

        const selected = await decodeAnswer(
          p,
          sk,
          answers[selectedBlock],
          EXPANSION_RECORD_BYTES,
          truth
        );
        expect(selected.failure, `selected block failed for deterministic seed ${seed}`).toBeNull();
        expect(Array.from(selected.bytes)).toEqual(Array.from(shelf[index]));

        const combined = answers.reduce((sum, answer) => addCiphertext(p, sum, answer));
        const decoded = await decodeAnswer(
          p,
          sk,
          combined,
          EXPANSION_RECORD_BYTES,
          truth
        );
        const budget = noiseBudgetBits(p, sk, combined, truth);
        if (decoded.failure) {
          expect(decoded.failure.code).toBe('NOISE_BUDGET_EXHAUSTED');
          expect(budget).toBeLessThanOrEqual(0);
          exhausted += 1;
        } else {
          expect(Array.from(decoded.bytes)).toEqual(Array.from(shelf[index]));
          expect(budget).toBeGreaterThan(0);
          survivingBudgets.push(budget);
        }
      }

      expect(exhausted).toBeGreaterThan(0);
      expect(survivingBudgets.length).toBeGreaterThan(0);
      expect(Math.max(...survivingBudgets)).toBeLessThan(0.5);
    },
    60_000
  );

  it('rejects unsupported dimensions, missing keys, and truncated setup bytes', () => {
    const rng = Rng.fromSeed('expand-refusals');
    const sk = keyGen(P, rng);
    expect(() => buildCompressedQuery(P, sk, 0, 6, rng)).toThrow(/power of two/);
    const keys = generateEvaluationKeys(P, sk, 8, rng);
    const query = buildCompressedQuery(P, sk, 3, 8, rng);
    const missing: EvaluationKeySet = { ...keys, keys: keys.keys.slice(0, -1) };
    expect(() => expandCompressedQuery(P, query, missing)).toThrow(/missing evaluation key/);

    const wire = serializeEvaluationKeys(P, keys);
    expect(() => deserializeEvaluationKeys(P, wire.subarray(0, wire.length - 1))).toThrow(
      /expected/
    );
    const wrong = makeParams(1_048_573, 512);
    expect(() => deserializeEvaluationKeys(wrong, wire)).toThrow(/do not match/);

    const noncanonical = cloneKeySet(keys);
    noncanonical.keys[0].digits[0].c0[0] = P.q;
    expect(() => serializeEvaluationKeys(P, noncanonical)).toThrow(/not canonical/);
  });

  it('a canonical corrupted evaluation key changes outputs rather than passing correctness', () => {
    const rng = Rng.fromSeed('expand-corrupt-key');
    const sk = keyGen(P, rng);
    const keys = generateEvaluationKeys(P, sk, 4, rng);
    const corrupted = cloneKeySet(keys);
    const first = corrupted.keys[0].digits[0].c0;
    first[0] = (first[0] + Math.floor(P.q / 3)) % P.q;
    const query = buildCompressedQuery(P, sk, 2, 4, rng);
    const expanded = expandCompressedQuery(P, query, corrupted);
    const decoded = expanded.ciphertexts.map((ct) => Array.from(decrypt(P, sk, ct)));
    const expected = Array.from({ length: 4 }, (_, i) => {
      const row = Array(P.n).fill(0);
      row[0] = i === 2 ? 1 : 0;
      return row;
    });
    expect(decoded).not.toEqual(expected);
  });
});
