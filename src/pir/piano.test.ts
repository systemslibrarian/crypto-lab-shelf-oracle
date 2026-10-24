import { describe, expect, it, vi } from 'vitest';
import { chachaBlock } from './chacha20';
import {
  abandonPianoRequest,
  auditPianoRequest,
  auditPianoState,
  beginPianoQuery,
  beginPianoQueryForTest,
  derivePianoPrimaryHintCount,
  deserializePianoState,
  fingerprintPianoDatabase,
  finishPianoQuery,
  makePianoStateLossRequestForTest,
  parsePianoQuery,
  parsePianoResponse,
  pianoAvailabilityBounds,
  PIANO_BACKUPS_PER_CHUNK,
  PIANO_BASE_STATE_BYTES,
  PIANO_CACHE_ENTRY_BYTES,
  PIANO_CHUNK_COUNT,
  PIANO_CHUNK_SIZE,
  PIANO_DATABASE_RECORDS,
  PIANO_FAILURE_BITS,
  PIANO_MAX_NORMAL_CACHE_BYTES,
  PIANO_PRIMARY_HINTS,
  PIANO_QUERY_BYTES,
  PIANO_QUERY_WINDOW,
  PIANO_RECORD_BYTES,
  PIANO_RESPONSE_BYTES,
  PIANO_SETUP_COSTS,
  pianoCostForQueries,
  pianoServerAnswer,
  pianoStateAnchor,
  pianoStateMetrics,
  preprocessPiano,
  preprocessPianoForTest,
  serializePianoQuery,
  serializePianoRequest,
  serializePianoState,
  verifyPianoDatabaseCurrent,
  type PianoClientState,
  type PianoTestEntropy,
} from './piano';
import { Rng } from './rng';

class SeededEntropy implements PianoTestEntropy {
  private readonly rng: Rng;

  constructor(seed: string) {
    this.rng = Rng.fromSeed(seed);
  }

  fill(out: Uint8Array): void {
    this.rng.fill(out);
  }
}

class WordEntropy implements PianoTestEntropy {
  private offset = 0;

  constructor(private readonly words: readonly number[]) {}

  fill(out: Uint8Array): void {
    out.fill(0);
    if (out.length === 4) {
      new DataView(out.buffer, out.byteOffset, out.byteLength).setUint32(
        0,
        this.words[this.offset] ?? 0,
        true
      );
      this.offset += 1;
    }
  }
}

function database(version = 0): Uint8Array[] {
  return Array.from({ length: PIANO_DATABASE_RECORDS }, (_, record) =>
    Uint8Array.from(
      { length: PIANO_RECORD_BYTES },
      (_, byte) => (version * 53 + record * 17 + byte * 29 + (byte >> 3)) & 0xff
    )
  );
}

function independentXor(records: readonly Uint8Array[], indices: readonly number[]): Uint8Array {
  const out = new Uint8Array(PIANO_RECORD_BYTES);
  for (const index of indices) {
    for (let byte = 0; byte < PIANO_RECORD_BYTES; byte += 1) {
      out[byte] ^= records[index][byte];
    }
  }
  return out;
}

function independentPrfIndex(
  key: Uint8Array,
  tag: number,
  chunk: number
): number {
  // Re-derived here rather than asking the Piano module which record belongs to
  // a set.  ChaCha20 itself is separately anchored to RFC 8439 KATs.
  const nonce = new Uint8Array(12);
  nonce.set([0x50, 0x4e, 0x4f, 0x31]);
  const view = new DataView(nonce.buffer);
  view.setUint32(4, tag, true);
  view.setUint32(8, chunk, true);
  const offset = chachaBlock(key, 0, nonce)[0] & 7;
  return chunk * PIANO_CHUNK_SIZE + offset;
}

function independentHintIndices(
  key: Uint8Array,
  hint: { readonly tag: number; readonly programmedTarget: number | null }
): number[] {
  return Array.from({ length: PIANO_CHUNK_COUNT }, (_, chunk) => {
    if (
      hint.programmedTarget !== null &&
      Math.floor(hint.programmedTarget / PIANO_CHUNK_SIZE) === chunk
    ) {
      return hint.programmedTarget;
    }
    return independentPrfIndex(key, hint.tag, chunk);
  });
}

function expectBytes(actual: Uint8Array, expected: Uint8Array): void {
  expect(Array.from(actual)).toEqual(Array.from(expected));
}

function xorThreeIndependent(a: Uint8Array, b: Uint8Array, c: Uint8Array): Uint8Array {
  return Uint8Array.from(a, (value, index) => value ^ b[index] ^ c[index]);
}

function withSyntheticSetupMiss(
  state: PianoClientState,
  target: number,
  record: Uint8Array
): PianoClientState {
  const encoded = serializePianoState(state);
  expect(encoded[101]).toBe(0);
  const extended = new Uint8Array(encoded.length + PIANO_CACHE_ENTRY_BYTES);
  extended.set(encoded);
  extended[101] = 1;
  extended[encoded.length] = target;
  extended.set(record, encoded.length + 1);
  return deserializePianoState(extended);
}

function answerAndFinish(
  state: PianoClientState,
  records: readonly Uint8Array[],
  target: number,
  entropy: PianoTestEntropy
) {
  const request = beginPianoQueryForTest(state, target, entropy);
  const wire = serializePianoRequest(request);
  const response = pianoServerAnswer(records, wire);
  return { request, wire, response, result: finishPianoQuery(state, request, response) };
}

describe('bounded Piano preprocessing', () => {
  it('keeps live setup and cover traffic on the WebCrypto entropy boundary', async () => {
    const getRandomValues = vi.spyOn(globalThis.crypto, 'getRandomValues');
    try {
      const records = database();
      const state = await preprocessPiano(records);
      const setupCalls = getRandomValues.mock.calls.length;
      expect(setupCalls).toBeGreaterThanOrEqual(66); // key, setup id, 64 replacements

      // An invalid local index still emits eight independently sampled cover
      // coordinates.  The live function has no seed/injection argument.
      const request = beginPianoQuery(state, -1);
      expect(getRandomValues.mock.calls.length).toBeGreaterThan(setupCalls);
      const wire = serializePianoRequest(request);
      expect(parsePianoQuery(wire)).toHaveLength(PIANO_QUERY_BYTES);
      finishPianoQuery(state, request, pianoServerAnswer(records, wire));
    } finally {
      getRandomValues.mockRestore();
    }
  });

  it('derives the fixed parameters and finite availability bounds without overstating them', () => {
    expect(PIANO_DATABASE_RECORDS).toBe(64);
    expect(PIANO_RECORD_BYTES).toBe(512);
    expect(PIANO_CHUNK_COUNT).toBe(8);
    expect(PIANO_CHUNK_SIZE).toBe(8);
    expect(PIANO_QUERY_WINDOW).toBe(33);
    expect(PIANO_PRIMARY_HINTS).toBe(256);
    expect(
      derivePianoPrimaryHintCount(
        PIANO_FAILURE_BITS,
        PIANO_QUERY_WINDOW,
        PIANO_CHUNK_SIZE
      )
    ).toBe(256);

    const bounds = pianoAvailabilityBounds();
    const fixedTarget = (7 / 8) ** 256;
    const session = 33 * (7 / 8) ** 249;
    expect(bounds.setupFixedTargetMiss).toBe(fixedTarget);
    expect(bounds.setupFixedTargetMissLog2).toBeCloseTo(Math.log2(fixedTarget), 12);
    expect(bounds.minimumUniformHintsPerTarget).toBe(249);
    expect(bounds.sessionPrimaryHintMissUpperBound / session).toBeCloseTo(1, 14);
    expect(bounds.sessionPrimaryHintMissUpperBound).toBeCloseTo(
      1.1981719339498246e-13,
      25
    );
    expect(bounds.sessionPrimaryHintMissLog2).toBeCloseTo(Math.log2(session), 12);
    expect(bounds.scope).toContain('Primary-hint availability only');
    expect(bounds.scope).toContain('not an end-to-end security');
  });

  it('streams real records into independently checkable primary and punctured backup parities', async () => {
    const records = database();
    const state = await preprocessPianoForTest(records, new SeededEntropy('piano-parities'));
    const audit = auditPianoState(state);

    expect(audit.primaryHints).toHaveLength(PIANO_PRIMARY_HINTS);
    expect(audit.backupHints).toHaveLength(PIANO_CHUNK_COUNT);
    expect(audit.setupMisses.size).toBe(0);
    for (const hint of audit.primaryHints) {
      const indices = independentHintIndices(audit.prfKey, hint);
      expectBytes(hint.parity, independentXor(records, indices));
    }
    for (let punctured = 0; punctured < PIANO_CHUNK_COUNT; punctured += 1) {
      expect(audit.backupHints[punctured]).toHaveLength(PIANO_BACKUPS_PER_CHUNK);
      for (const hint of audit.backupHints[punctured]) {
        const indices = Array.from({ length: PIANO_CHUNK_COUNT }, (_, chunk) => chunk)
          .filter((chunk) => chunk !== punctured)
          .map((chunk) => independentPrfIndex(audit.prfKey, hint.tag, chunk));
        expectBytes(hint.parityAfterPuncture, independentXor(records, indices));
      }
    }
    for (let chunk = 0; chunk < PIANO_CHUNK_COUNT; chunk += 1) {
      for (const replacement of audit.replacements[chunk]) {
        expect(Math.floor(replacement.index / PIANO_CHUNK_SIZE)).toBe(chunk);
        expectBytes(replacement.value, records[replacement.index]);
      }
    }
  });

  it('keeps independently sampled replacement collisions instead of deduplicating them', async () => {
    const records = database();
    const state = await preprocessPianoForTest(records, new SeededEntropy('piano-collisions'));
    const before = auditPianoState(state);
    const chunk = before.replacements.findIndex(
      (group) => new Set(group.map((replacement) => replacement.index)).size < group.length
    );
    expect(chunk).toBeGreaterThanOrEqual(0);
    const replacements = before.replacements[chunk].map((replacement) => replacement.index);
    let repeatedAt = -1;
    for (let i = 1; i < replacements.length; i += 1) {
      if (replacements.slice(0, i).includes(replacements[i])) {
        repeatedAt = i;
        break;
      }
    }
    expect(repeatedAt).toBeGreaterThan(0);

    const queryEntropy = new SeededEntropy('piano-collision-queries');
    const seenReplacementIndices: number[] = [];
    for (let slot = 0; slot <= repeatedAt; slot += 1) {
      const target = chunk * PIANO_CHUNK_SIZE + slot;
      const run = answerAndFinish(state, records, target, queryEntropy);
      expect(run.result.ok).toBe(true);
      expect(run.request.replacementIndex).toBe(replacements[slot]);
      seenReplacementIndices.push(run.request.replacementIndex as number);
      if (run.result.ok) expectBytes(run.result.record, records[target]);
    }
    expect(new Set(seenReplacementIndices).size).toBeLessThan(seenReplacementIndices.length);
  });
});

describe('canonical eight-index wire and server', () => {
  it('accepts exactly one byte/index per chunk and returns one real XOR parity', () => {
    const records = database();
    const indices = Uint8Array.from([3, 9, 18, 31, 32, 45, 54, 63]);
    const wire = serializePianoQuery(indices);
    expect(wire).toHaveLength(PIANO_QUERY_BYTES);
    expectBytes(parsePianoQuery(wire), indices);
    const response = pianoServerAnswer(records, wire);
    expect(response).toHaveLength(PIANO_RESPONSE_BYTES);
    expectBytes(response, independentXor(records, [...indices]));
    expectBytes(parsePianoResponse(response), response);
  });

  it('rejects truncated, extended, reordered and noncanonical query encodings', () => {
    const canonical = Uint8Array.from([0, 8, 16, 24, 32, 40, 48, 56]);
    expect(() => parsePianoQuery(canonical.subarray(0, 7))).toThrow(/exactly 8 bytes/);
    expect(() => parsePianoQuery(Uint8Array.from([...canonical, 0]))).toThrow(/exactly 8 bytes/);
    const reordered = canonical.slice();
    [reordered[0], reordered[1]] = [reordered[1], reordered[0]];
    expect(() => parsePianoQuery(reordered)).toThrow(/chunk 0/);
    expect(() => serializePianoQuery([0, 8, 16, 24, 32, 40, 48, 256])).toThrow(
      /canonical byte/
    );
    expect(() => parsePianoResponse(new Uint8Array(511))).toThrow(/exactly 512 bytes/);
  });
});

describe('online recovery, refresh and bounded state', () => {
  it('preserves the valid r == x case and refreshes with the exact backup equation', async () => {
    const records = database();
    const state = await preprocessPianoForTest(records, new SeededEntropy('piano-r-equals-x'));
    const before = auditPianoState(state);

    let target = -1;
    for (let chunk = 0; chunk < PIANO_CHUNK_COUNT; chunk += 1) {
      const candidate = before.replacements[chunk][0].index;
      if (!before.setupMisses.has(candidate)) {
        target = candidate;
        break;
      }
    }
    expect(target).toBeGreaterThanOrEqual(0);
    const expectedHit = before.primaryHints.findIndex((hint) =>
      independentHintIndices(before.prfKey, hint).includes(target)
    );
    expect(expectedHit).toBeGreaterThanOrEqual(0);
    const chunk = Math.floor(target / PIANO_CHUNK_SIZE);
    const backup = before.backupHints[chunk][0];

    const request = beginPianoQueryForTest(
      state,
      target,
      new SeededEntropy('piano-r-equals-x-query')
    );
    expect(request.replacementIndex).toBe(target);
    expect(request.hintIndex).toBe(expectedHit);
    const requestAudit = auditPianoRequest(request);
    expect(requestAudit.kind).toBe('retrieve');
    expect(requestAudit.backupTag).toBe(backup.tag);
    expect(requestAudit.originalHintParity).not.toBeNull();
    expect(requestAudit.backupParity).not.toBeNull();
    expect(requestAudit.replacementValue).not.toBeNull();
    const wire = serializePianoRequest(request);
    const response = pianoServerAnswer(records, wire);
    const expectedRecovered = xorThreeIndependent(
      requestAudit.originalHintParity as Uint8Array,
      response,
      requestAudit.replacementValue as Uint8Array
    );
    expectBytes(expectedRecovered, records[target]);

    // Instrumentation returns copies: corrupting one snapshot cannot alter the
    // committed plan or its serialized request.
    (requestAudit.originalHintParity as Uint8Array)[0] ^= 0xff;
    requestAudit.wire[0] ^= 0xff;
    expectBytes(serializePianoRequest(request), wire);
    expectBytes(
      auditPianoRequest(request).originalHintParity as Uint8Array,
      before.primaryHints[expectedHit].parity
    );

    const result = finishPianoQuery(state, request, response);
    expect(result.ok).toBe(true);
    if (result.ok) expectBytes(result.record, records[target]);

    const after = auditPianoState(state);
    const refreshed = after.primaryHints[expectedHit];
    expect(refreshed.tag).toBe(backup.tag);
    expect(refreshed.programmedTarget).toBe(target);
    const expectedParity = backup.parityAfterPuncture.slice();
    for (let i = 0; i < PIANO_RECORD_BYTES; i += 1) expectedParity[i] ^= records[target][i];
    expectBytes(refreshed.parity, expectedParity);
  });

  it('recovers 33 independently checked records, then sends only a dummy beyond the window', async () => {
    const records = database();
    const state = await preprocessPianoForTest(records, new SeededEntropy('piano-window'));
    const queryEntropy = new SeededEntropy('piano-window-queries');
    for (let target = 0; target < PIANO_QUERY_WINDOW; target += 1) {
      const run = answerAndFinish(state, records, target, queryEntropy);
      expect(run.result.ok, `target ${target}`).toBe(true);
      if (run.result.ok) {
        expectBytes(run.result.record, records[target]);
        expectBytes(run.result.recoveredEffectiveRecord, records[target]);
      }
    }

    const beforeExtra = pianoStateMetrics(state);
    expect(beforeExtra.requestsSent).toBe(33);
    expect(beforeExtra.effectiveTargetsConsumed).toBe(33);
    expect(beforeExtra.cachedRecords).toBe(33);
    expect(beforeExtra.cacheBytes).toBe(PIANO_MAX_NORMAL_CACHE_BYTES);
    expect(beforeExtra.retainedStateBytes).toBe(
      PIANO_BASE_STATE_BYTES + PIANO_MAX_NORMAL_CACHE_BYTES
    );

    const extra = beginPianoQueryForTest(state, 40, queryEntropy);
    expect(extra.kind).toBe('dummy');
    expect(extra.effectiveIndex).toBeNull();
    expect(extra.preflightFailure?.code).toBe('WINDOW_EXHAUSTED');
    const extraWire = serializePianoRequest(extra);
    expect(parsePianoQuery(extraWire)).toHaveLength(8);
    const failed = finishPianoQuery(state, extra, pianoServerAnswer(records, extraWire));
    expect(failed.ok).toBe(false);
    if (!failed.ok) expect(failed.failure.code).toBe('WINDOW_EXHAUSTED');
  });

  it('retrieves all 64 targets across fresh epochs and preserves each refreshed parity invariant', async () => {
    const records = database();
    const epochs = [
      Array.from({ length: PIANO_QUERY_WINDOW }, (_, index) => index),
      Array.from(
        { length: PIANO_DATABASE_RECORDS - PIANO_QUERY_WINDOW },
        (_, index) => index + PIANO_QUERY_WINDOW
      ),
    ];

    for (let epoch = 0; epoch < epochs.length; epoch += 1) {
      const state = await preprocessPianoForTest(
        records,
        new SeededEntropy(`piano-all-targets-setup-${epoch}`)
      );
      const entropy = new SeededEntropy(`piano-all-targets-query-${epoch}`);
      for (const target of epochs[epoch]) {
        const run = answerAndFinish(state, records, target, entropy);
        expect(run.result.ok, `epoch ${epoch}, target ${target}`).toBe(true);
        if (run.result.ok) expectBytes(run.result.record, records[target]);

        // Re-expand the just-refreshed hint independently and require its
        // retained parity to equal the XOR of the actual current database set.
        expect(run.request.hintIndex).not.toBeNull();
        const after = auditPianoState(state);
        const refreshed = after.primaryHints[run.request.hintIndex as number];
        const refreshedIndices = independentHintIndices(after.prfKey, refreshed);
        expectBytes(refreshed.parity, independentXor(records, refreshedIndices));
        for (const consumed of after.consumedSlots) {
          expect(consumed).toBeLessThanOrEqual(PIANO_BACKUPS_PER_CHUNK);
        }
      }
    }
  });

  it('answers cached repeats while consuming distinct unused cover targets', async () => {
    const records = database();
    const state = await preprocessPianoForTest(records, new SeededEntropy('piano-cache'));
    const entropy = new SeededEntropy('piano-cache-queries');
    const first = answerAndFinish(state, records, 12, entropy);
    expect(first.result.ok).toBe(true);

    const second = answerAndFinish(state, records, 12, entropy);
    const third = answerAndFinish(state, records, 12, entropy);
    expect(second.request.kind).toBe('cached-cover');
    expect(third.request.kind).toBe('cached-cover');
    expect(second.request.effectiveIndex).not.toBe(12);
    expect(third.request.effectiveIndex).not.toBe(12);
    expect(third.request.effectiveIndex).not.toBe(second.request.effectiveIndex);
    for (const run of [second, third]) {
      expect(run.result.ok).toBe(true);
      if (run.result.ok) {
        expect(run.result.fromApplicationCache).toBe(true);
        expectBytes(run.result.record, records[12]);
        expectBytes(
          run.result.recoveredEffectiveRecord,
          records[run.result.effectiveIndex]
        );
      }
    }
    const audit = auditPianoState(state);
    expect(audit.consumedTargets).toHaveLength(3);
    expect(new Set(audit.consumedTargets).size).toBe(3);
    expect(audit.cache.size).toBe(3);
  });

  it('executes the rare setup-miss route, including a cached-repeat composite cover', async () => {
    const records = database();
    const base = await preprocessPianoForTest(records, new SeededEntropy('piano-synthetic-miss'));
    expect(auditPianoState(base).setupMisses.size).toBe(0);
    const missTarget = 7;
    const state = withSyntheticSetupMiss(base, missTarget, records[missTarget]);

    const request = beginPianoQueryForTest(
      state,
      missTarget,
      new SeededEntropy('piano-synthetic-miss-query')
    );
    expect(request.kind).toBe('setup-miss');
    const requestAudit = auditPianoRequest(request);
    expect(requestAudit.fromSetupMissCache).toBe(true);
    expect(requestAudit.fromApplicationCache).toBe(false);
    expect(requestAudit.hintIndex).toBeNull();
    expect(requestAudit.replacementValue).toBeNull();
    expect(auditPianoState(state).setupMisses.has(missTarget)).toBe(false);
    const response = pianoServerAnswer(records, serializePianoRequest(request));
    const result = finishPianoQuery(state, request, response);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.kind).toBe('setup-miss');
      expect(result.fromApplicationCache).toBe(false);
      expectBytes(result.record, records[missTarget]);
    }
    expect([...auditPianoState(state).consumedSlots]).toEqual(Array(8).fill(0));
    expectBytes(serializePianoState(deserializePianoState(serializePianoState(state))), serializePianoState(state));

    // Add a different synthetic miss after a normal application record is in
    // cache, then select that miss as the repeat's unused cover target.
    const applicationTarget = 3;
    const cachedBase = await preprocessPianoForTest(
      records,
      new SeededEntropy('piano-composite-miss')
    );
    const first = answerAndFinish(
      cachedBase,
      records,
      applicationTarget,
      new SeededEntropy('piano-composite-first')
    );
    expect(first.result.ok).toBe(true);
    const coverTarget = 7;
    const compositeState = withSyntheticSetupMiss(
      cachedBase,
      coverTarget,
      records[coverTarget]
    );
    const unusedRank = coverTarget - (applicationTarget < coverTarget ? 1 : 0);
    const composite = beginPianoQueryForTest(
      compositeState,
      applicationTarget,
      new WordEntropy([unusedRank])
    );
    expect(composite.effectiveIndex).toBe(coverTarget);
    expect(composite.kind).toBe('cached-cover-setup-miss');
    expect(auditPianoRequest(composite).fromApplicationCache).toBe(true);
    expect(auditPianoRequest(composite).fromSetupMissCache).toBe(true);
    const compositeResult = finishPianoQuery(
      compositeState,
      composite,
      pianoServerAnswer(records, serializePianoRequest(composite))
    );
    expect(compositeResult.ok).toBe(true);
    if (compositeResult.ok) {
      expect(compositeResult.fromApplicationCache).toBe(true);
      expectBytes(compositeResult.record, records[applicationTarget]);
      expectBytes(compositeResult.recoveredEffectiveRecord, records[coverTarget]);
    }
  });

  it('commits a setup miss before send, so malformed and abandoned states round-trip', async () => {
    const records = database();
    const makeState = async (seed: string): Promise<PianoClientState> => {
      const base = await preprocessPianoForTest(records, new SeededEntropy(seed));
      return withSyntheticSetupMiss(base, 9, records[9]);
    };

    const malformedState = await makeState('piano-miss-malformed');
    const malformedRequest = beginPianoQueryForTest(
      malformedState,
      9,
      new SeededEntropy('piano-miss-malformed-query')
    );
    const malformed = finishPianoQuery(malformedState, malformedRequest, new Uint8Array(511));
    expect(malformed.ok).toBe(false);
    if (!malformed.ok) expect(malformed.failure.code).toBe('MALFORMED_RESPONSE');
    expect(auditPianoState(malformedState).setupMisses.has(9)).toBe(false);
    const malformedWire = serializePianoState(malformedState);
    expectBytes(serializePianoState(deserializePianoState(malformedWire)), malformedWire);

    const abandonedState = await makeState('piano-miss-abandoned');
    const abandonedRequest = beginPianoQueryForTest(
      abandonedState,
      9,
      new SeededEntropy('piano-miss-abandoned-query')
    );
    expect(abandonPianoRequest(abandonedState, abandonedRequest).code).toBe('REQUEST_ABANDONED');
    expect(auditPianoState(abandonedState).setupMisses.has(9)).toBe(false);
    const abandonedWire = serializePianoState(abandonedState);
    expectBytes(serializePianoState(deserializePianoState(abandonedWire)), abandonedWire);
  });

  it('uses the same fixed request shape for a local index failure without inventing a server flag', async () => {
    const records = database();
    const state = await preprocessPianoForTest(records, new SeededEntropy('piano-dummy'));
    const request = beginPianoQueryForTest(state, 999, new SeededEntropy('piano-dummy-query'));
    expect(request.kind).toBe('dummy');
    expect(request.preflightFailure?.code).toBe('INDEX_OUT_OF_RANGE');
    const wire = serializePianoRequest(request);
    expect(wire.constructor).toBe(Uint8Array);
    expect(wire).toHaveLength(8);
    expect(Object.keys(request)).toEqual([]);
    const response = pianoServerAnswer(records, wire);
    expect(response).toHaveLength(512);
    const result = finishPianoQuery(state, request, response);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure.requiresRebuild).toBe(false);
    expect(pianoStateMetrics(state).valid).toBe(true);
  });

  it('a malformed response consumes the target and refresh slot, then invalidates rather than retrying', async () => {
    const records = database();
    const state = await preprocessPianoForTest(records, new SeededEntropy('piano-malformed'));
    const entropy = new SeededEntropy('piano-malformed-query');
    const request = beginPianoQueryForTest(state, 10, entropy);
    const targetChunk = Math.floor(10 / PIANO_CHUNK_SIZE);
    expect(auditPianoState(state).consumedSlots[targetChunk]).toBe(1);
    const result = finishPianoQuery(state, request, new Uint8Array(511));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure.code).toBe('MALFORMED_RESPONSE');

    const after = auditPianoState(state);
    expect(after.consumedTargets).toContain(10);
    expect(after.consumedSlots[targetChunk]).toBe(1);
    expect(pianoStateMetrics(state).invalidReason?.code).toBe('MALFORMED_RESPONSE');
    const retry = beginPianoQueryForTest(state, 10, entropy);
    expect(retry.kind).toBe('dummy');
    expect(retry.effectiveIndex).toBeNull();
    expect(retry.preflightFailure?.code).toBe('MALFORMED_RESPONSE');
    finishPianoQuery(state, retry, pianoServerAnswer(records, serializePianoRequest(retry)));
  });

  it('a missing response also reserves state permanently and requires rebuild', async () => {
    const records = database();
    const state = await preprocessPianoForTest(records, new SeededEntropy('piano-abandon'));
    const request = beginPianoQueryForTest(
      state,
      27,
      new SeededEntropy('piano-abandon-query')
    );
    const abandoned = abandonPianoRequest(state, request);
    expect(abandoned.code).toBe('REQUEST_ABANDONED');
    expect(abandoned.requiresRebuild).toBe(true);
    expect(auditPianoState(state).consumedTargets).toContain(27);
    expect(pianoStateMetrics(state).invalidReason?.code).toBe('REQUEST_ABANDONED');
  });
});

describe('state loss, update invalidation and rollback', () => {
  it('state loss can send a cover-shaped query but cannot recover anything', () => {
    const records = database();
    const lost = makePianoStateLossRequestForTest(new SeededEntropy('piano-state-loss'));
    expect(lost.failure.code).toBe('STATE_LOST');
    expect(lost.failure.requiresRebuild).toBe(true);
    expect(parsePianoQuery(lost.wire)).toHaveLength(8);
    expect(pianoServerAnswer(records, lost.wire)).toHaveLength(512);
    expect(Object.keys(lost).sort()).toEqual(['failure', 'wire']);
  });

  it('shows stale recovery after a database update, invalidates it, and succeeds only after full rebuild', async () => {
    const oldDatabase = database();
    const state = await preprocessPianoForTest(
      oldDatabase,
      new SeededEntropy('piano-database-update')
    );
    const audit = auditPianoState(state);
    let target = -1;
    for (let candidate = 0; candidate < PIANO_DATABASE_RECORDS; candidate += 1) {
      const chunk = Math.floor(candidate / PIANO_CHUNK_SIZE);
      if (
        audit.replacements[chunk][0].index !== candidate &&
        !audit.setupMisses.has(candidate)
      ) {
        target = candidate;
        break;
      }
    }
    expect(target).toBeGreaterThanOrEqual(0);

    const updated = oldDatabase.map((record) => record.slice());
    updated[target][0] ^= 0xff;
    updated[target][311] ^= 0x5a;
    const request = beginPianoQueryForTest(
      state,
      target,
      new SeededEntropy('piano-stale-query')
    );
    expect(request.replacementIndex).not.toBe(target);
    const staleResult = finishPianoQuery(
      state,
      request,
      pianoServerAnswer(updated, serializePianoRequest(request))
    );
    expect(staleResult.ok).toBe(true);
    if (staleResult.ok) {
      expectBytes(staleResult.record, oldDatabase[target]);
      expect(Array.from(staleResult.record)).not.toEqual(Array.from(updated[target]));
    }

    expect(await verifyPianoDatabaseCurrent(state, updated)).toBe(false);
    expect(pianoStateMetrics(state).invalidReason?.code).toBe('DATABASE_UPDATED');
    const dummy = beginPianoQueryForTest(
      state,
      target,
      new SeededEntropy('piano-updated-dummy')
    );
    expect(dummy.kind).toBe('dummy');
    expect(dummy.preflightFailure?.code).toBe('DATABASE_UPDATED');
    finishPianoQuery(state, dummy, pianoServerAnswer(updated, serializePianoRequest(dummy)));

    const rebuilt = await preprocessPianoForTest(
      updated,
      new SeededEntropy('piano-database-rebuild')
    );
    expect(await verifyPianoDatabaseCurrent(rebuilt, updated)).toBe(true);
    const fresh = answerAndFinish(
      rebuilt,
      updated,
      target,
      new SeededEntropy('piano-fresh-after-update')
    );
    expect(fresh.result.ok).toBe(true);
    if (fresh.result.ok) expectBytes(fresh.result.record, updated[target]);
  });

  it('rejects a pending response when a known database update invalidates the epoch', async () => {
    const records = database();
    const updated = database(1);
    const state = await preprocessPianoForTest(
      records,
      new SeededEntropy('piano-pending-update')
    );
    const request = beginPianoQueryForTest(
      state,
      14,
      new SeededEntropy('piano-pending-update-query')
    );
    expect(await verifyPianoDatabaseCurrent(state, updated)).toBe(false);
    const result = finishPianoQuery(
      state,
      request,
      pianoServerAnswer(updated, serializePianoRequest(request))
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure.code).toBe('DATABASE_UPDATED');
    const metrics = pianoStateMetrics(state);
    expect(metrics.responsesAccepted).toBe(1);
    expect(metrics.cachedRecords).toBe(0);
    expect(metrics.invalidReason?.code).toBe('DATABASE_UPDATED');
  });

  it('shows that changing a selected non-target poisons an old parity until digest invalidation and rebuild', async () => {
    const oldDatabase = database();
    const state = await preprocessPianoForTest(
      oldDatabase,
      new SeededEntropy('piano-nontarget-update')
    );
    const before = auditPianoState(state);

    let target = -1;
    let selectedNonTarget = -1;
    for (let candidate = 0; candidate < PIANO_DATABASE_RECORDS; candidate += 1) {
      if (before.setupMisses.has(candidate)) continue;
      const hit = before.primaryHints.find((hint) =>
        independentHintIndices(before.prfKey, hint).includes(candidate)
      );
      if (!hit) continue;
      const targetChunk = Math.floor(candidate / PIANO_CHUNK_SIZE);
      const member = independentHintIndices(before.prfKey, hit).find(
        (index) => Math.floor(index / PIANO_CHUNK_SIZE) !== targetChunk
      );
      if (member !== undefined) {
        target = candidate;
        selectedNonTarget = member;
        break;
      }
    }
    expect(target).toBeGreaterThanOrEqual(0);
    expect(selectedNonTarget).toBeGreaterThanOrEqual(0);

    const updated = oldDatabase.map((record) => record.slice());
    updated[selectedNonTarget][17] ^= 0xa5;
    updated[selectedNonTarget][401] ^= 0x3c;
    const request = beginPianoQueryForTest(
      state,
      target,
      new SeededEntropy('piano-nontarget-stale-query')
    );
    expect([...serializePianoRequest(request)]).toContain(selectedNonTarget);
    const stale = finishPianoQuery(
      state,
      request,
      pianoServerAnswer(updated, serializePianoRequest(request))
    );
    expect(stale.ok).toBe(true);
    if (stale.ok) {
      expect(Array.from(stale.record)).not.toEqual(Array.from(oldDatabase[target]));
      expect(Array.from(stale.record)).not.toEqual(Array.from(updated[target]));
    }

    expect(await verifyPianoDatabaseCurrent(state, updated)).toBe(false);
    expect(pianoStateMetrics(state).invalidReason?.code).toBe('DATABASE_UPDATED');
    const rebuilt = await preprocessPianoForTest(
      updated,
      new SeededEntropy('piano-nontarget-rebuild')
    );
    const fresh = answerAndFinish(
      rebuilt,
      updated,
      target,
      new SeededEntropy('piano-nontarget-fresh-query')
    );
    expect(fresh.result.ok).toBe(true);
    if (fresh.result.ok) expectBytes(fresh.result.record, updated[target]);
  });

  it('serializes retained state canonically and refuses malformed encodings', async () => {
    const records = database();
    const state = await preprocessPianoForTest(records, new SeededEntropy('piano-state-wire'));
    const entropy = new SeededEntropy('piano-state-wire-queries');
    answerAndFinish(state, records, 7, entropy);
    answerAndFinish(state, records, 7, entropy); // cached request plus fresh cover

    const wire = serializePianoState(state);
    expect(wire.length).toBe(pianoStateMetrics(state).retainedStateBytes);
    const restored = deserializePianoState(wire);
    expectBytes(serializePianoState(restored), wire);
    const continued = answerAndFinish(restored, records, 22, entropy);
    expect(continued.result.ok).toBe(true);
    if (continued.result.ok) expectBytes(continued.result.record, records[22]);

    const wrongMagic = wire.slice();
    wrongMagic[0] ^= 1;
    expect(() => deserializePianoState(wrongMagic)).toThrow(/wrong magic/);
    const reserved = wire.slice();
    reserved[6] = 1;
    expect(() => deserializePianoState(reserved)).toThrow(/reserved/);
    const impossibleSlots = wire.slice();
    impossibleSlots[102] = PIANO_BACKUPS_PER_CHUNK;
    expect(() => deserializePianoState(impossibleSlots)).toThrow(
      /more refresh slots than effective targets/
    );
    const missingConsumedTargets = wire.slice();
    missingConsumedTargets.fill(0, 110, 118);
    expect(() => deserializePianoState(missingConsumedTargets)).toThrow(
      /more refresh slots than effective targets|programmed target is not marked as consumed|does not cache every consumed/
    );
    expect(() => deserializePianoState(wire.subarray(0, wire.length - 1))).toThrow(/expected/);
    expect(() => deserializePianoState(Uint8Array.from([...wire, 0]))).toThrow(/expected/);
  });

  it('demonstrates rollback linkability, then invalidates an old snapshot with an external anchor', async () => {
    const records = database();
    const state = await preprocessPianoForTest(records, new SeededEntropy('piano-rollback'));
    const oldSnapshot = serializePianoState(state);
    const queryEntropy = new SeededEntropy('piano-rollback-query');
    const first = beginPianoQueryForTest(state, 19, queryEntropy);
    const firstWire = serializePianoRequest(first);
    finishPianoQuery(state, first, pianoServerAnswer(records, firstWire));
    const advancedAnchor = pianoStateAnchor(state);
    expect(advancedAnchor.minimumGeneration).toBe(1);

    // Restoring without an external high-water mark reproduces the same hint
    // and replacement request byte for byte: a concrete linkability failure.
    const unguarded = deserializePianoState(oldSnapshot);
    const replay = beginPianoQueryForTest(
      unguarded,
      19,
      new SeededEntropy('entropy-unused-for-direct-target')
    );
    expectBytes(serializePianoRequest(replay), firstWire);
    finishPianoQuery(
      unguarded,
      replay,
      pianoServerAnswer(records, serializePianoRequest(replay))
    );

    const guarded = deserializePianoState(oldSnapshot, advancedAnchor);
    expect(pianoStateMetrics(guarded).invalidReason?.code).toBe('ROLLBACK_DETECTED');
    const blocked = beginPianoQueryForTest(
      guarded,
      19,
      new SeededEntropy('piano-rollback-cover')
    );
    expect(blocked.kind).toBe('dummy');
    expect(blocked.preflightFailure?.code).toBe('ROLLBACK_DETECTED');
    expect(blocked.effectiveIndex).toBeNull();
  });
});

describe('measured byte and operation ledgers', () => {
  it('keeps setup, online work, storage and amortized totals in separate exact counters', async () => {
    expect(PIANO_SETUP_COSTS).toEqual({
      streamedDatabaseBytes: 64 * 512,
      streamedRecords: 64,
      primaryParityRecordXors: 256 * 8,
      backupParityRecordXors: 8 * 8 * 7,
      totalSetupParityRecordXors: 256 * 8 + 8 * 8 * 7,
      replacementRecordCopies: 64,
    });
    expect(PIANO_QUERY_BYTES).toBe(8);
    expect(PIANO_RESPONSE_BYTES).toBe(512);
    expect(PIANO_CACHE_ENTRY_BYTES).toBe(513);
    expect(PIANO_MAX_NORMAL_CACHE_BYTES).toBe(33 * 513);
    expect(PIANO_BASE_STATE_BYTES).toBe(197_696);

    expect(pianoCostForQueries(33)).toEqual({
      applicationQueries: 33,
      setupRuns: 1,
      setupStreamBytes: 32_768,
      onlineUploadBytes: 264,
      onlineDownloadBytes: 16_896,
      totalWireBytes: 49_928,
      setupRecordReads: 64,
      onlineRecordProbes: 264,
      totalRecordProbes: 328,
      setupParityRecordXors: 2_496,
      onlineParityRecordXors: 264,
      replacementRecordCopies: 64,
    });
    expect(pianoCostForQueries(34).setupRuns).toBe(2);
    expect(pianoCostForQueries(34).totalWireBytes).toBe(2 * 32_768 + 34 * (8 + 512));

    const records = database();
    const state = await preprocessPianoForTest(records, new SeededEntropy('piano-cost-state'));
    expect(serializePianoState(state)).toHaveLength(PIANO_BASE_STATE_BYTES);
    const request = beginPianoQueryForTest(
      state,
      4,
      new SeededEntropy('piano-cost-query')
    );
    const upload = serializePianoRequest(request);
    const download = pianoServerAnswer(records, upload);
    expect(upload).toHaveLength(8);
    expect(download).toHaveLength(512);
    finishPianoQuery(state, request, download);
    const metrics = pianoStateMetrics(state);
    expect(metrics.committedUploadBytes).toBe(upload.length);
    expect(metrics.responseBytesReceived).toBe(download.length);
    expect(metrics.committedServerRecordProbes).toBe(8);
    expect(metrics.cacheBytes).toBe(513);
    expect(metrics.retainedStateBytes).toBe(PIANO_BASE_STATE_BYTES + 513);
    expectBytes(await fingerprintPianoDatabase(records), auditPianoState(state).databaseDigest);
  });
});
