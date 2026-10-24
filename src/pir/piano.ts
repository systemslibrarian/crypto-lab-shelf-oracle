import { chachaBlock } from './chacha20';
import { sha256 } from './records';

/**
 * A deliberately bounded, executable adaptation of the one-server Piano PIR
 * client in Zhou–Park–Shi–Zheng, "Piano: Extremely Simple, Single-Server PIR with
 * Sublinear Server Computation" (IEEE S&P 2024; ePrint 2023/452).
 *
 * This module fixes the database at 64 records of 512 bytes, split into eight
 * chunks of eight records.  The client streams that static database once to
 * build PRF-defined parity hints, then an honest-but-curious server answers an
 * online request by XORing exactly one record from each chunk.  The server sees
 * only eight compact indices and returns one 512-byte parity.
 *
 * IMPORTANT SCOPE.  This is a small teaching adaptation, not the paper's
 * asymptotic parameter regime or implementation.  In particular, eight backup
 * hints and replacement records are retained for EACH of eight chunks.  That
 * is explicit linear overprovision at N=64.  The finite availability bounds
 * exported below cover only primary-hint availability under their stated
 * assumptions; they are not a transferred Piano theorem, a 128-bit claim, or
 * a malicious-server guarantee.  This construction has no server ProcessDB
 * phase and transfers no property from the separate LMW doubly-efficient PIR.
 */

export const PIANO_DATABASE_RECORDS = 64;
export const PIANO_RECORD_BYTES = 512;
export const PIANO_CHUNK_COUNT = 8;
export const PIANO_CHUNK_SIZE = 8;
export const PIANO_QUERY_WINDOW = Math.floor(
  Math.sqrt(PIANO_DATABASE_RECORDS) * Math.log(PIANO_DATABASE_RECORDS)
); // 33
export const PIANO_FAILURE_BITS = 40;
export const PIANO_BACKUPS_PER_CHUNK = PIANO_CHUNK_SIZE;
export const PIANO_QUERY_BYTES = PIANO_CHUNK_COUNT;
export const PIANO_RESPONSE_BYTES = PIANO_RECORD_BYTES;

/**
 * The conservative primary-hint rule used by the authors' current reference
 * client: ceil(ln(Q) + (lambda + 1) ln(2)) groups, each of `chunkSize` hints.
 *
 * The exponential inequality (1 - 1/S)^M <= exp(-M/S) and the extra bit make
 * this deliberately more conservative than solving the exact finite equation.
 */
export function derivePianoPrimaryHintCount(
  failureBits: number,
  queryWindow: number,
  chunkSize: number
): number {
  if (!Number.isInteger(failureBits) || failureBits < 1) {
    throw new RangeError(`failureBits must be a positive integer; got ${failureBits}`);
  }
  if (!Number.isInteger(queryWindow) || queryWindow < 1) {
    throw new RangeError(`queryWindow must be a positive integer; got ${queryWindow}`);
  }
  if (!Number.isInteger(chunkSize) || chunkSize < 2) {
    throw new RangeError(`chunkSize must be an integer at least two; got ${chunkSize}`);
  }
  const groups = Math.ceil(Math.log(queryWindow) + (failureBits + 1) * Math.LN2);
  return groups * chunkSize;
}

export const PIANO_PRIMARY_HINTS = derivePianoPrimaryHintCount(
  PIANO_FAILURE_BITS,
  PIANO_QUERY_WINDOW,
  PIANO_CHUNK_SIZE
); // 256

/** Exact finite bounds for this fixed teaching instance. */
export interface PianoAvailabilityBounds {
  /** One fixed target is absent from all 256 primary hints at setup. */
  readonly setupFixedTargetMiss: number;
  /** log2 of setupFixedTargetMiss. */
  readonly setupFixedTargetMissLog2: number;
  /**
   * Union bound across the 33-query window after allowing seven programmed
   * hints in one chunk to be deterministic non-hits for its eighth target.
   */
  readonly sessionPrimaryHintMissUpperBound: number;
  /** log2 of sessionPrimaryHintMissUpperBound. */
  readonly sessionPrimaryHintMissLog2: number;
  /** The minimum number of still-uniform coordinates used by that bound. */
  readonly minimumUniformHintsPerTarget: number;
  readonly scope: string;
}

export function pianoAvailabilityBounds(): PianoAvailabilityBounds {
  const missPerHint = (PIANO_CHUNK_SIZE - 1) / PIANO_CHUNK_SIZE;
  const minimumUniformHintsPerTarget = PIANO_PRIMARY_HINTS - (PIANO_CHUNK_SIZE - 1);
  const setupFixedTargetMiss = missPerHint ** PIANO_PRIMARY_HINTS;
  const sessionPrimaryHintMissUpperBound =
    PIANO_QUERY_WINDOW * missPerHint ** minimumUniformHintsPerTarget;
  return {
    setupFixedTargetMiss,
    setupFixedTargetMissLog2: Math.log2(setupFixedTargetMiss),
    sessionPrimaryHintMissUpperBound,
    sessionPrimaryHintMissLog2: Math.log2(sessionPrimaryHintMissUpperBound),
    minimumUniformHintsPerTarget,
    scope:
      'Primary-hint availability only, for at most 33 unique effective targets, ' +
      'under independent secret PRF coordinates and the bounded refresh schedule; ' +
      'not an end-to-end security or malicious-server bound.',
  };
}

export interface PianoSetupCosts {
  readonly streamedDatabaseBytes: number;
  readonly streamedRecords: number;
  readonly primaryParityRecordXors: number;
  readonly backupParityRecordXors: number;
  readonly totalSetupParityRecordXors: number;
  readonly replacementRecordCopies: number;
}

export const PIANO_SETUP_COSTS: PianoSetupCosts = Object.freeze({
  streamedDatabaseBytes: PIANO_DATABASE_RECORDS * PIANO_RECORD_BYTES,
  streamedRecords: PIANO_DATABASE_RECORDS,
  primaryParityRecordXors: PIANO_PRIMARY_HINTS * PIANO_CHUNK_COUNT,
  backupParityRecordXors:
    PIANO_CHUNK_COUNT * PIANO_BACKUPS_PER_CHUNK * (PIANO_CHUNK_COUNT - 1),
  totalSetupParityRecordXors:
    PIANO_PRIMARY_HINTS * PIANO_CHUNK_COUNT +
    PIANO_CHUNK_COUNT * PIANO_BACKUPS_PER_CHUNK * (PIANO_CHUNK_COUNT - 1),
  replacementRecordCopies: PIANO_CHUNK_COUNT * PIANO_BACKUPS_PER_CHUNK,
});

export interface PianoCostLedger {
  readonly applicationQueries: number;
  readonly setupRuns: number;
  readonly setupStreamBytes: number;
  readonly onlineUploadBytes: number;
  readonly onlineDownloadBytes: number;
  readonly totalWireBytes: number;
  readonly setupRecordReads: number;
  readonly onlineRecordProbes: number;
  readonly totalRecordProbes: number;
  readonly setupParityRecordXors: number;
  readonly onlineParityRecordXors: number;
  readonly replacementRecordCopies: number;
}

/**
 * A formula ledger, not a timing claim.  A fresh preprocessing stream is needed
 * for each 33-query window.  Heterogeneous record reads, XORs, copies and bytes
 * stay in separate counters rather than being collapsed into a "speed score".
 */
export function pianoCostForQueries(applicationQueries: number): PianoCostLedger {
  if (!Number.isInteger(applicationQueries) || applicationQueries < 0) {
    throw new RangeError(
      `applicationQueries must be a non-negative integer; got ${applicationQueries}`
    );
  }
  const setupRuns =
    applicationQueries === 0 ? 0 : Math.ceil(applicationQueries / PIANO_QUERY_WINDOW);
  const setupStreamBytes = setupRuns * PIANO_SETUP_COSTS.streamedDatabaseBytes;
  const onlineUploadBytes = applicationQueries * PIANO_QUERY_BYTES;
  const onlineDownloadBytes = applicationQueries * PIANO_RESPONSE_BYTES;
  const setupRecordReads = setupRuns * PIANO_SETUP_COSTS.streamedRecords;
  const onlineRecordProbes = applicationQueries * PIANO_CHUNK_COUNT;
  return {
    applicationQueries,
    setupRuns,
    setupStreamBytes,
    onlineUploadBytes,
    onlineDownloadBytes,
    totalWireBytes: setupStreamBytes + onlineUploadBytes + onlineDownloadBytes,
    setupRecordReads,
    onlineRecordProbes,
    totalRecordProbes: setupRecordReads + onlineRecordProbes,
    setupParityRecordXors: setupRuns * PIANO_SETUP_COSTS.totalSetupParityRecordXors,
    onlineParityRecordXors: applicationQueries * PIANO_CHUNK_COUNT,
    replacementRecordCopies: setupRuns * PIANO_SETUP_COSTS.replacementRecordCopies,
  };
}

/**
 * Entropy injection is deliberately exposed only through functions whose names
 * say `ForTest`.  Live entry points below always cross the WebCrypto CSPRNG
 * boundary and accept no caller-supplied seed.
 */
export interface PianoTestEntropy {
  fill(out: Uint8Array): void;
}

interface PianoEntropy {
  fill(out: Uint8Array): void;
}

function liveEntropy(): PianoEntropy {
  if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
    throw new Error('WebCrypto getRandomValues is required for live Piano state');
  }
  return {
    fill(out: Uint8Array): void {
      // TypeScript 7 correctly permits a caller's Uint8Array to be backed by a
      // SharedArrayBuffer, while WebCrypto accepts only ArrayBuffer-backed
      // views.  Draw into a fresh ordinary buffer, then copy into the caller's
      // view so the live entropy boundary remains valid for either shape.
      const fresh = new Uint8Array(out.length);
      crypto.getRandomValues(fresh);
      out.set(fresh);
    },
  };
}

function uniformBelow(entropy: PianoEntropy, bound: number): number {
  if (!Number.isInteger(bound) || bound < 1 || bound > 0x1_0000_0000) {
    throw new RangeError(`uniform bound must be in 1 .. 2^32; got ${bound}`);
  }
  const bytes = new Uint8Array(4);
  const limit = Math.floor(0x1_0000_0000 / bound) * bound;
  for (;;) {
    entropy.fill(bytes);
    const value = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0, true);
    if (value < limit) return value % bound;
  }
}

function randomBytes(entropy: PianoEntropy, length: number): Uint8Array {
  const out = new Uint8Array(length);
  entropy.fill(out);
  return out;
}

function validateDatabase(database: readonly Uint8Array[]): void {
  if (database.length !== PIANO_DATABASE_RECORDS) {
    throw new RangeError(
      `Piano database must contain exactly ${PIANO_DATABASE_RECORDS} records; got ${database.length}`
    );
  }
  for (let i = 0; i < database.length; i += 1) {
    if (!(database[i] instanceof Uint8Array) || database[i].length !== PIANO_RECORD_BYTES) {
      throw new RangeError(
        `Piano record ${i} must contain exactly ${PIANO_RECORD_BYTES} bytes; got ${database[i]?.length}`
      );
    }
  }
}

/** SHA-256 over the exact ordered 64 x 512-byte database snapshot. */
export async function fingerprintPianoDatabase(
  database: readonly Uint8Array[]
): Promise<Uint8Array> {
  validateDatabase(database);
  const bytes = new Uint8Array(PIANO_DATABASE_RECORDS * PIANO_RECORD_BYTES);
  for (let i = 0; i < database.length; i += 1) {
    bytes.set(database[i], i * PIANO_RECORD_BYTES);
  }
  return sha256(bytes);
}

function xorInto(target: Uint8Array, value: Uint8Array): void {
  for (let i = 0; i < PIANO_RECORD_BYTES; i += 1) target[i] ^= value[i];
}

function xorThree(a: Uint8Array, b: Uint8Array, c: Uint8Array): Uint8Array {
  const out = new Uint8Array(PIANO_RECORD_BYTES);
  for (let i = 0; i < PIANO_RECORD_BYTES; i += 1) out[i] = a[i] ^ b[i] ^ c[i];
  return out;
}

/**
 * One PRF coordinate.  A distinct 256-bit setup key feeds the existing,
 * RFC-8439-KAT-tested ChaCha20 block function.  The nonce domain-separates a
 * four-byte tag and chunk number; taking three low bits is exact because the
 * chunk size is eight.
 */
function prfOffset(key: Uint8Array, tag: number, chunk: number): number {
  const nonce = new Uint8Array(12);
  nonce.set([0x50, 0x4e, 0x4f, 0x31], 0); // "PNO1"
  const view = new DataView(nonce.buffer);
  view.setUint32(4, tag, true);
  view.setUint32(8, chunk, true);
  return chachaBlock(key, 0, nonce)[0] & (PIANO_CHUNK_SIZE - 1);
}

interface PrimaryHint {
  tag: number;
  parity: Uint8Array;
  programmedTarget: number | null;
}

interface BackupHint {
  readonly tag: number;
  readonly parityAfterPuncture: Uint8Array;
}

interface Replacement {
  readonly index: number;
  readonly value: Uint8Array;
}

export type PianoFailureCode =
  | 'INDEX_OUT_OF_RANGE'
  | 'WINDOW_EXHAUSTED'
  | 'HINT_UNAVAILABLE'
  | 'NO_COVER_TARGET'
  | 'DATABASE_UPDATED'
  | 'ROLLBACK_DETECTED'
  | 'MALFORMED_RESPONSE'
  | 'REQUEST_ABANDONED'
  | 'STATE_INVALID'
  | 'STATE_LOST';

export interface PianoFailure {
  readonly code: PianoFailureCode;
  readonly detail: string;
  readonly requiresRebuild: boolean;
}

interface StateData {
  readonly databaseDigest: Uint8Array;
  readonly stateId: Uint8Array;
  readonly prfKey: Uint8Array;
  readonly primaryHints: PrimaryHint[];
  readonly backupHints: BackupHint[][];
  readonly replacements: Replacement[][];
  readonly consumedSlots: Uint8Array;
  readonly consumedTargets: Uint8Array;
  readonly cache: Map<number, Uint8Array>;
  readonly setupMisses: Map<number, Uint8Array>;
  requestsSent: number;
  responsesAccepted: number;
  responseBytesReceived: number;
  invalid: PianoFailure | null;
  pending: PianoPreparedRequest | null;
}

const STATE_TOKEN = Symbol('piano-state');
const STATE_DATA = new WeakMap<PianoClientState, StateData>();

/** Opaque retained client state.  Inspect it only through the exported helpers. */
export class PianoClientState {
  constructor(token?: symbol) {
    if (token !== STATE_TOKEN) {
      throw new TypeError('PianoClientState is created by preprocessPiano');
    }
  }
}

function makeState(data: StateData): PianoClientState {
  const state = new PianoClientState(STATE_TOKEN);
  STATE_DATA.set(state, data);
  return state;
}

function stateData(state: PianoClientState): StateData {
  const data = STATE_DATA.get(state);
  if (!data) throw new TypeError('unrecognized Piano client state');
  return data;
}

function failure(
  code: PianoFailureCode,
  detail: string,
  requiresRebuild: boolean
): PianoFailure {
  return Object.freeze({ code, detail, requiresRebuild });
}

function invalidate(data: StateData, why: PianoFailure): void {
  if (data.invalid === null) data.invalid = why;
}

function primaryIndexAtChunk(data: StateData, hint: PrimaryHint, chunk: number): number {
  if (
    hint.programmedTarget !== null &&
    Math.floor(hint.programmedTarget / PIANO_CHUNK_SIZE) === chunk
  ) {
    return hint.programmedTarget;
  }
  return chunk * PIANO_CHUNK_SIZE + prfOffset(data.prfKey, hint.tag, chunk);
}

function hintContains(data: StateData, hint: PrimaryHint, target: number): boolean {
  const chunk = Math.floor(target / PIANO_CHUNK_SIZE);
  return primaryIndexAtChunk(data, hint, chunk) === target;
}

async function preprocessWithEntropy(
  database: readonly Uint8Array[],
  entropy: PianoEntropy
): Promise<PianoClientState> {
  validateDatabase(database);
  // Snapshot synchronously before the first await.  Otherwise a caller could
  // mutate one of its record buffers while SHA-256 is pending and leave the
  // retained digest describing different bytes from the computed parities.
  const snapshot = database.map((record) => record.slice());
  const databaseDigest = await fingerprintPianoDatabase(snapshot);
  const prfKey = randomBytes(entropy, 32);
  const stateId = randomBytes(entropy, 16);

  const primaryHints: PrimaryHint[] = Array.from(
    { length: PIANO_PRIMARY_HINTS },
    (_, tag) => ({ tag, parity: new Uint8Array(PIANO_RECORD_BYTES), programmedTarget: null })
  );
  const backupHints: BackupHint[][] = Array.from(
    { length: PIANO_CHUNK_COUNT },
    (_, puncturedChunk) =>
      Array.from({ length: PIANO_BACKUPS_PER_CHUNK }, (_, slot) => ({
        tag:
          PIANO_PRIMARY_HINTS + puncturedChunk * PIANO_BACKUPS_PER_CHUNK + slot,
        parityAfterPuncture: new Uint8Array(PIANO_RECORD_BYTES),
      }))
  );

  // Sample every replacement independently.  Deliberately do NOT reject r=x
  // and do NOT deduplicate collisions: both are valid in the recovery equation.
  const replacementIndices = Array.from({ length: PIANO_CHUNK_COUNT }, (_, chunk) =>
    Array.from(
      { length: PIANO_BACKUPS_PER_CHUNK },
      () => chunk * PIANO_CHUNK_SIZE + uniformBelow(entropy, PIANO_CHUNK_SIZE)
    )
  );
  const replacements: Replacement[][] = Array.from(
    { length: PIANO_CHUNK_COUNT },
    () => []
  );
  const covered = new Uint8Array(PIANO_DATABASE_RECORDS);

  // One logical stream over the database.  Each arriving chunk updates every
  // primary parity and every backup parity that is not punctured at that chunk.
  for (let chunk = 0; chunk < PIANO_CHUNK_COUNT; chunk += 1) {
    for (const hint of primaryHints) {
      const index = chunk * PIANO_CHUNK_SIZE + prfOffset(prfKey, hint.tag, chunk);
      xorInto(hint.parity, snapshot[index]);
      covered[index] = 1;
    }
    for (let punctured = 0; punctured < PIANO_CHUNK_COUNT; punctured += 1) {
      if (punctured === chunk) continue;
      for (const hint of backupHints[punctured]) {
        const index = chunk * PIANO_CHUNK_SIZE + prfOffset(prfKey, hint.tag, chunk);
        xorInto(hint.parityAfterPuncture, snapshot[index]);
      }
    }
    replacements[chunk] = replacementIndices[chunk].map((index) => ({
      index,
      value: snapshot[index].slice(),
    }));
  }

  // The reference construction keeps the vanishingly rare setup misses.  This
  // is a sparse exception cache, not a copy of the full database.
  const setupMisses = new Map<number, Uint8Array>();
  for (let index = 0; index < PIANO_DATABASE_RECORDS; index += 1) {
    if (covered[index] === 0) setupMisses.set(index, snapshot[index].slice());
  }

  return makeState({
    databaseDigest,
    stateId,
    prfKey,
    primaryHints,
    backupHints,
    replacements,
    consumedSlots: new Uint8Array(PIANO_CHUNK_COUNT),
    consumedTargets: new Uint8Array(PIANO_DATABASE_RECORDS),
    cache: new Map(),
    setupMisses,
    requestsSent: 0,
    responsesAccepted: 0,
    responseBytesReceived: 0,
    invalid: null,
    pending: null,
  });
}

/** Live preprocessing: key, setup id and replacements all come from WebCrypto. */
export async function preprocessPiano(
  database: readonly Uint8Array[]
): Promise<PianoClientState> {
  return preprocessWithEntropy(database, liveEntropy());
}

/** TEST ONLY: deterministic/injectable entropy must never back a live lesson run. */
export async function preprocessPianoForTest(
  database: readonly Uint8Array[],
  entropy: PianoTestEntropy
): Promise<PianoClientState> {
  return preprocessWithEntropy(database, entropy);
}

/**
 * Parse the entire canonical query.  Its byte at position j must be an index in
 * chunk j, which forbids alternate encodings, reordering and hidden metadata.
 * The pinned reference prototype transports uint64 indices through protobuf;
 * this lab-specific codec can use one byte because every valid index is below
 * 64.  Its measured eight-byte upload is therefore this implementation's wire
 * cost, not a benchmark copied from the reference implementation or paper.
 */
export function parsePianoQuery(bytes: Uint8Array): Uint8Array {
  if (!(bytes instanceof Uint8Array) || bytes.length !== PIANO_QUERY_BYTES) {
    throw new RangeError(
      `Piano query must be exactly ${PIANO_QUERY_BYTES} bytes; got ${bytes?.length}`
    );
  }
  const out = bytes.slice();
  for (let chunk = 0; chunk < PIANO_CHUNK_COUNT; chunk += 1) {
    const index = out[chunk];
    const low = chunk * PIANO_CHUNK_SIZE;
    const high = low + PIANO_CHUNK_SIZE;
    if (index < low || index >= high) {
      throw new RangeError(
        `query byte ${chunk} must name one record in chunk ${chunk} (${low} .. ${high - 1}); got ${index}`
      );
    }
  }
  return out;
}

export function serializePianoQuery(indices: ArrayLike<number>): Uint8Array {
  if (indices.length !== PIANO_QUERY_BYTES) {
    throw new RangeError(
      `Piano query must contain exactly ${PIANO_QUERY_BYTES} indices; got ${indices.length}`
    );
  }
  const bytes = new Uint8Array(PIANO_QUERY_BYTES);
  for (let i = 0; i < bytes.length; i += 1) {
    const value = indices[i];
    if (!Number.isInteger(value) || value < 0 || value > 255) {
      throw new RangeError(`query index ${i} is not one canonical byte: ${value}`);
    }
    bytes[i] = value;
  }
  return parsePianoQuery(bytes);
}

export function parsePianoResponse(bytes: Uint8Array): Uint8Array {
  if (!(bytes instanceof Uint8Array) || bytes.length !== PIANO_RESPONSE_BYTES) {
    throw new RangeError(
      `Piano response must be exactly ${PIANO_RESPONSE_BYTES} bytes; got ${bytes?.length}`
    );
  }
  return bytes.slice();
}

/**
 * The complete server API: eight bytes in, 512 bytes out.  There is no target,
 * hint id, chunk id, dummy flag, cache flag, revision or other side channel in
 * the request object because the server receives no object at all.
 */
export function pianoServerAnswer(
  database: readonly Uint8Array[],
  queryBytes: Uint8Array
): Uint8Array {
  validateDatabase(database);
  const indices = parsePianoQuery(queryBytes);
  const answer = new Uint8Array(PIANO_RESPONSE_BYTES);
  for (const index of indices) xorInto(answer, database[index]);
  return answer;
}

export type PianoRequestKind =
  | 'retrieve'
  | 'cached-cover'
  | 'setup-miss'
  | 'cached-cover-setup-miss'
  | 'dummy';

interface RequestPlan {
  readonly stateId: Uint8Array;
  readonly requestNumber: number;
  readonly requestedIndex: number;
  readonly effectiveIndex: number | null;
  readonly kind: PianoRequestKind;
  readonly wire: Uint8Array;
  readonly preflightFailure: PianoFailure | null;
  readonly applicationCachedRecord: Uint8Array | null;
  readonly setupMissRecord: Uint8Array | null;
  readonly hintIndex: number | null;
  readonly originalHintParity: Uint8Array | null;
  readonly backupTag: number | null;
  readonly backupParity: Uint8Array | null;
  readonly replacementIndex: number | null;
  readonly replacementValue: Uint8Array | null;
}

const REQUEST_TOKEN = Symbol('piano-request');
const REQUEST_PLANS = new WeakMap<PianoPreparedRequest, RequestPlan>();

/** Private client envelope.  Only serializePianoRequest(request) goes to the server. */
export class PianoPreparedRequest {
  constructor(token?: symbol) {
    if (token !== REQUEST_TOKEN) {
      throw new TypeError('PianoPreparedRequest is created by beginPianoQuery');
    }
  }

  private get plan(): RequestPlan {
    const plan = REQUEST_PLANS.get(this);
    if (!plan) throw new TypeError('unrecognized Piano request');
    return plan;
  }

  get requestNumber(): number {
    return this.plan.requestNumber;
  }

  get requestedIndex(): number {
    return this.plan.requestedIndex;
  }

  get effectiveIndex(): number | null {
    return this.plan.effectiveIndex;
  }

  get kind(): PianoRequestKind {
    return this.plan.kind;
  }

  get preflightFailure(): PianoFailure | null {
    return this.plan.preflightFailure;
  }

  get hintIndex(): number | null {
    return this.plan.hintIndex;
  }

  get replacementIndex(): number | null {
    return this.plan.replacementIndex;
  }
}

function makeRequest(plan: RequestPlan): PianoPreparedRequest {
  const request = new PianoPreparedRequest(REQUEST_TOKEN);
  REQUEST_PLANS.set(request, plan);
  return request;
}

function requestPlan(request: PianoPreparedRequest): RequestPlan {
  const plan = REQUEST_PLANS.get(request);
  if (!plan) throw new TypeError('unrecognized Piano request');
  return plan;
}

export function serializePianoRequest(request: PianoPreparedRequest): Uint8Array {
  return parsePianoQuery(requestPlan(request).wire);
}

/**
 * Copy the client-local recovery plan for tests and the learner trace.  None of
 * these fields belongs on the wire: the server receives only
 * `serializePianoRequest(request)`.  Returned buffers are defensive copies so
 * instrumentation cannot mutate a committed request.
 */
export interface PianoRequestAuditSnapshot {
  readonly requestedIndex: number;
  readonly effectiveIndex: number | null;
  readonly kind: PianoRequestKind;
  readonly wire: Uint8Array;
  readonly hintIndex: number | null;
  readonly originalHintParity: Uint8Array | null;
  readonly backupTag: number | null;
  readonly backupParity: Uint8Array | null;
  readonly replacementIndex: number | null;
  readonly replacementValue: Uint8Array | null;
  readonly fromApplicationCache: boolean;
  readonly fromSetupMissCache: boolean;
}

export function auditPianoRequest(request: PianoPreparedRequest): PianoRequestAuditSnapshot {
  const plan = requestPlan(request);
  return {
    requestedIndex: plan.requestedIndex,
    effectiveIndex: plan.effectiveIndex,
    kind: plan.kind,
    wire: plan.wire.slice(),
    hintIndex: plan.hintIndex,
    originalHintParity: plan.originalHintParity?.slice() ?? null,
    backupTag: plan.backupTag,
    backupParity: plan.backupParity?.slice() ?? null,
    replacementIndex: plan.replacementIndex,
    replacementValue: plan.replacementValue?.slice() ?? null,
    fromApplicationCache: plan.applicationCachedRecord !== null,
    fromSetupMissCache: plan.setupMissRecord !== null,
  };
}

function dummyIndices(entropy: PianoEntropy): Uint8Array {
  return Uint8Array.from({ length: PIANO_CHUNK_COUNT }, (_, chunk) =>
    chunk * PIANO_CHUNK_SIZE + uniformBelow(entropy, PIANO_CHUNK_SIZE)
  );
}

function chooseUnusedTarget(data: StateData, entropy: PianoEntropy): number | null {
  const unused: number[] = [];
  for (let i = 0; i < PIANO_DATABASE_RECORDS; i += 1) {
    if (data.consumedTargets[i] === 0) unused.push(i);
  }
  if (unused.length === 0) return null;
  return unused[uniformBelow(entropy, unused.length)];
}

function beginWithEntropy(
  state: PianoClientState,
  requestedIndex: number,
  entropy: PianoEntropy
): PianoPreparedRequest {
  const data = stateData(state);
  if (data.pending !== null) {
    throw new Error(
      'a committed Piano request is still pending; finish it or abandon it and rebuild'
    );
  }

  let kind: PianoRequestKind = 'retrieve';
  let effectiveIndex: number | null = null;
  let preflightFailure: PianoFailure | null = null;
  let applicationCachedRecord: Uint8Array | null = null;
  let setupMissRecord: Uint8Array | null = null;
  let hintIndex: number | null = null;
  let originalHintParity: Uint8Array | null = null;
  let backupTag: number | null = null;
  let backupParity: Uint8Array | null = null;
  let replacementIndex: number | null = null;
  let replacementValue: Uint8Array | null = null;
  let wire: Uint8Array;

  if (data.invalid !== null) {
    kind = 'dummy';
    preflightFailure = data.invalid;
    wire = dummyIndices(entropy);
  } else if (data.requestsSent >= PIANO_QUERY_WINDOW) {
    kind = 'dummy';
    preflightFailure = failure(
      'WINDOW_EXHAUSTED',
      `the bounded ${PIANO_QUERY_WINDOW}-request window is exhausted; rebuild before another real query`,
      true
    );
    invalidate(data, preflightFailure);
    wire = dummyIndices(entropy);
  } else if (
    !Number.isInteger(requestedIndex) ||
    requestedIndex < 0 ||
    requestedIndex >= PIANO_DATABASE_RECORDS
  ) {
    kind = 'dummy';
    preflightFailure = failure(
      'INDEX_OUT_OF_RANGE',
      `record ${requestedIndex} is outside 0 .. ${PIANO_DATABASE_RECORDS - 1}; one window slot was still spent on a fixed-shape cover request`,
      false
    );
    wire = dummyIndices(entropy);
  } else {
    const cached = data.cache.get(requestedIndex);
    if (cached) {
      kind = 'cached-cover';
      applicationCachedRecord = cached.slice();
      effectiveIndex = chooseUnusedTarget(data, entropy);
      if (effectiveIndex === null) {
        kind = 'dummy';
        preflightFailure = failure(
          'NO_COVER_TARGET',
          'no unused effective target remains for a cached-repeat cover query',
          true
        );
        invalidate(data, preflightFailure);
      }
    } else {
      effectiveIndex = requestedIndex;
    }

    if (effectiveIndex === null) {
      wire = dummyIndices(entropy);
    } else {
      // Commit the unique effective target BEFORE producing bytes to send.  It
      // can never be retried from this state, even if response parsing fails.
      data.consumedTargets[effectiveIndex] = 1;
      const localMiss = data.setupMisses.get(effectiveIndex);
      if (localMiss) {
        kind = applicationCachedRecord === null ? 'setup-miss' : 'cached-cover-setup-miss';
        setupMissRecord = localMiss.slice();
        // The target is committed now, not after a successful response.  The
        // request plan retains the exception record, so removing it here keeps
        // failed/abandoned serialized state canonical without enabling retry.
        data.setupMisses.delete(effectiveIndex);
        wire = dummyIndices(entropy);
      } else {
        hintIndex = data.primaryHints.findIndex((hint) =>
          hintContains(data, hint, effectiveIndex as number)
        );
        const chunk = Math.floor(effectiveIndex / PIANO_CHUNK_SIZE);
        const slot = data.consumedSlots[chunk];
        if (hintIndex < 0 || slot >= PIANO_BACKUPS_PER_CHUNK) {
          kind = 'dummy';
          const why = hintIndex < 0
            ? `no primary hint contains effective target ${effectiveIndex}`
            : `chunk ${chunk} has consumed all ${PIANO_BACKUPS_PER_CHUNK} refresh slots`;
          preflightFailure = failure('HINT_UNAVAILABLE', `${why}; rebuild is required`, true);
          invalidate(data, preflightFailure);
          wire = dummyIndices(entropy);
          hintIndex = null;
        } else {
          const hint = data.primaryHints[hintIndex];
          const backup = data.backupHints[chunk][slot];
          const replacement = data.replacements[chunk][slot];
          const indices = Uint8Array.from({ length: PIANO_CHUNK_COUNT }, (_, current) =>
            primaryIndexAtChunk(data, hint, current)
          );
          indices[chunk] = replacement.index;
          wire = serializePianoQuery(indices);

          // The paired backup and replacement are consumed before the request
          // leaves.  r==x and earlier replacement collisions remain untouched.
          data.consumedSlots[chunk] += 1;
          originalHintParity = hint.parity.slice();
          backupTag = backup.tag;
          backupParity = backup.parityAfterPuncture.slice();
          replacementIndex = replacement.index;
          replacementValue = replacement.value.slice();
        }
      }
    }
  }

  // Returning from this function is the send/commit boundary.  A caller that
  // loses the response must call abandonPianoRequest; there is no rollback API.
  data.requestsSent += 1;
  const plan: RequestPlan = {
    stateId: data.stateId.slice(),
    requestNumber: data.requestsSent,
    requestedIndex,
    effectiveIndex,
    kind,
    wire: parsePianoQuery(wire),
    preflightFailure,
    applicationCachedRecord,
    setupMissRecord,
    hintIndex,
    originalHintParity,
    backupTag,
    backupParity,
    replacementIndex,
    replacementValue,
  };
  const request = makeRequest(plan);
  data.pending = request;
  return request;
}

/**
 * Commit one live request.  No deterministic seed can cross this boundary.
 * The returned eight bytes should be sent exactly once.
 */
export function beginPianoQuery(
  state: PianoClientState,
  requestedIndex: number
): PianoPreparedRequest {
  return beginWithEntropy(state, requestedIndex, liveEntropy());
}

/** TEST ONLY: commit one request using deterministic/injected entropy. */
export function beginPianoQueryForTest(
  state: PianoClientState,
  requestedIndex: number,
  entropy: PianoTestEntropy
): PianoPreparedRequest {
  return beginWithEntropy(state, requestedIndex, entropy);
}

export interface PianoSuccessResult {
  readonly ok: true;
  readonly requestedIndex: number;
  readonly effectiveIndex: number;
  readonly kind: Exclude<PianoRequestKind, 'dummy'>;
  /** The record returned to the application (possibly its already-cached one). */
  readonly record: Uint8Array;
  /** The newly recovered effective target, including a cached-repeat cover. */
  readonly recoveredEffectiveRecord: Uint8Array;
  readonly fromApplicationCache: boolean;
}

export interface PianoFailureResult {
  readonly ok: false;
  readonly requestedIndex: number;
  readonly effectiveIndex: number | null;
  readonly kind: PianoRequestKind;
  readonly failure: PianoFailure;
}

export type PianoQueryResult = PianoSuccessResult | PianoFailureResult;

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i += 1) difference |= a[i] ^ b[i];
  return difference === 0;
}

/**
 * Accept one response and perform the exact recovery/refresh equations:
 *
 *   DB[x] = primaryParity XOR serverParity XOR DB[r]
 *   refreshedParity = backupParityAfterPuncture XOR DB[x]
 *
 * r=x is valid: the server parity then equals the primary parity and DB[x]
 * still survives through the retained replacement value.
 */
export function finishPianoQuery(
  state: PianoClientState,
  request: PianoPreparedRequest,
  responseBytes: Uint8Array
): PianoQueryResult {
  const data = stateData(state);
  const plan = requestPlan(request);
  if (data.pending !== request) {
    throw new Error('this Piano request is not the state\'s one committed pending request');
  }
  if (!sameBytes(plan.stateId, data.stateId)) {
    throw new Error('the Piano request belongs to a different setup epoch');
  }
  data.responseBytesReceived += responseBytes instanceof Uint8Array ? responseBytes.length : 0;

  let response: Uint8Array;
  try {
    response = parsePianoResponse(responseBytes);
  } catch (error) {
    data.pending = null;
    const malformed = failure(
      'MALFORMED_RESPONSE',
      `${error instanceof Error ? error.message : String(error)}; the committed epoch cannot be retried`,
      true
    );
    invalidate(data, malformed);
    return {
      ok: false,
      requestedIndex: plan.requestedIndex,
      effectiveIndex: plan.effectiveIndex,
      kind: plan.kind,
      failure: malformed,
    };
  }

  data.responsesAccepted += 1;
  data.pending = null;
  if (plan.preflightFailure !== null) {
    return {
      ok: false,
      requestedIndex: plan.requestedIndex,
      effectiveIndex: plan.effectiveIndex,
      kind: plan.kind,
      failure: plan.preflightFailure,
    };
  }
  // A known database change may be detected after this request was committed
  // but before its response arrives.  Parse and account for the fixed response
  // shape, then refuse to recover, refresh or cache against invalidated state.
  if (data.invalid !== null) {
    return {
      ok: false,
      requestedIndex: plan.requestedIndex,
      effectiveIndex: plan.effectiveIndex,
      kind: plan.kind,
      failure: data.invalid,
    };
  }
  if (plan.effectiveIndex === null) {
    const impossible = failure('STATE_INVALID', 'a committed request lost its effective target', true);
    invalidate(data, impossible);
    return {
      ok: false,
      requestedIndex: plan.requestedIndex,
      effectiveIndex: null,
      kind: plan.kind,
      failure: impossible,
    };
  }

  let recovered: Uint8Array;
  if (plan.setupMissRecord !== null) {
    // The response is intentionally ignored only AFTER its fixed shape was
    // parsed.  The committed plan retained this rare missing record locally.
    recovered = plan.setupMissRecord.slice();
  } else {
    if (
      plan.hintIndex === null ||
      plan.originalHintParity === null ||
      plan.backupTag === null ||
      plan.backupParity === null ||
      plan.replacementValue === null
    ) {
      const impossible = failure('STATE_INVALID', 'the recovery plan is incomplete', true);
      invalidate(data, impossible);
      return {
        ok: false,
        requestedIndex: plan.requestedIndex,
        effectiveIndex: plan.effectiveIndex,
        kind: plan.kind,
        failure: impossible,
      };
    }
    recovered = xorThree(plan.originalHintParity, response, plan.replacementValue);
    const refreshed = plan.backupParity.slice();
    xorInto(refreshed, recovered);
    const hint = data.primaryHints[plan.hintIndex];
    hint.tag = plan.backupTag;
    hint.parity = refreshed;
    hint.programmedTarget = plan.effectiveIndex;
  }

  data.cache.set(plan.effectiveIndex, recovered.slice());
  const applicationRecord = plan.applicationCachedRecord?.slice() ?? recovered.slice();
  return {
    ok: true,
    requestedIndex: plan.requestedIndex,
    effectiveIndex: plan.effectiveIndex,
    kind: plan.kind as Exclude<PianoRequestKind, 'dummy'>,
    record: applicationRecord,
    recoveredEffectiveRecord: recovered.slice(),
    fromApplicationCache: plan.applicationCachedRecord !== null,
  };
}

/**
 * A missing response consumes the committed request and invalidates the epoch.
 * Reusing its old hint/replacement state would make a retry linkable.
 */
export function abandonPianoRequest(
  state: PianoClientState,
  request: PianoPreparedRequest
): PianoFailure {
  const data = stateData(state);
  if (data.pending !== request) {
    throw new Error('this Piano request is not pending');
  }
  data.pending = null;
  const abandoned = failure(
    'REQUEST_ABANDONED',
    'a committed request lost its response; any target and refresh slot committed by that plan stay consumed and the epoch must be rebuilt',
    true
  );
  invalidate(data, abandoned);
  return abandoned;
}

export interface PianoDetachedDummyRequest {
  readonly wire: Uint8Array;
  readonly failure: PianoFailure;
}

function stateLossRequest(entropy: PianoEntropy): PianoDetachedDummyRequest {
  return {
    wire: serializePianoQuery(dummyIndices(entropy)),
    failure: failure(
      'STATE_LOST',
      'the PRF key, parities, replacements and cache are gone; a fixed-shape request can hide this event but cannot recover a record',
      true
    ),
  };
}

/** Live fixed-shape request for the lost-client-state lesson. */
export function makePianoStateLossRequest(): PianoDetachedDummyRequest {
  return stateLossRequest(liveEntropy());
}

/** TEST ONLY: deterministic fixed-shape request for the lost-state lesson. */
export function makePianoStateLossRequestForTest(
  entropy: PianoTestEntropy
): PianoDetachedDummyRequest {
  return stateLossRequest(entropy);
}

/**
 * Known database changes invalidate every hint, replacement and cached record.
 * An unseen malicious update remains outside this honest-but-curious model; the
 * SHA-256 binding is a state/version check, not a verifiable-PIR proof.
 */
export async function verifyPianoDatabaseCurrent(
  state: PianoClientState,
  database: readonly Uint8Array[]
): Promise<boolean> {
  const data = stateData(state);
  const current = await fingerprintPianoDatabase(database);
  if (sameBytes(current, data.databaseDigest)) return true;
  invalidate(
    data,
    failure(
      'DATABASE_UPDATED',
      'the ordered database digest changed; all hints, replacements and cached values are stale and a full preprocessing stream is required',
      true
    )
  );
  return false;
}

const STATE_MAGIC = [0x53, 0x4f, 0x50, 0x4e] as const; // "SOPN"
const STATE_VERSION = 1;
const STATE_HEADER_BYTES = 128;
const PRIMARY_BYTES = 2 + 1 + PIANO_RECORD_BYTES;
const BACKUP_BYTES = 2 + PIANO_RECORD_BYTES;
const REPLACEMENT_BYTES = 1 + PIANO_RECORD_BYTES;
export const PIANO_CACHE_ENTRY_BYTES = 1 + PIANO_RECORD_BYTES;
export const PIANO_MAX_NORMAL_CACHE_BYTES =
  PIANO_QUERY_WINDOW * PIANO_CACHE_ENTRY_BYTES; // 16,929, never 64 records.

/** Fixed state bytes before the sparse query cache and setup-miss cache. */
export const PIANO_BASE_STATE_BYTES =
  STATE_HEADER_BYTES +
  PIANO_PRIMARY_HINTS * PRIMARY_BYTES +
  PIANO_CHUNK_COUNT * PIANO_BACKUPS_PER_CHUNK * BACKUP_BYTES +
  PIANO_CHUNK_COUNT * PIANO_BACKUPS_PER_CHUNK * REPLACEMENT_BYTES;

const STATUS_TO_BYTE: Readonly<Record<string, number>> = Object.freeze({
  DATABASE_UPDATED: 1,
  ROLLBACK_DETECTED: 2,
  MALFORMED_RESPONSE: 3,
  REQUEST_ABANDONED: 4,
  HINT_UNAVAILABLE: 5,
  WINDOW_EXHAUSTED: 6,
  NO_COVER_TARGET: 7,
  STATE_INVALID: 8,
});

const BYTE_TO_STATUS: Readonly<Record<number, PianoFailureCode>> = Object.freeze({
  1: 'DATABASE_UPDATED',
  2: 'ROLLBACK_DETECTED',
  3: 'MALFORMED_RESPONSE',
  4: 'REQUEST_ABANDONED',
  5: 'HINT_UNAVAILABLE',
  6: 'WINDOW_EXHAUSTED',
  7: 'NO_COVER_TARGET',
  8: 'STATE_INVALID',
});

function sortedEntries(map: ReadonlyMap<number, Uint8Array>): Array<[number, Uint8Array]> {
  return [...map.entries()].sort((a, b) => a[0] - b[0]);
}

function stateSerializedBytes(data: StateData): number {
  return (
    PIANO_BASE_STATE_BYTES +
    (data.cache.size + data.setupMisses.size) * PIANO_CACHE_ENTRY_BYTES
  );
}

/**
 * Canonical retained-state encoding.  This is private client persistence, NOT
 * a network protocol.  It deliberately includes the secret PRF key and has no
 * tamper protection; a deployment would need authenticated protected storage.
 */
export function serializePianoState(state: PianoClientState): Uint8Array {
  const data = stateData(state);
  if (data.pending !== null) {
    throw new Error('cannot serialize while a committed request is awaiting its response');
  }
  if (data.cache.size > PIANO_DATABASE_RECORDS || data.setupMisses.size > PIANO_DATABASE_RECORDS) {
    throw new Error('Piano sparse-cache dimensions are invalid');
  }
  const out = new Uint8Array(stateSerializedBytes(data));
  const view = new DataView(out.buffer);
  out.set(STATE_MAGIC, 0);
  view.setUint8(4, STATE_VERSION);
  view.setUint8(5, data.invalid === null ? 0 : (STATUS_TO_BYTE[data.invalid.code] ?? 8));
  // bytes 6..7 and 118..127 stay canonical zero.
  out.set(data.databaseDigest, 8);
  out.set(data.stateId, 40);
  out.set(data.prfKey, 56);
  view.setUint32(88, data.requestsSent, true);
  view.setUint32(92, data.responsesAccepted, true);
  view.setUint32(96, data.responseBytesReceived, true);
  view.setUint8(100, data.cache.size);
  view.setUint8(101, data.setupMisses.size);
  out.set(data.consumedSlots, 102);
  for (let i = 0; i < PIANO_DATABASE_RECORDS; i += 1) {
    if (data.consumedTargets[i]) out[110 + (i >> 3)] |= 1 << (i & 7);
  }

  let offset = STATE_HEADER_BYTES;
  for (const hint of data.primaryHints) {
    view.setUint16(offset, hint.tag, true);
    view.setUint8(offset + 2, hint.programmedTarget ?? 0xff);
    out.set(hint.parity, offset + 3);
    offset += PRIMARY_BYTES;
  }
  for (const group of data.backupHints) {
    for (const hint of group) {
      view.setUint16(offset, hint.tag, true);
      out.set(hint.parityAfterPuncture, offset + 2);
      offset += BACKUP_BYTES;
    }
  }
  for (const group of data.replacements) {
    for (const replacement of group) {
      view.setUint8(offset, replacement.index);
      out.set(replacement.value, offset + 1);
      offset += REPLACEMENT_BYTES;
    }
  }
  for (const entries of [sortedEntries(data.cache), sortedEntries(data.setupMisses)]) {
    for (const [index, record] of entries) {
      view.setUint8(offset, index);
      out.set(record, offset + 1);
      offset += PIANO_CACHE_ENTRY_BYTES;
    }
  }
  if (offset !== out.length) throw new Error('internal Piano state-size mismatch');
  return out;
}

export interface PianoStateAnchor {
  readonly stateId: Uint8Array;
  readonly minimumGeneration: number;
}

/**
 * A high-water mark that MUST live outside the serialized state it protects.
 * It warns about old snapshots; it is not an authenticated-storage mechanism.
 */
export function pianoStateAnchor(state: PianoClientState): PianoStateAnchor {
  const data = stateData(state);
  return { stateId: data.stateId.slice(), minimumGeneration: data.requestsSent };
}

function invalidFromStatus(status: number): PianoFailure | null {
  if (status === 0) return null;
  const code = BYTE_TO_STATUS[status];
  if (!code) throw new RangeError(`unknown Piano state status ${status}`);
  return failure(code, `restored state is marked ${code}`, true);
}

function readSparseEntries(
  bytes: Uint8Array,
  offset: number,
  count: number,
  label: string
): { map: Map<number, Uint8Array>; offset: number } {
  const map = new Map<number, Uint8Array>();
  let previous = -1;
  for (let i = 0; i < count; i += 1) {
    const index = bytes[offset];
    if (index >= PIANO_DATABASE_RECORDS || index <= previous) {
      throw new RangeError(`${label} indices are not canonical ascending distinct bytes`);
    }
    previous = index;
    map.set(index, bytes.slice(offset + 1, offset + PIANO_CACHE_ENTRY_BYTES));
    offset += PIANO_CACHE_ENTRY_BYTES;
  }
  return { map, offset };
}

/** Parse one canonical encoding and validate its structural/state-counter invariants. */
export function deserializePianoState(
  bytes: Uint8Array,
  anchor?: PianoStateAnchor
): PianoClientState {
  if (!(bytes instanceof Uint8Array) || bytes.length < PIANO_BASE_STATE_BYTES) {
    throw new RangeError('Piano state payload is truncated');
  }
  for (let i = 0; i < STATE_MAGIC.length; i += 1) {
    if (bytes[i] !== STATE_MAGIC[i]) throw new RangeError('Piano state has the wrong magic');
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint8(4) !== STATE_VERSION) {
    throw new RangeError(`unsupported Piano state version ${view.getUint8(4)}`);
  }
  if (bytes[6] !== 0 || bytes[7] !== 0) {
    throw new RangeError('Piano state header uses noncanonical reserved bytes');
  }
  for (let i = 118; i < STATE_HEADER_BYTES; i += 1) {
    if (bytes[i] !== 0) throw new RangeError('Piano state header uses noncanonical reserved bytes');
  }
  const invalid = invalidFromStatus(view.getUint8(5));
  const databaseDigest = bytes.slice(8, 40);
  const stateId = bytes.slice(40, 56);
  const prfKey = bytes.slice(56, 88);
  const requestsSent = view.getUint32(88, true);
  const responsesAccepted = view.getUint32(92, true);
  const responseBytesReceived = view.getUint32(96, true);
  const cacheCount = view.getUint8(100);
  const missCount = view.getUint8(101);
  if (responsesAccepted > requestsSent) {
    throw new RangeError('Piano state accepts more responses than committed requests');
  }
  if (responseBytesReceived < responsesAccepted * PIANO_RESPONSE_BYTES) {
    throw new RangeError('Piano state records fewer bytes than its accepted responses require');
  }
  if (invalid === null && responsesAccepted !== requestsSent) {
    throw new RangeError('valid Piano state has a committed request without an accepted response');
  }
  if (
    invalid === null &&
    responseBytesReceived !== responsesAccepted * PIANO_RESPONSE_BYTES
  ) {
    throw new RangeError('valid Piano state has a noncanonical response-byte total');
  }
  if (cacheCount > PIANO_QUERY_WINDOW || cacheCount > requestsSent) {
    throw new RangeError('Piano normal cache exceeds the bounded committed query history');
  }
  if (invalid === null && requestsSent > PIANO_QUERY_WINDOW) {
    throw new RangeError('Piano state exceeds its query window without an invalid status');
  }
  const expected =
    PIANO_BASE_STATE_BYTES + (cacheCount + missCount) * PIANO_CACHE_ENTRY_BYTES;
  if (bytes.length !== expected) {
    throw new RangeError(`Piano state has ${bytes.length} bytes; expected exactly ${expected}`);
  }
  const consumedSlots = bytes.slice(102, 110);
  for (const count of consumedSlots) {
    if (count > PIANO_BACKUPS_PER_CHUNK) {
      throw new RangeError('Piano state consumes more refresh slots than exist');
    }
  }
  const consumedTargets = new Uint8Array(PIANO_DATABASE_RECORDS);
  let consumedTargetCount = 0;
  const consumedTargetsByChunk = new Uint8Array(PIANO_CHUNK_COUNT);
  for (let i = 0; i < PIANO_DATABASE_RECORDS; i += 1) {
    consumedTargets[i] = (bytes[110 + (i >> 3)] >> (i & 7)) & 1;
    consumedTargetCount += consumedTargets[i];
    consumedTargetsByChunk[Math.floor(i / PIANO_CHUNK_SIZE)] += consumedTargets[i];
  }
  if (consumedTargetCount > PIANO_QUERY_WINDOW || consumedTargetCount > requestsSent) {
    throw new RangeError('Piano consumed-target bitmap exceeds its bounded query history');
  }
  let consumedSlotCount = 0;
  for (let chunk = 0; chunk < consumedSlots.length; chunk += 1) {
    const count = consumedSlots[chunk];
    consumedSlotCount += count;
    if (count > consumedTargetsByChunk[chunk]) {
      throw new RangeError(`chunk ${chunk} consumes more refresh slots than effective targets`);
    }
  }
  if (consumedSlotCount > consumedTargetCount) {
    throw new RangeError('Piano refresh-slot consumption exceeds effective targets');
  }

  let offset = STATE_HEADER_BYTES;
  const primaryHints: PrimaryHint[] = [];
  const activeTags = new Set<number>();
  for (let i = 0; i < PIANO_PRIMARY_HINTS; i += 1) {
    const tag = view.getUint16(offset, true);
    const encodedProgrammed = view.getUint8(offset + 2);
    if (tag >= PIANO_PRIMARY_HINTS + PIANO_CHUNK_COUNT * PIANO_BACKUPS_PER_CHUNK) {
      throw new RangeError(`primary hint tag ${tag} is outside the bounded setup`);
    }
    if (activeTags.has(tag)) throw new RangeError(`duplicate active primary hint tag ${tag}`);
    activeTags.add(tag);
    const programmedTarget = encodedProgrammed === 0xff ? null : encodedProgrammed;
    if (programmedTarget !== null && programmedTarget >= PIANO_DATABASE_RECORDS) {
      throw new RangeError(`programmed target ${programmedTarget} is outside the database`);
    }
    if ((tag < PIANO_PRIMARY_HINTS) !== (programmedTarget === null)) {
      throw new RangeError('primary hint tag/programming state is noncanonical');
    }
    if (programmedTarget !== null) {
      const tagChunk = Math.floor((tag - PIANO_PRIMARY_HINTS) / PIANO_BACKUPS_PER_CHUNK);
      const tagSlot = (tag - PIANO_PRIMARY_HINTS) % PIANO_BACKUPS_PER_CHUNK;
      const targetChunk = Math.floor(programmedTarget / PIANO_CHUNK_SIZE);
      if (tagChunk !== targetChunk) {
        throw new RangeError('programmed target does not match its punctured backup group');
      }
      if (tagSlot >= consumedSlots[tagChunk]) {
        throw new RangeError('active backup tag is outside its group\'s consumed prefix');
      }
      if (consumedTargets[programmedTarget] === 0) {
        throw new RangeError('programmed target is not marked as consumed');
      }
    }
    primaryHints.push({
      tag,
      programmedTarget,
      parity: bytes.slice(offset + 3, offset + PRIMARY_BYTES),
    });
    offset += PRIMARY_BYTES;
  }

  const backupHints: BackupHint[][] = [];
  for (let chunk = 0; chunk < PIANO_CHUNK_COUNT; chunk += 1) {
    const group: BackupHint[] = [];
    for (let slot = 0; slot < PIANO_BACKUPS_PER_CHUNK; slot += 1) {
      const tag = view.getUint16(offset, true);
      const expectedTag =
        PIANO_PRIMARY_HINTS + chunk * PIANO_BACKUPS_PER_CHUNK + slot;
      if (tag !== expectedTag) throw new RangeError('backup hint tags are not canonical');
      group.push({
        tag,
        parityAfterPuncture: bytes.slice(offset + 2, offset + BACKUP_BYTES),
      });
      offset += BACKUP_BYTES;
    }
    backupHints.push(group);
  }

  const replacements: Replacement[][] = [];
  for (let chunk = 0; chunk < PIANO_CHUNK_COUNT; chunk += 1) {
    const group: Replacement[] = [];
    for (let slot = 0; slot < PIANO_BACKUPS_PER_CHUNK; slot += 1) {
      const index = view.getUint8(offset);
      if (Math.floor(index / PIANO_CHUNK_SIZE) !== chunk) {
        throw new RangeError('replacement index is outside its chunk');
      }
      group.push({ index, value: bytes.slice(offset + 1, offset + REPLACEMENT_BYTES) });
      offset += REPLACEMENT_BYTES;
    }
    replacements.push(group);
  }

  const cacheRead = readSparseEntries(bytes, offset, cacheCount, 'cache');
  const cache = cacheRead.map;
  offset = cacheRead.offset;
  const missesRead = readSparseEntries(bytes, offset, missCount, 'setup-miss cache');
  const setupMisses = missesRead.map;
  offset = missesRead.offset;
  for (const index of cache.keys()) {
    if (setupMisses.has(index)) throw new RangeError('cache and setup-miss cache overlap');
    if (consumedTargets[index] === 0) {
      throw new RangeError('a normal cache entry has no consumed effective target');
    }
  }
  for (const index of setupMisses.keys()) {
    if (consumedTargets[index] !== 0) {
      throw new RangeError('an unconsumed setup-miss entry is marked as an effective target');
    }
  }
  if (invalid === null) {
    for (let index = 0; index < PIANO_DATABASE_RECORDS; index += 1) {
      if ((consumedTargets[index] === 1) !== cache.has(index)) {
        throw new RangeError('valid state does not cache every consumed effective target');
      }
    }
  }
  if (offset !== bytes.length) throw new RangeError('Piano state has trailing bytes');

  const data: StateData = {
    databaseDigest,
    stateId,
    prfKey,
    primaryHints,
    backupHints,
    replacements,
    consumedSlots,
    consumedTargets,
    cache,
    setupMisses,
    requestsSent,
    responsesAccepted,
    responseBytesReceived,
    invalid,
    pending: null,
  };
  if (
    anchor &&
    (!(anchor.stateId instanceof Uint8Array) ||
      anchor.stateId.length !== 16 ||
      !Number.isInteger(anchor.minimumGeneration) ||
      anchor.minimumGeneration < 0)
  ) {
    throw new RangeError('Piano rollback anchor is malformed');
  }
  if (anchor && (!sameBytes(anchor.stateId, stateId) || requestsSent < anchor.minimumGeneration)) {
    data.invalid = failure(
      'ROLLBACK_DETECTED',
      `restored generation ${requestsSent} is older than the external high-water mark ${anchor.minimumGeneration}, or belongs to another setup; rebuild before sending a real query`,
      true
    );
  }
  return makeState(data);
}

export interface PianoStateMetrics {
  readonly valid: boolean;
  readonly invalidReason: PianoFailure | null;
  readonly requestPending: boolean;
  readonly requestsSent: number;
  readonly responsesAccepted: number;
  readonly responseBytesReceived: number;
  readonly effectiveTargetsConsumed: number;
  readonly remainingWindow: number;
  readonly cachedRecords: number;
  readonly setupMissRecords: number;
  readonly cacheBytes: number;
  readonly retainedStateBytes: number;
  readonly committedUploadBytes: number;
  readonly committedServerRecordProbes: number;
}

export function pianoStateMetrics(state: PianoClientState): PianoStateMetrics {
  const data = stateData(state);
  let effectiveTargetsConsumed = 0;
  for (const used of data.consumedTargets) effectiveTargetsConsumed += used;
  return {
    valid: data.invalid === null,
    invalidReason: data.invalid,
    requestPending: data.pending !== null,
    requestsSent: data.requestsSent,
    responsesAccepted: data.responsesAccepted,
    responseBytesReceived: data.responseBytesReceived,
    effectiveTargetsConsumed,
    remainingWindow: Math.max(0, PIANO_QUERY_WINDOW - data.requestsSent),
    cachedRecords: data.cache.size,
    setupMissRecords: data.setupMisses.size,
    cacheBytes: data.cache.size * PIANO_CACHE_ENTRY_BYTES,
    retainedStateBytes: stateSerializedBytes(data),
    committedUploadBytes: data.requestsSent * PIANO_QUERY_BYTES,
    committedServerRecordProbes: data.requestsSent * PIANO_CHUNK_COUNT,
  };
}

export interface PianoAuditSnapshot {
  readonly databaseDigest: Uint8Array;
  readonly stateId: Uint8Array;
  readonly prfKey: Uint8Array;
  readonly primaryHints: readonly {
    readonly tag: number;
    readonly parity: Uint8Array;
    readonly programmedTarget: number | null;
  }[];
  readonly backupHints: readonly (readonly {
    readonly tag: number;
    readonly parityAfterPuncture: Uint8Array;
  }[])[];
  readonly replacements: readonly (readonly {
    readonly index: number;
    readonly value: Uint8Array;
  }[])[];
  readonly consumedSlots: Uint8Array;
  readonly consumedTargets: readonly number[];
  readonly cache: ReadonlyMap<number, Uint8Array>;
  readonly setupMisses: ReadonlyMap<number, Uint8Array>;
}

/**
 * Copy the secret teaching state for independent tests/instrumentation.  Never
 * send this snapshot to the server; it contains the key that defines every set.
 */
export function auditPianoState(state: PianoClientState): PianoAuditSnapshot {
  const data = stateData(state);
  const copyMap = (source: ReadonlyMap<number, Uint8Array>): Map<number, Uint8Array> =>
    new Map([...source].map(([index, record]) => [index, record.slice()]));
  const consumedTargets: number[] = [];
  for (let i = 0; i < data.consumedTargets.length; i += 1) {
    if (data.consumedTargets[i]) consumedTargets.push(i);
  }
  return {
    databaseDigest: data.databaseDigest.slice(),
    stateId: data.stateId.slice(),
    prfKey: data.prfKey.slice(),
    primaryHints: data.primaryHints.map((hint) => ({
      tag: hint.tag,
      parity: hint.parity.slice(),
      programmedTarget: hint.programmedTarget,
    })),
    backupHints: data.backupHints.map((group) =>
      group.map((hint) => ({
        tag: hint.tag,
        parityAfterPuncture: hint.parityAfterPuncture.slice(),
      }))
    ),
    replacements: data.replacements.map((group) =>
      group.map((replacement) => ({
        index: replacement.index,
        value: replacement.value.slice(),
      }))
    ),
    consumedSlots: data.consumedSlots.slice(),
    consumedTargets,
    cache: copyMap(data.cache),
    setupMisses: copyMap(data.setupMisses),
  };
}
