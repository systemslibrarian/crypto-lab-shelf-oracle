import { entryText, shelfEntries, type ShelfEntry } from '../data/catalog';
import {
  PIANO_BACKUPS_PER_CHUNK,
  PIANO_BASE_STATE_BYTES,
  PIANO_CACHE_ENTRY_BYTES,
  PIANO_CHUNK_COUNT,
  PIANO_CHUNK_SIZE,
  PIANO_DATABASE_RECORDS,
  PIANO_PRIMARY_HINTS,
  PIANO_QUERY_BYTES,
  PIANO_QUERY_WINDOW,
  PIANO_RECORD_BYTES,
  PIANO_RESPONSE_BYTES,
  PIANO_SETUP_COSTS,
  auditPianoRequest,
  auditPianoState,
  beginPianoQuery,
  finishPianoQuery,
  makePianoStateLossRequest,
  pianoAvailabilityBounds,
  pianoCostForQueries,
  pianoServerAnswer,
  pianoStateMetrics,
  preprocessPiano,
  serializePianoRequest,
  verifyPianoDatabaseCurrent,
  type PianoClientState,
  type PianoFailureCode,
  type PianoRequestAuditSnapshot,
  type PianoRequestKind,
  type PianoSuccessResult,
} from '../pir/piano';
import { buildRecord, tagMatches } from '../pir/records';
import {
  append,
  card,
  clear,
  disclose,
  el,
  formatBytes,
  kv,
  nextFrame,
  panelStatus,
  scroller,
  verdict,
  withFocusRestored,
} from './dom';
import type { Lab } from './state';

/**
 * A bounded, stateful preprocessing-PIR lesson over a fixed public database.
 *
 * This panel intentionally does not reuse Lab.random.  A pinned lab seed is a
 * useful reproducibility control for the BFV exhibits, but it would publish the
 * Piano client's secret PRF key, hint choices and replacements.  Every live
 * setup and cover query here crosses the WebCrypto entropy boundary in
 * `piano.ts` instead.
 *
 * The module-level state is also deliberate.  main.ts may rebuild this panel
 * when a book is selected or another lab parameter changes; retained Piano
 * state survives those view renders because changing the selection is not a
 * protocol reset.  Only the learner-visible loss, update and rebuild controls
 * change the setup epoch.
 */

const FIXED_ENTRIES: readonly ShelfEntry[] = shelfEntries(PIANO_DATABASE_RECORDS);

interface ExchangeView {
  readonly requestedIndex: number | null;
  readonly effectiveIndex: number | null;
  readonly kind: PianoRequestKind;
  readonly wire: Uint8Array;
  readonly responseBytes: number;
  readonly responseHead: string;
  readonly hintIndex: number | null;
  readonly replacementIndex: number | null;
  readonly fromApplicationCache: boolean;
  readonly applicationRecordMatches: boolean | null;
  readonly effectiveRecordMatches: boolean | null;
  readonly applicationTagMatches: boolean | null;
  readonly failureCode: PianoFailureCode | null;
  readonly failureDetail: string | null;
  readonly equation: EquationView;
}

interface EquationView {
  readonly route: 'parity-refresh' | 'setup-miss' | 'none';
  readonly primaryHead: string | null;
  readonly responseHead: string | null;
  readonly replacementHead: string | null;
  readonly recoveredHead: string | null;
  readonly recoveryMatches: boolean | null;
  readonly backupTag: number | null;
  readonly backupSlot: number | null;
  readonly backupHead: string | null;
  readonly refreshedHead: string | null;
  readonly refreshMatches: boolean | null;
}

interface UpdateView {
  readonly index: number;
  readonly title: string;
  readonly diagnosticTarget: number;
  readonly retainedReplacementMatchedOldRecord: boolean;
  readonly oldAndNewDiffer: boolean;
  readonly oldTagStillValid: boolean;
  readonly newTagValid: boolean;
  readonly staleRecoveredMatchesCurrent: boolean;
  readonly staleRecoveredTagMatches: boolean;
  readonly digestDetectedChange: boolean;
  recoveredAfterRebuild: boolean;
}

interface ExecutedCosts {
  setupRuns: number;
  setupStreamBytes: number;
  setupRecordReads: number;
  setupParityRecordXors: number;
  replacementRecordCopies: number;
  onlineRequests: number;
  onlineUploadBytes: number;
  onlineDownloadBytes: number;
  onlineServerRecordProbes: number;
  onlineServerParityRecordXors: number;
  databaseDigestScans: number;
  databaseDigestBytes: number;
}

interface PanelState {
  database: Uint8Array[] | null;
  client: PianoClientState | null;
  busy: boolean;
  stage: string | null;
  notice: string;
  error: string | null;
  lostState: boolean;
  last: ExchangeView | null;
  update: UpdateView | null;
  costs: ExecutedCosts;
}

const state: PanelState = {
  database: null,
  client: null,
  busy: false,
  stage: null,
  notice: 'No preprocessing has run. The server has received no Piano request.',
  error: null,
  lostState: false,
  last: null,
  update: null,
  costs: {
    setupRuns: 0,
    setupStreamBytes: 0,
    setupRecordReads: 0,
    setupParityRecordXors: 0,
    replacementRecordCopies: 0,
    onlineRequests: 0,
    onlineUploadBytes: 0,
    onlineDownloadBytes: 0,
    onlineServerRecordProbes: 0,
    onlineServerParityRecordXors: 0,
    databaseDigestScans: 0,
    databaseDigestBytes: 0,
  },
};

export function renderStateful(root: HTMLElement, lab: Lab): void {
  clear(root);
  const selected = lab.snapshot().selectedIndex;
  const inRange = selected >= 0 && selected < PIANO_DATABASE_RECORDS;
  const metrics = state.client ? pianoStateMetrics(state.client) : null;
  const cached =
    state.client !== null && inRange
      ? auditPianoState(state.client).cache.has(selected)
      : false;

  append(
    root,
    card('Run the bounded stateful lesson', [
      el(
        'p',
        { class: 'lede' },
        `This executable Piano-style adaptation fixes a public database at ${PIANO_DATABASE_RECORDS} ` +
          `${PIANO_RECORD_BYTES}-byte records. A client-specific setup streams the whole database once, ` +
          `retains secret parity hints and replacement records, and then asks with one index from each ` +
          `of ${PIANO_CHUNK_COUNT} chunks. The server has no preprocessing phase: ProcessDB is the ` +
          `identity/none, and it keeps only the ordinary public database.`
      ),
      selectedReadout(selected, inRange),
      el('div', { class: 'controls' }, [
        el(
          'button',
          {
            class: 'btn btn-primary',
            type: 'button',
            'data-role': 'stateful-setup',
            disabled:
              state.busy || !!(state.update && !state.update.recoveredAfterRebuild),
          },
          setupLabel()
        ),
        el(
          'button',
          {
            class: 'btn',
            type: 'button',
            'data-role': 'stateful-query',
            disabled: state.busy || !state.client || !inRange,
          },
          'Query selected record'
        ),
        el(
          'button',
          {
            class: 'btn',
            type: 'button',
            'data-role': 'stateful-repeat',
            disabled: state.busy || !state.client || !inRange || !cached || metrics?.valid === false,
          },
          'Repeat with a real cover query'
        ),
        el(
          'button',
          {
            class: 'btn btn-danger',
            type: 'button',
            'data-role': 'stateful-lose',
            disabled: state.busy || !state.client,
          },
          'Lose client state and send cover'
        ),
        el(
          'button',
          {
            class: 'btn btn-danger',
            type: 'button',
            'data-role': 'stateful-update',
            disabled:
              state.busy ||
              !state.client ||
              !inRange ||
              !!state.update ||
              metrics?.valid === false,
          },
          'Run controlled retained-state update diagnostic'
        ),
        el(
          'button',
          {
            class: 'btn',
            type: 'button',
            'data-role': 'stateful-recover-update',
            disabled:
              state.busy || !state.update || state.update.recoveredAfterRebuild,
          },
          'Full rebuild and recover changed record'
        ),
      ]),
      state.busy
        ? el('p', { class: 'status-line', 'data-role': 'stateful-stage' }, state.stage ?? 'Working…')
        : currentVerdict(metrics),
      el(
        'p',
        { class: 'inline-note' },
        `The shelf selection chooses the application target but does not reset this client's ` +
          `state. The lab's optional reproducible seed never controls this panel: live setup keys, ` +
          `hint coordinates, replacements and cover targets always use platform entropy.`
      ),
    ])
  );

  append(root, card('What crossed the server boundary', exchangeOutput()));
  append(root, card('Client state and update evidence', stateOutput(metrics)));
  append(root, card('Protocol cost ledger from executed actions', costOutput(metrics)));
  append(root, card('Exact model, exact limit', modelOutput()));

  announce(root, state.busy ? state.stage ?? 'Working.' : state.notice);
  bind(root, lab);
}

function selectedReadout(selected: number, inRange: boolean): HTMLElement {
  if (!inRange) {
    return verdict('alarm', [
      el('strong', {}, `Shelf position ${selected} is outside this fixed database. `),
      `Choose a position from 0 through ${PIANO_DATABASE_RECORDS - 1}; the bounded lesson does not ` +
        `silently tile or resize its database. Existing client state remains intact.`,
    ]);
  }
  const entry = FIXED_ENTRIES[selected];
  return kv([
    ['Current application target', `${selected} — ${entry.title}`],
    ['Target visibility', 'client-local; it is not a request field'],
    ['Database shape', `${PIANO_DATABASE_RECORDS} records × ${PIANO_RECORD_BYTES} bytes`],
    ['Online shape', `${PIANO_QUERY_BYTES} B upload + ${PIANO_RESPONSE_BYTES} B response`],
    ['Wire codec', 'lab-specific one-byte indices; not the reference implementation\'s uint64/protobuf encoding'],
  ]);
}

function setupLabel(): string {
  if (state.busy) return 'Working…';
  if (state.lostState || (state.update && !state.update.recoveredAfterRebuild)) return 'Full rebuild';
  if (state.client) return 'Start a fresh setup epoch';
  return 'Preprocess 64 records';
}

function currentVerdict(metrics: ReturnType<typeof pianoStateMetrics> | null): HTMLElement {
  if (state.error) {
    return verdict('fail', [el('strong', {}, 'The operation stopped. '), state.error]);
  }
  if (!state.client) {
    return verdict(state.lostState ? 'alarm' : 'info', state.notice);
  }
  if (!metrics?.valid) {
    return verdict('alarm', [
      el('strong', { class: 'fail-code' }, `${metrics?.invalidReason?.code ?? 'STATE_INVALID'}: `),
      metrics?.invalidReason?.detail ?? state.notice,
    ]);
  }
  return verdict('pass', state.notice);
}

function exchangeOutput(): HTMLElement {
  const last = state.last;
  if (!last) {
    return el('div', {}, [
      el(
        'p',
        { class: 'status-line', 'data-role': 'stateful-transcript-empty' },
        'No online request is retained for the current epoch. Preprocessing is client work and sends no Piano query.'
      ),
      verdict(
        'info',
        `Every online path, including cached repeats, lost state and locally detected invalid ` +
          `state, sends exactly ${PIANO_QUERY_BYTES} bytes and receives exactly ` +
          `${PIANO_RESPONSE_BYTES} bytes in this lesson.`
      ),
    ]);
  }

  const serverTable = el('table', { class: 'data', 'data-role': 'stateful-server-transcript' }, [
    el(
      'caption',
      {},
      'Server-visible request fields and message shape. No separately labelled target, chunk label, hint id, cache flag, dummy flag or revision accompanies these bytes.'
    ),
    el('thead', {}, el('tr', {}, [el('th', {}, 'Server sees'), el('th', {}, 'Executed value')])),
    el('tbody', {}, [
      row('Canonical query', `${last.wire.length} B`),
      row('Eight one-byte indices', last.wire.join(' · '), 'stateful-server-indices'),
      row('Response', `${last.responseBytes} B`),
      row('Response head', last.responseHead),
      row('Database probes', `${PIANO_CHUNK_COUNT} records, one per chunk`),
      row('Server XOR contributions', `${PIANO_CHUNK_COUNT} record contributions`),
    ]),
  ]);

  const localRows: Array<[string, string]> = [
    ['Application target', last.requestedIndex === null ? 'client state was lost' : String(last.requestedIndex)],
    ['Effective target', last.effectiveIndex === null ? 'none; cover only' : String(last.effectiveIndex)],
    ['Local route', last.kind],
    ['Application cache used', last.fromApplicationCache ? 'yes' : 'no'],
    ['Primary hint slot', last.hintIndex === null ? 'none' : String(last.hintIndex)],
    ['Replacement r', last.replacementIndex === null ? 'none' : String(last.replacementIndex)],
  ];
  if (last.replacementIndex !== null && last.effectiveIndex !== null) {
    localRows.push([
      'Was r = x?',
      last.replacementIndex === last.effectiveIndex
        ? 'yes — valid; the recovery equation still holds'
        : 'no — equality is allowed, never resampled away',
    ]);
  }

  const setupMiss =
    last.kind === 'setup-miss' || last.kind === 'cached-cover-setup-miss';
  const successLead = setupMiss
    ? last.fromApplicationCache
      ? 'Cached application record returned; the cover target came from the local setup-miss exception cache after the fixed response was parsed and ignored. '
      : 'The requested record came from the local setup-miss exception cache after the fixed response was parsed and ignored. '
    : last.fromApplicationCache
      ? 'Cached application record returned; a different real target was recovered for cover. '
      : 'The requested record was recovered from the actual parity response. ';
  const result = last.failureCode
    ? verdict('alarm', [
        el('strong', { class: 'fail-code' }, `${last.failureCode}: `),
        last.failureDetail ?? 'The local client could not recover a record.',
      ])
    : verdict(
        last.applicationRecordMatches && last.effectiveRecordMatches && last.applicationTagMatches
          ? 'pass'
          : 'fail',
        [
          el('strong', {}, successLead),
          `Application bytes ${last.applicationRecordMatches ? 'match' : 'do not match'} the current ` +
            `database, the recovered effective bytes ${last.effectiveRecordMatches ? 'match' : 'do not match'}, ` +
            `and the public decode tag ${last.applicationTagMatches ? 'matches' : 'does not match'}.`,
        ]
      );
  result.dataset.role = 'stateful-result';

  return el('div', {}, [
    scroller('Server-visible Piano request and response', serverTable),
    el('h4', {}, 'Client-local explanation — not sent'),
    el('div', { 'data-role': 'stateful-local-route' }, kv(localRows)),
    equationOutput(last.equation),
    result,
    el(
      'p',
      { class: 'inline-note' },
      `A real target can appear among the eight indices when the independently sampled replacement ` +
        `r equals x. That is valid, not filtered out. Privacy is a distributional claim about the ` +
        `whole request; it is not the false claim that the target can never occur on the wire.`
    ),
  ]);
}

function equationOutput(equation: EquationView): HTMLElement {
  if (equation.route === 'none') {
    return el(
      'p',
      { class: 'inline-note', 'data-role': 'stateful-equations' },
      'No recovery or refresh equation ran for this local failure/cover-only exchange.'
    );
  }
  if (equation.route === 'setup-miss') {
    return el('div', { 'data-role': 'stateful-equations' }, [
      el('h4', {}, 'Executed client route'),
      verdict(
        'info',
        `This rare target was absent from every primary hint at setup, so the client returned its ` +
          `retained exception record only after parsing the fixed 512-byte response. The response ` +
          `was ignored and no backup hint or refresh slot was consumed.`
      ),
    ]);
  }

  return el('div', { 'data-role': 'stateful-equations' }, [
    el('h4', {}, 'Executed client equations — byte heads shown, all 512 bytes checked'),
    el(
      'p',
      { class: 'code', 'data-role': 'stateful-recovery-equation' },
      `P ${equation.primaryHead} ⊕ response ${equation.responseHead} ⊕ DB[r] ` +
        `${equation.replacementHead} = recovered ${equation.recoveredHead}`
    ),
    verdict(
      equation.recoveryMatches ? 'pass' : 'fail',
      `Recovery equation across all ${PIANO_RECORD_BYTES} bytes: ${yesNo(equation.recoveryMatches === true)}.`
    ),
    el(
      'p',
      { class: 'code', 'data-role': 'stateful-refresh-equation' },
      `backup ${equation.backupHead} ⊕ recovered ${equation.recoveredHead} = refreshed ` +
        `${equation.refreshedHead}`
    ),
    verdict(
      equation.refreshMatches ? 'pass' : 'fail',
      `Backup tag ${equation.backupTag}, slot ${equation.backupSlot}: refreshed parity across all ` +
        `${PIANO_RECORD_BYTES} bytes ${equation.refreshMatches ? 'matches' : 'does not match'} the retained hint.`
    ),
  ]);
}

function stateOutput(metrics: ReturnType<typeof pianoStateMetrics> | null): HTMLElement {
  const parts: HTMLElement[] = [];
  if (metrics) {
    parts.push(
      el('div', { 'data-role': 'stateful-state-metrics' }, kv([
        ['Epoch status', metrics.valid ? 'valid' : metrics.invalidReason?.code ?? 'invalid'],
        ['Requests committed', String(metrics.requestsSent)],
        ['Responses accepted', String(metrics.responsesAccepted)],
        ['Unique effective targets spent', String(metrics.effectiveTargetsConsumed)],
        ['Window remaining', `${metrics.remainingWindow} of ${PIANO_QUERY_WINDOW}`],
        ['Application/effective cache', `${metrics.cachedRecords} records / ${formatExactBytes(metrics.cacheBytes)}`],
        ['Setup-miss exception cache', `${metrics.setupMissRecords} records`],
        ['Canonical retained state now', formatExactBytes(metrics.retainedStateBytes)],
      ]))
    );
  } else {
    parts.push(
      verdict(
        state.lostState ? 'alarm' : 'info',
        state.lostState
          ? `No PRF key, parities, replacements or cache remain reachable through this client. ` +
              `JavaScript does not promise secure zeroization of garbage-collected memory. The cover ` +
              `exchange hid the local loss event's request shape, but it could not recover a record. ` +
              `Only a full setup stream can restore usable state.`
          : 'There is no retained client state yet.'
      )
    );
  }

  if (state.update) {
    const update = state.update;
    parts.push(
      el('div', { 'data-role': 'stateful-update-evidence' }, [
        el('h4', {}, `Database revision at record ${update.index} — ${update.title}`),
        el(
          'p',
          { class: 'callout callout-caveat' },
          `To make this stale-state failure reproducible, the diagnostic deliberately chose ` +
            `its target and replacement relation from client-private audit state. This is not ` +
            `an ordinary application query and is not evidence for the independent-target ` +
            `privacy or availability claim.`
        ),
        kv([
          ['Stale diagnostic target', String(update.diagnosticTarget)],
          ['Old record was retained as a replacement', yesNo(update.retainedReplacementMatchedOldRecord)],
          ['New record actually differs', yesNo(update.oldAndNewDiffer)],
          ['Old record still has a valid public tag', yesNo(update.oldTagStillValid)],
          ['New record has a valid public tag', yesNo(update.newTagValid)],
          ['Stale recovery matches current diagnostic record', yesNo(update.staleRecoveredMatchesCurrent)],
          ['Stale recovery public tag matches', yesNo(update.staleRecoveredTagMatches)],
          ['Snapshot digest detected the known update', yesNo(update.digestDetectedChange)],
          ['Recovered current bytes after full rebuild', yesNo(update.recoveredAfterRebuild)],
        ]),
        verdict('alarm', [
          el('strong', {}, 'A valid tag does not prove freshness. '),
          `The stale old record and the changed record both carry matching truncated SHA-256 tags. ` +
            `The tag detects accidental decode failure only; it is public and replayable. The local ` +
            `snapshot digest detected this known update, but a malicious server replaying an entire ` +
            `old snapshot would require an external authenticated, monotonic commitment to detect.`,
        ]),
        el(
          'p',
          { class: 'callout callout-caveat' },
          `This static construction does not patch one hint. One changed record invalidates all ` +
            `client parities, replacements and cached answers, so recovery costs a complete ` +
            `${formatExactBytes(PIANO_SETUP_COSTS.streamedDatabaseBytes)} preprocessing stream.`
        ),
      ])
    );
  }

  parts.push(
    disclose('Persistence, rollback and crash limits', [
      el(
        'p',
        {},
        `The serialized client state contains a secret PRF key, parities, replacement records, ` +
          `spent-target bits and a sparse cache. It needs confidential, authenticated storage. Its ` +
          `encoding is not self-authenticating.`
      ),
      el(
        'p',
        {},
        `A generation high-water mark stored outside that blob can reject an older snapshot, but ` +
          `it is only rollback evidence, not a storage security system. Restoring a stale state, ` +
          `retrying an abandoned request or losing a response can reuse correlated hints and make ` +
          `requests linkable. This lesson therefore invalidates rather than rolls back.`
      ),
    ])
  );
  return el('div', {}, parts);
}

function costOutput(metrics: ReturnType<typeof pianoStateMetrics> | null): HTMLElement {
  const c = state.costs;
  const executed = el('table', { class: 'data', 'data-role': 'stateful-executed-costs' }, [
    el(
      'caption',
      {},
      'Logical protocol costs accumulated from actions executed in this browser session. This is not an instrumented CPU or memory benchmark: setup snapshot and SHA-256 passes are not folded into the stream, XOR or copy counters, and unlike units are never added together.'
    ),
    el('thead', {}, el('tr', {}, [el('th', {}, 'Phase / unit'), el('th', { class: 'num' }, 'Executed')])),
    el('tbody', {}, [
      rowNum('Setup runs', c.setupRuns),
      rowNum('Setup database bytes streamed', formatExactBytes(c.setupStreamBytes)),
      rowNum('Setup database records streamed', c.setupRecordReads),
      rowNum('Setup parity record-XOR contributions', c.setupParityRecordXors),
      rowNum('Setup replacement-record copies', c.replacementRecordCopies),
      rowNum('Online requests sent', c.onlineRequests),
      rowNum('Online upload bytes', formatExactBytes(c.onlineUploadBytes)),
      rowNum('Online download bytes', formatExactBytes(c.onlineDownloadBytes)),
      rowNum('Online server record probes', c.onlineServerRecordProbes),
      rowNum('Online server record-XOR contributions', c.onlineServerParityRecordXors),
      rowNum('Known-update digest scans', `${c.databaseDigestScans} × ${formatExactBytes(PIANO_SETUP_COSTS.streamedDatabaseBytes)}`),
      rowNum('Known-update digest bytes', formatExactBytes(c.databaseDigestBytes)),
    ]),
  ]);

  const setupBreakdown = kv([
    ['Public database stream', `${formatExactBytes(PIANO_SETUP_COSTS.streamedDatabaseBytes)} / ${PIANO_SETUP_COSTS.streamedRecords} records`],
    ['Primary parity contributions', String(PIANO_SETUP_COSTS.primaryParityRecordXors)],
    ['Backup parity contributions', String(PIANO_SETUP_COSTS.backupParityRecordXors)],
    ['Total parity contributions', String(PIANO_SETUP_COSTS.totalSetupParityRecordXors)],
    ['Byte-wise XOR operations in those contributions', String(PIANO_SETUP_COSTS.totalSetupParityRecordXors * PIANO_RECORD_BYTES)],
    ['Replacement record copies', String(PIANO_SETUP_COSTS.replacementRecordCopies)],
    ['Base retained state encoding', formatExactBytes(PIANO_BASE_STATE_BYTES)],
    ['Each sparse cache entry', formatExactBytes(PIANO_CACHE_ENTRY_BYTES)],
    ['Current retained state encoding', metrics ? formatExactBytes(metrics.retainedStateBytes) : 'not built'],
    ['Server ProcessDB', 'identity/none; no derived server state'],
  ]);

  const crossoverRows = [1, 2, PIANO_QUERY_WINDOW].map((queries) => {
    const ledger = pianoCostForQueries(queries);
    const downloadAll = queries * PIANO_SETUP_COSTS.streamedDatabaseBytes;
    return el('tr', {}, [
      el('th', { scope: 'row', class: 'num' }, String(queries)),
      el('td', { class: 'num' }, formatExactBytes(ledger.setupStreamBytes)),
      el('td', { class: 'num' }, formatExactBytes(ledger.onlineUploadBytes + ledger.onlineDownloadBytes)),
      el('td', { class: 'num' }, formatExactBytes(ledger.totalWireBytes)),
      el('td', { class: 'num' }, `${(ledger.totalWireBytes / queries).toFixed(2)} B`),
      el('td', { class: 'num' }, formatExactBytes(downloadAll)),
    ]);
  });
  const crossover = el('table', { class: 'data', 'data-role': 'stateful-cost-table' }, [
    el(
      'caption',
      {},
      `Communication accounting, not a timing benchmark. At query 2, setup plus fixed online messages becomes smaller than downloading all ${PIANO_DATABASE_RECORDS} records each time.`
    ),
    el('thead', {}, el('tr', {}, [
      el('th', { class: 'num' }, 'Queries'),
      el('th', { class: 'num' }, 'Setup stream'),
      el('th', { class: 'num' }, 'Online wire'),
      el('th', { class: 'num' }, 'Total'),
      el('th', { class: 'num' }, 'Amortized'),
      el('th', { class: 'num' }, 'Download full DB'),
    ])),
    el('tbody', {}, crossoverRows),
  ]);

  return el('div', {}, [
    scroller('Executed preprocessing and online costs', executed),
    el('h4', {}, 'One setup epoch, by operation type'),
    setupBreakdown,
    el('h4', {}, 'Repeated-query communication crossover'),
    scroller('Piano-style setup amortization against full database download', crossover),
    el(
      'p',
      { class: 'inline-note' },
      `At the full ${PIANO_QUERY_WINDOW}-request window, setup contributes ` +
        `${(PIANO_SETUP_COSTS.streamedDatabaseBytes / PIANO_QUERY_WINDOW).toFixed(2)} bytes per request; ` +
        `adding ${PIANO_QUERY_BYTES + PIANO_RESPONSE_BYTES} online bytes gives ` +
        `${((PIANO_SETUP_COSTS.streamedDatabaseBytes / PIANO_QUERY_WINDOW) + PIANO_QUERY_BYTES + PIANO_RESPONSE_BYTES).toFixed(2)} ` +
        `bytes per application query. Cached repeats still spend a real unique effective target and a window slot.`
    ),
    el(
      'p',
      { class: 'inline-note' },
      `This crossover compares setup-plus-query traffic with re-downloading the entire database ` +
        `for every lookup. A client permitted to retain this static public database after one ` +
        `download would need no PIR queries at all, so the table is an accounting exercise rather ` +
        `than a deployment recommendation.`
    ),
  ]);
}

function modelOutput(): HTMLElement {
  const bounds = pianoAvailabilityBounds();
  return el('div', {}, [
    el(
      'p',
      { class: 'callout', 'data-role': 'stateful-bound' },
      [
        el('strong', {}, 'The finite availability bound is narrow and explicit. '),
        `${PIANO_QUERY_WINDOW} × (7/8)^${bounds.minimumUniformHintsPerTarget} = ` +
          `${bounds.sessionPrimaryHintMissUpperBound.toExponential(6)} ≈ 2^${bounds.sessionPrimaryHintMissLog2.toFixed(2)}. ` +
          `It bounds primary-hint availability over at most ${PIANO_QUERY_WINDOW} unique effective ` +
          `targets selected independently of the secret PRF coordinates, under this refresh schedule. It is not ` +
          `a 128-bit claim, an end-to-end security bound or a malicious-server guarantee.`,
      ]
    ),
    kv([
      ['Database model', 'static, public, 64 × 512 bytes'],
      ['Server model', 'one honest-but-curious server'],
      ['Client setup', `${PIANO_PRIMARY_HINTS} primary hints; ${PIANO_BACKUPS_PER_CHUNK} backups per chunk`],
      ['Online window', `${PIANO_QUERY_WINDOW} committed requests, including covers and local failures`],
      ['Online encoding', '8 lab-specific one-byte indices; the pinned reference client uses uint64/protobuf fields'],
      ['Online server work', `${PIANO_CHUNK_COUNT} probes and ${PIANO_CHUNK_COUNT} parity contributions per request`],
      ['Answer integrity / availability', 'not provided'],
      ['Traffic, timing, identity, access control', 'not hidden or provided'],
    ]),
    disclose('What is adapted, and what does not transfer', [
      el('p', {}, [
        `This executable lesson is informed by Mingxun Zhou, Andrew Park, Elaine Shi and Wenting Zheng's `,
        sourceLink('Piano paper (ePrint 2023/452)', 'https://eprint.iacr.org/2023/452'),
        `, revised 12 November 2023. Its N = 64 parameter set, finite linear backup overprovision, one-byte ` +
          `wire codec, serialized-state format, ` +
          `cache and failure policy are a bounded teaching adaptation. The paper's asymptotic ` +
          `bounds, parameter recommendations, throughput results and separate dynamic extension ` +
          `are not claims about this code. In particular, the 8-byte upload is this lab's compact ` +
          `codec, not a copied Piano benchmark: the `,
        sourceLink(
          'pinned reference implementation',
          'https://github.com/wuwuz/Piano-PIR-new/tree/f7107cfadc15a0ac3df20f0bc64f126bf359b702'
        ),
        ` serializes indices as uint64/protobuf fields.`,
      ]),
      el('p', {}, [
        sourceLink('LMW doubly-efficient PIR (ePrint 2022/1703)', 'https://eprint.iacr.org/2022/1703'),
        ` uses different cryptographic machinery and server preprocessing. For any constant ε > 0, ` +
          `it gives polylogarithmic online work and communication, with O(N^ε) preprocessing-update ` +
          `time; those bounds do ` +
          `not transfer to this no-ProcessDB XOR-parity lesson. `,
        sourceLink('Corrigan-Gibbs, Henzinger and Kogan (ePrint 2022/081)', 'https://eprint.iacr.org/2022/081'),
        `'s most efficient scheme is optimal for its stated trade-off between server online time ` +
          `and client storage. This adaptation neither instantiates that scheme nor transfers its ` +
          `lower bound into a numeric claim for N = 64.`,
      ]),
    ]),
    disclose('Why this is not ORAM', [
      el(
        'p',
        {},
        `PIR answers a read while hiding which record that request targets under its stated model. ` +
          `This bounded lesson consumes client hints and uses fresh effective targets, but it does ` +
          `not implement oblivious writes, server reshuffling, an ORAM position map or an ORAM ` +
          `access-sequence theorem. Database updates are visible and force a full client rebuild.`
      ),
    ]),
    verdict('alarm', [
      el('strong', {}, 'Do not read more into the hashes. '),
      `The database digest is a local snapshot/version check, and each record's truncated SHA-256 ` +
        `tag detects accidental decode corruption. Neither authenticates a server answer, prevents ` +
        `replay, establishes freshness or protects state storage. A deployment needs independent ` +
        `authentication, monotonic versioning, crash-safe private state, access controls and a policy ` +
        `for traffic metadata.`
    ]),
  ]);
}

function bind(root: HTMLElement, lab: Lab): void {
  root.querySelector<HTMLButtonElement>('[data-role="stateful-setup"]')?.addEventListener('click', () => {
    void runSetup(root, lab, false);
  });
  root.querySelector<HTMLButtonElement>('[data-role="stateful-query"]')?.addEventListener('click', () => {
    void runSelectedQuery(root, lab, 'stateful-query');
  });
  root.querySelector<HTMLButtonElement>('[data-role="stateful-repeat"]')?.addEventListener('click', () => {
    void runSelectedQuery(root, lab, 'stateful-repeat');
  });
  root.querySelector<HTMLButtonElement>('[data-role="stateful-lose"]')?.addEventListener('click', () => {
    void loseState(root, lab);
  });
  root.querySelector<HTMLButtonElement>('[data-role="stateful-update"]')?.addEventListener('click', () => {
    void updateDatabase(root, lab);
  });
  root.querySelector<HTMLButtonElement>('[data-role="stateful-recover-update"]')?.addEventListener('click', () => {
    void recoverUpdate(root, lab);
  });
}

async function buildFixedDatabase(): Promise<Uint8Array[]> {
  return Promise.all(
    FIXED_ENTRIES.map((entry) => buildRecord(entryText(entry), PIANO_RECORD_BYTES))
  );
}

async function performSetup(): Promise<void> {
  if (!state.database) state.database = await buildFixedDatabase();
  state.client = await preprocessPiano(state.database);
  state.lostState = false;
  state.costs.setupRuns += 1;
  state.costs.setupStreamBytes += PIANO_SETUP_COSTS.streamedDatabaseBytes;
  state.costs.setupRecordReads += PIANO_SETUP_COSTS.streamedRecords;
  state.costs.setupParityRecordXors += PIANO_SETUP_COSTS.totalSetupParityRecordXors;
  state.costs.replacementRecordCopies += PIANO_SETUP_COSTS.replacementRecordCopies;
}

async function runSetup(root: HTMLElement, lab: Lab, recoveringUpdate: boolean): Promise<void> {
  if (state.busy) return;
  state.busy = true;
  state.stage = recoveringUpdate
    ? 'Streaming the changed database into a fresh client epoch…'
    : 'Streaming 64 records and constructing client-specific hints…';
  state.error = null;
  redraw(root, lab);
  await nextFrame();
  try {
    await performSetup();
    state.last = null;
    state.notice =
      `Setup epoch ready: ${formatExactBytes(PIANO_SETUP_COSTS.streamedDatabaseBytes)} streamed, ` +
      `${PIANO_SETUP_COSTS.totalSetupParityRecordXors} parity record-XOR contributions, ` +
      `${PIANO_SETUP_COSTS.replacementRecordCopies} replacement copies. No online request was sent.`;
  } catch (error) {
    state.error = errorText(error);
    state.notice = 'Preprocessing did not complete.';
  } finally {
    state.busy = false;
    state.stage = null;
    redraw(root, lab);
    focusAction(root, 'stateful-setup');
  }
}

async function runSelectedQuery(
  root: HTMLElement,
  lab: Lab,
  focusRole: 'stateful-query' | 'stateful-repeat'
): Promise<void> {
  const target = lab.snapshot().selectedIndex;
  if (state.busy || !state.client || target < 0 || target >= PIANO_DATABASE_RECORDS) return;
  state.busy = true;
  state.stage = `Sending one fixed-shape request for application record ${target}…`;
  state.error = null;
  redraw(root, lab);
  await nextFrame();
  try {
    await executeQuery(target);
  } catch (error) {
    state.error = errorText(error);
    state.notice = 'The online operation stopped before a trustworthy result was available.';
  } finally {
    state.busy = false;
    state.stage = null;
    redraw(root, lab);
    focusAction(root, focusRole, 'stateful-setup');
  }
}

async function executeQuery(target: number): Promise<void> {
  if (!state.client || !state.database) throw new Error('client setup is unavailable');
  const request = beginPianoQuery(state.client, target);
  const plan = auditPianoRequest(request);
  const wire = serializePianoRequest(request);
  const response = pianoServerAnswer(state.database, wire);
  recordOnlineCosts(wire, response);
  const result = finishPianoQuery(state.client, request, response);
  if (!result.ok) {
    state.last = {
      requestedIndex: target,
      effectiveIndex: result.effectiveIndex,
      kind: result.kind,
      wire,
      responseBytes: response.length,
      responseHead: byteHead(response),
      hintIndex: request.hintIndex,
      replacementIndex: request.replacementIndex,
      fromApplicationCache: false,
      applicationRecordMatches: null,
      effectiveRecordMatches: null,
      applicationTagMatches: null,
      failureCode: result.failure.code,
      failureDetail: result.failure.detail,
      equation: noEquation(),
    };
    state.notice = `${result.failure.code}: a fixed ${wire.length}-byte cover request still received a ${response.length}-byte response; no record was returned.`;
    return;
  }

  const applicationRecordMatches = sameBytes(result.record, state.database[target]);
  const effectiveRecordMatches = sameBytes(
    result.recoveredEffectiveRecord,
    state.database[result.effectiveIndex]
  );
  const applicationTagMatches = await tagMatches(result.record);
  const equation = buildEquationView(plan, response, result, state.client);
  state.last = {
    requestedIndex: target,
    effectiveIndex: result.effectiveIndex,
    kind: result.kind,
    wire,
    responseBytes: response.length,
    responseHead: byteHead(response),
    hintIndex: request.hintIndex,
    replacementIndex: request.replacementIndex,
    fromApplicationCache: result.fromApplicationCache,
    applicationRecordMatches,
    effectiveRecordMatches,
    applicationTagMatches,
    failureCode: null,
    failureDetail: null,
    equation,
  };
  if (plan.fromSetupMissCache) {
    state.notice = result.fromApplicationCache
      ? `Returned cached record ${target}; the fresh cover target used its retained setup-miss exception after the fixed response was parsed and ignored. No hint was refreshed.`
      : `Returned setup-miss exception record ${target} after parsing and ignoring the fixed response. No hint was refreshed.`;
  } else {
    state.notice = result.fromApplicationCache
      ? `Returned cached record ${target} while a real cover request recovered fresh effective target ${result.effectiveIndex} and refreshed one hint.`
      : `Recovered record ${target} from the server parity and refreshed its consumed primary hint with one backup.`;
  }
}

async function loseState(root: HTMLElement, lab: Lab): Promise<void> {
  if (state.busy || !state.client || !state.database) return;
  state.busy = true;
  state.stage = 'Discarding the private-state reference, then sending one fixed-shape cover request…';
  state.error = null;
  redraw(root, lab);
  await nextFrame();
  try {
    const detached = makePianoStateLossRequest();
    // Model a logical loss before the request crosses the server boundary. JavaScript
    // does not promise secure memory zeroization, so the UI never claims that it does.
    state.client = null;
    state.lostState = true;
    const response = pianoServerAnswer(state.database, detached.wire);
    recordOnlineCosts(detached.wire, response);
    state.last = {
      requestedIndex: null,
      effectiveIndex: null,
      kind: 'dummy',
      wire: detached.wire,
      responseBytes: response.length,
      responseHead: byteHead(response),
      hintIndex: null,
      replacementIndex: null,
      fromApplicationCache: false,
      applicationRecordMatches: null,
      effectiveRecordMatches: null,
      applicationTagMatches: null,
      failureCode: detached.failure.code,
      failureDetail: detached.failure.detail,
      equation: noEquation(),
    };
    state.notice =
      `STATE_LOST: the server saw the usual ${detached.wire.length}-byte request and returned ` +
      `${response.length} bytes, but the client had no secret state with which to recover anything.`;
  } catch (error) {
    state.error = errorText(error);
    state.notice = 'The state-loss exercise stopped.';
  } finally {
    state.busy = false;
    state.stage = null;
    redraw(root, lab);
    focusAction(root, 'stateful-setup');
  }
}

async function updateDatabase(root: HTMLElement, lab: Lab): Promise<void> {
  const selected = lab.snapshot().selectedIndex;
  if (
    state.busy ||
    !state.client ||
    !state.database ||
    state.update ||
    !pianoStateMetrics(state.client).valid ||
    selected < 0 ||
    selected >= PIANO_DATABASE_RECORDS
  ) return;
  state.busy = true;
  state.stage = 'Changing one non-target record retained in the client setup…';
  state.error = null;
  redraw(root, lab);
  await nextFrame();
  try {
    const client = state.client;
    const database = state.database;
    const audit = auditPianoState(client);
    const diagnostic = chooseUpdateDiagnostic(audit, selected);
    if (!diagnostic) {
      throw new Error('no unused diagnostic target with a retained non-target replacement was available');
    }

    const { diagnosticTarget, replacementIndex: index } = diagnostic;
    const oldRecord = state.database[index].slice();
    const changedRecord = await buildRecord(
      `Catalog revision 2 — corrected local teaching copy. ${entryText(FIXED_ENTRIES[index])}`,
      PIANO_RECORD_BYTES
    );
    const updated = database.map<Uint8Array>((record) => record.slice());
    updated[index] = changedRecord;

    // Commit a real request while the old client snapshot is still valid. The
    // chosen record is its retained replacement r, not its target x. Updating r
    // after commitment makes the stale recovery equation execute and fail
    // against current DB[x], before the separate digest check invalidates state.
    const request = beginPianoQuery(client, diagnosticTarget);
    const plan = auditPianoRequest(request);
    const wire = serializePianoRequest(request);
    if (
      plan.fromSetupMissCache ||
      plan.replacementIndex !== index ||
      plan.replacementValue === null
    ) {
      const response = pianoServerAnswer(database, wire);
      recordOnlineCosts(wire, response);
      finishPianoQuery(client, request, response);
      throw new Error('the diagnostic request did not commit the selected retained replacement');
    }

    state.database = updated;
    const response = pianoServerAnswer(updated, wire);
    recordOnlineCosts(wire, response);
    const result = finishPianoQuery(client, request, response);
    if (!result.ok) {
      throw new Error(`the stale diagnostic request returned ${result.failure.code}`);
    }
    const equation = buildEquationView(plan, response, result, client);
    const staleRecoveredMatchesCurrent = sameBytes(
      result.recoveredEffectiveRecord,
      updated[diagnosticTarget]
    );
    const staleRecoveredTagMatches = await tagMatches(result.recoveredEffectiveRecord);
    const retainedReplacementMatchedOldRecord = sameBytes(plan.replacementValue, oldRecord);
    const oldAndNewDiffer = !sameBytes(oldRecord, changedRecord);
    const oldTagStillValid = await tagMatches(oldRecord);
    const newTagValid = await tagMatches(changedRecord);
    const digestDetectedChange = !(await verifyPianoDatabaseCurrent(client, updated));
    state.costs.databaseDigestScans += 1;
    state.costs.databaseDigestBytes += PIANO_SETUP_COSTS.streamedDatabaseBytes;

    state.last = {
      requestedIndex: diagnosticTarget,
      effectiveIndex: result.effectiveIndex,
      kind: result.kind,
      wire,
      responseBytes: response.length,
      responseHead: byteHead(response),
      hintIndex: request.hintIndex,
      replacementIndex: request.replacementIndex,
      fromApplicationCache: result.fromApplicationCache,
      applicationRecordMatches: staleRecoveredMatchesCurrent,
      effectiveRecordMatches: staleRecoveredMatchesCurrent,
      applicationTagMatches: staleRecoveredTagMatches,
      failureCode: null,
      failureDetail: null,
      equation,
    };
    state.update = {
      index,
      title: FIXED_ENTRIES[index].title,
      diagnosticTarget,
      retainedReplacementMatchedOldRecord,
      oldAndNewDiffer,
      oldTagStillValid,
      newTagValid,
      staleRecoveredMatchesCurrent,
      staleRecoveredTagMatches,
      digestDetectedChange,
      recoveredAfterRebuild: false,
    };
    state.notice =
      `DATABASE_UPDATED: non-target replacement ${index} changed after request commitment. ` +
      `The old client equation still executed, but its recovered bytes failed the current-record ` +
      `and public-tag checks; the subsequent snapshot digest invalidated the whole epoch.`;
  } catch (error) {
    state.error = errorText(error);
    state.notice = 'The database-update exercise stopped.';
  } finally {
    state.busy = false;
    state.stage = null;
    redraw(root, lab);
    focusAction(root, 'stateful-recover-update', 'stateful-setup');
  }
}

async function recoverUpdate(root: HTMLElement, lab: Lab): Promise<void> {
  if (state.busy || !state.update) return;
  state.busy = true;
  state.stage = 'Streaming the entire changed database, then retrieving its changed record…';
  state.error = null;
  redraw(root, lab);
  await nextFrame();
  try {
    const index = state.update.index;
    await performSetup();
    await executeQuery(index);
    state.update.recoveredAfterRebuild =
      state.last?.failureCode === null && state.last.applicationRecordMatches === true;
    state.notice = state.update.recoveredAfterRebuild
      ? `Full rebuild complete: a new setup epoch recovered the current bytes of changed record ${index}.`
      : `The rebuild ran, but changed record ${index} was not independently recovered.`;
  } catch (error) {
    state.error = errorText(error);
    state.notice = 'The full-rebuild recovery exercise stopped.';
  } finally {
    state.busy = false;
    state.stage = null;
    redraw(root, lab);
    focusAction(root, 'stateful-query', 'stateful-setup');
  }
}

function noEquation(): EquationView {
  return {
    route: 'none',
    primaryHead: null,
    responseHead: null,
    replacementHead: null,
    recoveredHead: null,
    recoveryMatches: null,
    backupTag: null,
    backupSlot: null,
    backupHead: null,
    refreshedHead: null,
    refreshMatches: null,
  };
}

function buildEquationView(
  plan: PianoRequestAuditSnapshot,
  response: Uint8Array,
  result: PianoSuccessResult,
  client: PianoClientState
): EquationView {
  if (plan.fromSetupMissCache) {
    return { ...noEquation(), route: 'setup-miss' };
  }
  if (
    plan.effectiveIndex === null ||
    plan.hintIndex === null ||
    plan.originalHintParity === null ||
    plan.backupTag === null ||
    plan.backupParity === null ||
    plan.replacementValue === null
  ) {
    return noEquation();
  }

  // Recompute the executed equations from defensive audit copies rather than
  // trusting the result flags produced by finishPianoQuery.
  const recovered = xorRecords(plan.originalHintParity, response, plan.replacementValue);
  const refreshed = xorRecords(plan.backupParity, recovered);
  const post = auditPianoState(client);
  const retainedHint = post.primaryHints[plan.hintIndex];
  const chunk = Math.floor(plan.effectiveIndex / PIANO_CHUNK_SIZE);
  const backupSlot =
    plan.backupTag - PIANO_PRIMARY_HINTS - chunk * PIANO_BACKUPS_PER_CHUNK;

  return {
    route: 'parity-refresh',
    primaryHead: byteHead(plan.originalHintParity),
    responseHead: byteHead(response),
    replacementHead: byteHead(plan.replacementValue),
    recoveredHead: byteHead(recovered),
    recoveryMatches: sameBytes(recovered, result.recoveredEffectiveRecord),
    backupTag: plan.backupTag,
    backupSlot,
    backupHead: byteHead(plan.backupParity),
    refreshedHead: byteHead(refreshed),
    refreshMatches:
      retainedHint.tag === plan.backupTag &&
      retainedHint.programmedTarget === plan.effectiveIndex &&
      sameBytes(retainedHint.parity, refreshed),
  };
}

function chooseUpdateDiagnostic(
  audit: ReturnType<typeof auditPianoState>,
  selected: number
): { diagnosticTarget: number; replacementIndex: number } | null {
  const consumed = new Set(audit.consumedTargets);
  for (let chunk = 0; chunk < PIANO_CHUNK_COUNT; chunk += 1) {
    const slot = audit.consumedSlots[chunk];
    if (slot >= PIANO_BACKUPS_PER_CHUNK) continue;
    const replacementIndex = audit.replacements[chunk][slot].index;
    if (replacementIndex === selected) continue;
    for (let offset = 0; offset < PIANO_CHUNK_SIZE; offset += 1) {
      const diagnosticTarget = chunk * PIANO_CHUNK_SIZE + offset;
      if (
        diagnosticTarget !== selected &&
        diagnosticTarget !== replacementIndex &&
        !consumed.has(diagnosticTarget) &&
        !audit.setupMisses.has(diagnosticTarget)
      ) {
        return { diagnosticTarget, replacementIndex };
      }
    }
  }
  return null;
}

function xorRecords(...records: readonly Uint8Array[]): Uint8Array {
  if (records.length === 0) return new Uint8Array();
  const out = new Uint8Array(records[0].length);
  for (const record of records) {
    if (record.length !== out.length) throw new RangeError('equation record lengths differ');
    for (let i = 0; i < out.length; i += 1) out[i] ^= record[i];
  }
  return out;
}

function byteHead(bytes: Uint8Array): string {
  const head = Array.from(bytes.subarray(0, 8), (byte) => byte.toString(16).padStart(2, '0')).join(' ');
  return bytes.length > 8 ? `${head} …` : head;
}

function formatExactBytes(bytes: number): string {
  const compact = formatBytes(bytes);
  return compact === `${bytes} B` ? compact : `${bytes} B (${compact})`;
}

function focusAction(root: HTMLElement, preferredRole: string, fallbackRole?: string): void {
  const enabled = (role: string | undefined): HTMLButtonElement | null => {
    if (!role) return null;
    const button = root.querySelector<HTMLButtonElement>(`[data-role="${role}"]`);
    return button && !button.disabled ? button : null;
  };
  const target = enabled(preferredRole) ?? enabled(fallbackRole);
  target?.focus({ preventScroll: true });
}

function recordOnlineCosts(wire: Uint8Array, response: Uint8Array): void {
  state.costs.onlineRequests += 1;
  state.costs.onlineUploadBytes += wire.length;
  state.costs.onlineDownloadBytes += response.length;
  state.costs.onlineServerRecordProbes += PIANO_CHUNK_COUNT;
  state.costs.onlineServerParityRecordXors += PIANO_CHUNK_COUNT;
}

function row(label: string, value: string, role?: string): HTMLTableRowElement {
  return el('tr', {}, [
    el('th', { scope: 'row' }, label),
    el('td', role ? { 'data-role': role } : {}, value),
  ]);
}

function rowNum(label: string, value: number | string): HTMLTableRowElement {
  return el('tr', {}, [
    el('th', { scope: 'row' }, label),
    el('td', { class: 'num' }, String(value)),
  ]);
}

function sourceLink(label: string, href: string): HTMLAnchorElement {
  return el('a', { href, target: '_blank', rel: 'noopener noreferrer' }, label);
}

function yesNo(value: boolean): string {
  return value ? 'yes' : 'no';
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i += 1) difference |= a[i] ^ b[i];
  return difference === 0;
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function announce(root: HTMLElement, text: string): void {
  if (root.parentElement) panelStatus(root.parentElement, text);
}

function redraw(root: HTMLElement, lab: Lab): void {
  withFocusRestored(root, () => renderStateful(root, lab));
}
