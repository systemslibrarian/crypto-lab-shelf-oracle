import {
  append,
  card,
  clear,
  disclose,
  el,
  formatBytes,
  nextFrame,
  panelStatus,
  withFocusRestored,
  scroller,
  verdict,
} from './dom';
import type { Lab } from './state';
import { buildQuery, serverAnswer } from '../pir/pir';
import { serializeCiphertext, serializeQuery } from '../pir/serialize';

/**
 * Act seven: the negative claim, shown rather than asserted.
 *
 * PIR hides the index under its security model. It does not hide that a query
 * happened, when it happened, or how often. Saying that in a paragraph is the
 * "tell, not show" failure this fleet keeps finding, so instead the reader runs
 * several real queries for different books and watches an observer's log fill
 * up with rows that differ in TIME and are identical in SIZE — which is the
 * precise shape of what leaks and what does not.
 *
 * The fixed response length is genuinely a property of the construction here,
 * and it is separated from the properties that come from a deployment, because
 * conflating the two is how a demo ends up overclaiming.
 */

interface Observation {
  index: number;
  title: string;
  atMs: number;
  uploadBytes: number;
  downloadBytes: number;
}

interface PanelState {
  log: Observation[];
  running: boolean;
  startedAt: number | null;
  retired: string | null;
}

const state: PanelState = { log: [], running: false, startedAt: null, retired: null };

/**
 * Clear the observer log, and REMEMBER WHY.
 *
 * The log's whole claim is that every row is the same size. Mixing rows recorded
 * at different shelf lengths or record sizes would break that — the sizes would
 * differ for a reason that has nothing to do with the index — so a parameter
 * change clears it and says so.
 */
export function resetScope(reason?: string): void {
  // `|| state.retired` so a second change updates the reason, not just the first.
  if (state.log.length || state.retired) state.retired = reason ?? null;
  state.log = [];
  state.startedAt = null;
}

export function renderScope(root: HTMLElement, lab: Lab): void {
  clear(root);
  const s = lab.snapshot();

  append(
    root,
    card('What a network observer sees', [
      el(
        'p',
        { class: 'lede' },
        `Run some queries. The observer below is not the server and has no secret key — it sees ` +
          `only what a router sees: that a request went out, when, and how big it was. Watch which ` +
          `columns change.`
      ),
      el('div', { class: 'controls' }, [
        el(
          'button',
          { class: 'btn btn-primary', type: 'button', 'data-role': 'query-random', disabled: state.running },
          'Query a random book'
        ),
        el(
          'button',
          { class: 'btn', type: 'button', 'data-role': 'query-selected', disabled: state.running },
          `Query position ${s.selectedIndex} again`
        ),
        el('button', { class: 'btn', type: 'button', 'data-role': 'clear-log' }, 'Clear the log'),
      ]),
      el('div', { 'data-role': 'log' }, logOutput()),
    ])
  );

  append(root, card('What is hidden, and by what', [claimTable(), forwardLinks()]));

  append(
    root,
    card('Honest scope', [
      el(
        'p',
        { class: 'callout callout-caveat' },
        [
          el('strong', {}, 'What this page does not prove. '),
          `It does not prove that RLWE is hard, that a PRF is secure, that these bounded parameters ` +
            `inherit a paper's theorem, or that a deployment built this way would be private. It ` +
            `demonstrates that three correctly formed single-server PIR routes return the requested ` +
            `record under their stated models, and it executes the distinct costs and state changes ` +
            `that make those claims possible.`,
        ]
      ),
      el(
        'p',
        { class: 'callout' },
        [
          el('strong', {}, 'What is real here. '),
          `The BFV key generation, encryption, decryption, plaintext-ciphertext multiplication and ` +
            `homomorphic addition; the bounded Galois substitutions, noisy key switching and exact ` +
            `NTT/CRT products; the negacyclic ring arithmetic; the ChaCha20 sampler and its RFC 8439 ` +
            `vectors; the Piano-style setup parities, eight-index online request, recovery and hint ` +
            `refresh; the noise measurement; the two-server XOR protocol; every displayed ` +
            `cryptographic-buffer byte count (taken by serializing) and browser timing. Modeled ` +
            `stateful-PIR operation counts are kept separate from measured browser timings. ` +
            `Transport framing and low-level instruction counts are not included.`,
        ]
      ),
      el(
        'p',
        { class: 'callout callout-danger' },
        [
          el('strong', {}, 'What is not production. '),
          `Schoolbook O(n²) record products remain; only dense expansion-key products use the ` +
            `new exact NTT/CRT. No constant-time discipline anywhere — and the direct server loop ` +
            `skips zero plaintext coefficients, so its running time depends on its own data. Ring ` +
            `degree 1024. Each query ciphertext expands to sixteen selectors, and four fixed blocks ` +
            `cover the 64-record catalog; there is no multi-dimensional indexing, modulus switching ` +
            `or seeded ciphertext compression. The 2018 HES table uses Gaussian error while this ` +
            `lab uses centred-binomial error, so the page makes only a modulus-bit comparison. The ` +
            `BFV secret key and stateful PIR hints live in ordinary browser memory. The bounded ` +
            `stateful construction is a static-public-database, honest-but-curious teaching ` +
            `adaptation: it does not provide answer integrity, freshness, rollback protection, ` +
            `traffic hiding or crash-safe state. Nothing has been audited. Every "server" is an ` +
            `object in this page.`,
        ]
      ),
      el('div', { id: 'decryption-feedback-research', class: 'callout callout-caveat' }, [
        el('strong', {}, 'Research update — 20 October 2026: decryption feedback'),
        el('p', {}, 'Ordinary encryption security (IND-CPA), correct decryption, and security when an adversary learns computation results (IND-CPA-D) are different guarantees. Choe, Kang and Stehlé report attacks on particular BFV/BGV configurations using heuristic correctness assumptions, with experiments in OpenFHE and HElib. Crafted operations can exceed heuristic noise bounds; two attacks recover keys, while a third breaks indistinguishability. Parameter tables and noise estimates alone do not establish security in this feedback model. This browser lab does not reproduce those attacks or establish that its implementation is vulnerable.'),
        el('p', {}, 'This PIR model assumes an honest-but-curious server. Both parties run locally; the displayed noise measurements and failure verdicts are teaching diagnostics, not messages to a remote server. A real deployment must analyze any disclosure of decrypted results or errors to an adversary.'),
        el('p', {}, [
          el('a', { href: 'https://eprint.iacr.org/2026/2546' }, 'New IND-CPA-D Attacks on BFV and BGV'),
          ' — received 19 October; revised 20 October 2026; accepted to ACM CCS 2026. Demonstrated results under specific attack-model conditions.',
        ]),
      ]),
      disclose('The construction, and where it comes from', [
        el(
          'p',
          {},
          `The direct protocol is SealPIR (Sebastian Angel, Hao Chen, Kim Laine and Srinath Setty, ` +
            `"PIR with Compressed Queries and Amortized Query Processing", IEEE Symposium on ` +
            `Security and Privacy, 2018) reduced to its direct one-hot form: the client encrypts a ` +
            `selection vector, the server takes a homomorphic inner product against its records, ` +
            `and one ciphertext comes back. The separate Compressed Query panel uses Microsoft ` +
            `SealPIR's client pre-scaling, algebraically equivalent to the paper's server-side ` +
            `inverse scale. It sends four fixed blocks, expands each over sixteen positions, uses ` +
            `that same inner product across all 64 records and returns four fixed responses.`
        ),
        el(
          'p',
          {},
          `The Stateful PIR panel is a bounded adaptation of Zhou, Park, Shi and Zheng's Piano ` +
            `(IEEE Symposium on Security and Privacy 2024; IACR ePrint 2023/452). A client-specific ` +
            `setup streams the static public database and retains secret parity hints. The server ` +
            `has no transformed ProcessDB artifact: online it receives eight compact indices, ` +
            `XORs eight records and returns one parity. The page does not transfer Piano's ` +
            `asymptotic, storage or malicious-server results to this 64-record adapter, and it does ` +
            `not implement the paper's separate hierarchical dynamic extension.`
        ),
        el(
          'p',
          {},
          `The encryption is BFV (Junfeng Fan and Frederik Vercauteren, "Somewhat Practical Fully ` +
            `Homomorphic Encryption", IACR ePrint 2012/144). The noise budget is Microsoft SEAL's ` +
            `invariant noise budget, -log2(2·||v||), measured by decryption rather than estimated.`
        ),
        el(
          'p',
          {},
          `The two-server comparison implements Benny Chor, Oded Goldreich, Eyal Kushilevitz and ` +
            `Madhu Sudan, "Private Information Retrieval", FOCS 1995 — the basic XOR construction, ` +
            `run here over this lab's own records so the comparison is like for like. Oblivious ` +
            `Shelf and Patron Shield teach that scheme properly.`
        ),
        el(
          'p',
          {},
          `Modulus-bit ceilings are quoted from the Homomorphic Encryption Security Standard ` +
            `(HomomorphicEncryption.org, November 2018), uniform ternary secret, classical column. ` +
            `Its Gaussian error model differs from this lab's centred-binomial error, so its ` +
            `security estimates are not transferred here.`
        ),
      ]),
    ])
  );

  announce(
    root,
    state.running
      ? 'Running a query.'
      : state.log.length === 0
        ? 'The observer has seen no queries yet.'
        : `The observer has seen ${state.log.length} quer${state.log.length === 1 ? 'y' : 'ies'}, ` +
          `every one the same size and each at a different time.`
  );

  bind(root, lab);
}

function logOutput(): HTMLElement {
  if (state.running) return el('p', { class: 'status-line' }, 'Running a query…');
  if (state.log.length === 0) {
    return state.retired
      ? verdict('info', [
          el('strong', {}, 'Observer log retired: '),
          `${state.retired}. Every row in this log has to be recorded under the same parameters ` +
            `for the identical-size claim to mean anything, so the previous rows were discarded.`,
        ])
      : el(
          'p',
          { class: 'status-line' },
          'The observer has seen nothing yet. Run a few queries — try different books.'
        );
  }
  const sizes = new Set(state.log.map((o) => `${o.uploadBytes}/${o.downloadBytes}`));
  const table = el('table', { class: 'data' }, [
    el(
      'caption',
      {},
      'The observer’s log. The "book" column is what YOU know; the observer never had it.'
    ),
    el(
      'thead',
      {},
      el('tr', {}, [
        el('th', { class: 'num' }, '#'),
        el('th', { class: 'num' }, 'At (ms)'),
        el('th', { class: 'num' }, 'Uploaded'),
        el('th', { class: 'num' }, 'Downloaded'),
        el('th', {}, 'Book (not observable)'),
      ])
    ),
    el(
      'tbody',
      {},
      state.log.map((o, i) =>
        el('tr', {}, [
          el('td', { class: 'num' }, String(i + 1)),
          el('td', { class: 'num' }, o.atMs.toFixed(0)),
          el('td', { class: 'num' }, formatBytes(o.uploadBytes)),
          el('td', { class: 'num' }, formatBytes(o.downloadBytes)),
          el('td', { class: 'code-dim' }, `${o.index} — ${o.title}`),
        ])
      )
    ),
  ]);

  return el('div', {}, [
    scroller('Observer log', table),
    verdict(
      sizes.size === 1 ? 'pass' : 'alarm',
      sizes.size === 1
        ? [
            el('strong', {}, `Every row is the same size: ${[...sizes][0]} bytes. `),
            `Response length is fixed by construction here — the answer is one ciphertext whatever ` +
              `you asked for — and this observer exercise's direct query is one ciphertext per ` +
              `shelf position regardless of which position. The compressed exhibit has a different, ` +
              `also index-independent shape. That is one metadata channel this design genuinely closes.`,
          ]
        : [
            el('strong', {}, 'The sizes differ across rows. '),
            `That is because the shelf length or record size changed between queries, not because ` +
              `the index leaked — but it is exactly the shape of leak that padding exists to stop.`,
          ]
    ),
    verdict('alarm', [
      el('strong', {}, `The observer knows ${state.log.length} quer${state.log.length === 1 ? 'y' : 'ies'} happened, and when. `),
      `Occurrence, timing, count and rate are all in the log above, and no amount of encryption ` +
        `removes them. Hiding them takes a different mechanism: cover traffic, batching, fixed ` +
        `schedules, a mix network. PIR does not claim to.`,
    ]),
  ]);
}

function claimTable(): HTMLElement {
  const rows: Array<[string, string, string]> = [
    ['Which record was requested', 'Hidden by the protocol', 'The direct path relies on decision RLWE; the compressed path additionally publishes key-dependent evaluation material and relies on the stated circular-security assumption. The bounded stateful path relies on secret PRF-defined hints, one-time refresh state and its stated distinct-target model.'],
    [
      'Whether the response length reveals it',
      'Hidden by the protocol',
      'Direct: one fixed ciphertext. Compressed: four fixed ciphertexts. Stateful: one 512-byte parity. None of those lengths varies with the index; that is construction, not padding.',
    ],
    [
      'Whether the query length reveals it',
      'Hidden by the protocol',
      'The observer exercise uses one ciphertext per shelf position. The compressed route uses four fixed query blocks. The stateful route uses exactly eight one-byte positions, one per chunk. All three shapes are fixed for the 64-record catalog, not its index.',
    ],
    ['That a query happened', 'NOT hidden', 'The request is visible to anyone on the path.'],
    ['When it happened', 'NOT hidden', 'Timing is a deployment concern: batching or a fixed schedule, not PIR.'],
    ['How often, and how many', 'NOT hidden', 'Rate and count leak. Cover traffic is a separate mechanism.'],
    ['Who is asking', 'NOT hidden', 'Client identity and network address are outside the protocol entirely.'],
    ['The size of the database', 'NOT hidden', 'The shelf is public, and the stateful client streams the entire fixed database during setup.'],
    ['Which records exist at all', 'NOT hidden', 'The server owns the shelf and can enumerate it.'],
    ['Whether the answer is honest', 'NOT hidden', 'PIR gives no integrity. A malicious server can return a lie with a matching tag.'],
    [
      'Sequence of requested indices',
      'Hidden by the protocol',
      'Fresh BFV randomness protects the full-scan routes. The bounded stateful route consumes unique effective targets and sends a fresh cover for a cached repeat; lost or rolled-back state can reuse one-time structure and violate that model. Query occurrence, timing and count remain visible.',
    ],
  ];
  const table = el('table', { class: 'data' }, [
    el(
      'caption',
      {},
      'What single-server PIR hides, what it does not, and which of those come from the ' +
        'construction rather than from how it is deployed. Read each row as a question about ' +
        'the INDEX: a length that is visible but constant reveals nothing about which record ' +
        'was asked for, even though it does reveal how many there are.'
    ),
    el(
      'thead',
      {},
      el('tr', {}, [el('th', {}, 'Property'), el('th', {}, 'Status'), el('th', {}, 'Where that comes from')])
    ),
    el(
      'tbody',
      {},
      rows.map(([property, status, source]) =>
        el('tr', {}, [
          el('th', { scope: 'row' }, property),
          el(
            'td',
            {},
            status.startsWith('Hidden')
              ? el('span', { class: 'pill pill-ok' }, ['✓ ', status])
              : el('span', { class: 'pill pill-bad' }, ['✕ ', status])
          ),
          el('td', {}, source),
        ])
      )
    ),
  ]);
  return scroller('What PIR hides and does not hide', table);
}

function forwardLinks(): HTMLElement {
  return el('div', {}, [
    el('h4', {}, 'Where the rest of this goes'),
    el('ul', { class: 'stack-list', role: 'list' }, [
      el('li', { role: 'listitem' }, [
        el(
          'a',
          {
            href: 'https://systemslibrarian.github.io/crypto-lab-search-vault/',
            target: '_blank',
            rel: 'noopener noreferrer',
          },
          'Search Vault'
        ),
        ' — searchable encryption deliberately leaks the access pattern, then inverts it with the ' +
          'count attack (Cash et al., CCS 2015) and the IKK attack (Islam et al., NDSS 2012). ' +
          'That is what happens when the leakage this page refuses to produce is produced.',
      ]),
      el('li', { role: 'listitem' }, [
        el(
          'a',
          {
            href: 'https://systemslibrarian.github.io/crypto-lab-oram-vault/',
            target: '_blank',
            rel: 'noopener noreferrer',
          },
          'ORAM Vault'
        ),
        ' — Path ORAM (Stefanov et al., CCS 2013) hides a logical access sequence from a server ' +
          'that observes data-dependent physical storage locations. This page’s BFV routes perform ' +
          'the same full 64-record scan on every query; its stateful route touches eight records ' +
          'online only after a full setup stream and with private consumable hint state. Neither is ' +
          'an ORAM position map or stash, and visible timing and count remain traffic metadata.',
      ]),
      el('li', { role: 'listitem' }, [
        el(
          'a',
          {
            href: 'https://systemslibrarian.github.io/crypto-lab-oblivious-shelf/',
            target: '_blank',
            rel: 'noopener noreferrer',
          },
          'Oblivious Shelf'
        ),
        ' and ',
        el(
          'a',
          {
            href: 'https://systemslibrarian.github.io/crypto-lab-patron-shield/',
            target: '_blank',
            rel: 'noopener noreferrer',
          },
          'Patron Shield'
        ),
        ' — the two-server, information-theoretic side of the trade this lab is one half of.',
      ]),
      el('li', { role: 'listitem' }, [
        el(
          'a',
          {
            href: 'https://systemslibrarian.github.io/crypto-lab-fhe-arena/',
            target: '_blank',
            rel: 'noopener noreferrer',
          },
          'FHE Arena'
        ),
        ' — BGV and BFV with ciphertext-by-ciphertext multiplication, relinearization and the ' +
          'noise budget this lab borrows and puts to work.',
      ]),
    ]),
  ]);
}

function bind(root: HTMLElement, lab: Lab): void {
  root.querySelector<HTMLButtonElement>('[data-role="query-random"]')?.addEventListener('click', () => {
    const s = lab.snapshot();
    void runQuery(root, lab, lab.random.uniformBelow(s.shelfSize));
  });
  root.querySelector<HTMLButtonElement>('[data-role="query-selected"]')?.addEventListener('click', () => {
    void runQuery(root, lab, lab.snapshot().selectedIndex);
  });
  root.querySelector<HTMLButtonElement>('[data-role="clear-log"]')?.addEventListener('click', () => {
    resetScope();
    redraw(root, lab);
  });
}

async function runQuery(root: HTMLElement, lab: Lab, index: number): Promise<void> {
  if (state.running) return;
  state.running = true;
  state.retired = null;
  redraw(root, lab);
  await nextFrame();

  const s = lab.snapshot();
  if (state.startedAt === null) state.startedAt = performance.now();
  const query = buildQuery(s.params, s.sk, index, s.shelfSize, lab.random);
  const answer = serverAnswer(s.params, s.plaintexts, query.ciphertexts);

  state.log.push({
    index,
    title: s.entries[index].title,
    atMs: performance.now() - state.startedAt,
    uploadBytes: serializeQuery(s.params, query.ciphertexts).length,
    downloadBytes: serializeCiphertext(s.params, answer).length,
  });
  state.running = false;
  redraw(root, lab);
}

/**
 * Announce the panel's headline through the ONE live region `main.ts` created
 * before any render ran. `root` is the panel body; the region is its sibling.
 */
function announce(root: HTMLElement, text: string): void {
  if (root.parentElement) panelStatus(root.parentElement, text);
}

/**
 * Re-render from an event handler WITHOUT throwing the keyboard reader away.
 *
 * A panel rebuilds its whole subtree, which destroys the control the reader is
 * standing on. `main.ts` wraps the renders IT drives; these are the ones the
 * panel drives itself — pressing a button, opening a disclosure, running a
 * measurement — and they are the majority.
 */
function redraw(root: HTMLElement, lab: Lab): void {
  withFocusRestored(root, () => renderScope(root, lab));
}

