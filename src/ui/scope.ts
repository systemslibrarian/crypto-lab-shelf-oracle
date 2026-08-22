import { append, card, clear, disclose, el, formatBytes, nextFrame, scroller, verdict } from './dom';
import type { Lab } from './state';
import { buildQuery, serverAnswer } from '../pir/pir';
import { serializeCiphertext, serializeQuery } from '../pir/serialize';

/**
 * Act six: the negative claim, shown rather than asserted.
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
  if (state.log.length) state.retired = reason ?? null;
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
      el('div', { 'data-role': 'log', role: 'status', 'aria-live': 'polite' }, logOutput()),
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
          `It does not prove that RLWE is hard, that these parameters are secure, or that a ` +
            `deployment built this way would be private. It demonstrates that a correctly formed ` +
            `single-server PIR query returns the right record while carrying no index a server can ` +
            `read without the key — and it demonstrates the costs of doing so.`,
        ]
      ),
      el(
        'p',
        { class: 'callout' },
        [
          el('strong', {}, 'What is real here. '),
          `The BFV key generation, encryption, decryption, plaintext-ciphertext multiplication and ` +
            `homomorphic addition; the negacyclic ring arithmetic; the ChaCha20 sampler and its ` +
            `RFC 8439 vectors; the noise measurement; the two-server XOR protocol; every byte count ` +
            `(taken by serializing) and every timing (taken by timing).`,
        ]
      ),
      el(
        'p',
        { class: 'callout callout-danger' },
        [
          el('strong', {}, 'What is not production. '),
          `Schoolbook O(n²) polynomial multiplication instead of a number-theoretic transform. No ` +
            `constant-time discipline anywhere — and the server's inner loop deliberately skips ` +
            `zero plaintext coefficients, so its running time depends on its own data. Ring degree ` +
            `1024, the smallest row of the standard's table. No query expansion, no ` +
            `multi-dimensional indexing, no modulus switching. The secret key lives in ordinary ` +
            `browser memory. Nothing has been audited. Both "servers" are objects in this page.`,
        ]
      ),
      disclose('The construction, and where it comes from', [
        el(
          'p',
          {},
          `The protocol is SealPIR (Sebastian Angel, Hao Chen, Kim Laine and Srinath Setty, ` +
            `"PIR with Compressed Queries and Amortized Query Processing", IEEE Symposium on ` +
            `Security and Privacy, 2018) reduced to its direct one-hot form: the client encrypts a ` +
            `selection vector, the server takes a homomorphic inner product against its records, ` +
            `and one ciphertext comes back.`
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
          `Parameter security is quoted from the Homomorphic Encryption Security Standard ` +
            `(HomomorphicEncryption.org, November 2018), uniform ternary secret, classical column.`
        ),
      ]),
    ])
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
              `you asked for — and the query is one ciphertext per shelf position regardless of ` +
              `which position. That is one metadata channel this design genuinely closes.`,
          ]
        : [
            el('strong', {}, 'The sizes differ across rows. '),
            `That is because the shelf length or record size changed between queries, not because ` +
              `the index leaked — but it is exactly the shape of leak that padding exists to stop.`,
          ],
      { live: true }
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
    ['Which record was requested', 'Hidden by the protocol', 'Under decision RLWE at these parameters, and only then.'],
    ['Response length', 'Hidden by the protocol', 'One ciphertext, the same size for every index — fixed by construction.'],
    ['Query length', 'Hidden by the protocol', 'One ciphertext per shelf position, independent of which position.'],
    ['That a query happened', 'NOT hidden', 'The request is visible to anyone on the path.'],
    ['When it happened', 'NOT hidden', 'Timing is a deployment concern: batching or a fixed schedule, not PIR.'],
    ['How often, and how many', 'NOT hidden', 'Rate and count leak. Cover traffic is a separate mechanism.'],
    ['Who is asking', 'NOT hidden', 'Client identity and network address are outside the protocol entirely.'],
    ['The size of the database', 'NOT hidden', 'The shelf length is public; the query length announces it.'],
    ['Which records exist at all', 'NOT hidden', 'The server owns the shelf and can enumerate it.'],
    ['Whether the answer is honest', 'NOT hidden', 'PIR gives no integrity. A malicious server can return a lie with a matching tag.'],
    ['Access patterns over many queries', 'NOT hidden', 'Repeated queries are separately observable events; hiding the sequence is ORAM’s problem, not PIR’s.'],
  ];
  const table = el('table', { class: 'data' }, [
    el(
      'caption',
      {},
      'What single-server PIR hides, what it does not, and which of those come from the ' +
        'construction rather than from how it is deployed.'
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
        ' — Path ORAM (Stefanov et al., CCS 2013) hides the SEQUENCE of locations touched across ' +
          'many accesses, which is the row this page’s table marks as not hidden.',
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
    renderScope(root, lab);
  });
}

async function runQuery(root: HTMLElement, lab: Lab, index: number): Promise<void> {
  if (state.running) return;
  state.running = true;
  state.retired = null;
  renderScope(root, lab);
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
  renderScope(root, lab);
}
