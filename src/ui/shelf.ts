import { append, card, clear, disclose, el, kv, scroller, verdict } from './dom';
import type { Lab } from './state';
import { RECORD_SIZES, SHELF_SIZES } from '../pir/params';
import { recordText, TAG_BYTES, toHex } from '../pir/records';
import { CATALOG_SIZE } from '../data/catalog';

/**
 * Act one: the shelf.
 *
 * Everything downstream is about hiding WHICH of these the reader wants, so the
 * first thing to establish is that a record is a record — 512 bytes of catalog
 * text, not an availability bit. The nibble packing is shown from the actual
 * selected record rather than described, because "four bits per coefficient" is
 * a sentence and the numbers are a fact.
 */
export function renderShelf(root: HTMLElement, lab: Lab): void {
  clear(root);
  const s = lab.snapshot();
  const entry = s.entries[s.selectedIndex];
  const record = s.records[s.selectedIndex];

  append(
    root,
    card('Pick a book', [
      el(
        'p',
        { class: 'lede' },
        `Sixty-four public-domain works. Choose one — that choice, and nothing else, is what the ` +
          `rest of this lab hides from the server. The shelf position you pick is the only secret ` +
          `in the protocol.`
      ),
      shelfControls(lab),
      el(
        'div',
        { class: 'shelf-grid', role: 'list', 'aria-label': 'Catalog shelf' },
        s.entries.map((item, index) =>
          el(
            'div',
            { role: 'listitem' },
            el(
              'button',
              {
                class: 'shelf-item',
                type: 'button',
                'aria-pressed': index === s.selectedIndex ? 'true' : 'false',
                'data-index': index,
              },
              [
                el('span', { class: 'shelf-pos' }, `position ${index}`),
                el('span', { class: 'shelf-title' }, item.title),
                el('span', { class: 'shelf-author' }, `${item.author} · ${item.year} · ${item.lcClass}`),
              ]
            )
          )
        )
      ),
    ])
  );

  append(
    root,
    card('The record the protocol will return', [
      el(
        'p',
        { class: 'lede' },
        `This is the exact byte string a successful query hands back. Not a flag, not a row id — ` +
          `the record itself.`
      ),
      verdict('info', [
        el('strong', {}, `Position ${s.selectedIndex}: `),
        entry.title,
        ' / ',
        entry.author,
      ]),
      el('code', { class: 'code' }, recordText(record)),
      kv([
        ['Record size', `${s.recordBytes} bytes (${s.recordBytes - TAG_BYTES} payload + ${TAG_BYTES}-byte SHA-256 tag)`],
        ['Plaintext coefficients', `${s.params.coeffsUsed} of ${s.params.n} (4 bits each)`],
        ['Integrity tag', toHex(record.subarray(record.length - TAG_BYTES))],
        ['First 32 bytes', toHex(record, 32)],
      ]),
      packingDisclosure(record, s.params.coeffsUsed),
    ])
  );

  append(root, card('This run', runControls(lab)));

  bind(root, lab);
}

function shelfControls(lab: Lab): HTMLElement {
  const s = lab.snapshot();
  const recordSelect = el(
    'select',
    { id: 'shelf-record-size', 'data-role': 'record-size' },
    RECORD_SIZES.map((size) =>
      el('option', { value: size, selected: size === s.recordBytes }, `${size} bytes`)
    )
  );
  const shelfSelect = el(
    'select',
    { id: 'shelf-size', 'data-role': 'shelf-size' },
    SHELF_SIZES.map((size) =>
      el('option', { value: size, selected: size === s.shelfSize }, `${size} records`)
    )
  );

  return el('div', { class: 'controls' }, [
    el('div', { class: 'field' }, [
      el('label', { for: 'shelf-record-size' }, 'Record size'),
      recordSelect,
    ]),
    el('div', { class: 'field' }, [el('label', { for: 'shelf-size' }, 'Shelf length'), shelfSelect]),
    el(
      'p',
      { class: 'inline-note' },
      s.shelfSize > CATALOG_SIZE
        ? `Past ${CATALOG_SIZE} the catalog is tiled: positions ${CATALOG_SIZE} and up repeat earlier ` +
          `titles. Noise growth and server cost depend on how many records there are, not on ` +
          `whether they differ, so a tiled shelf measures the real cost of a longer one.`
        : `A longer shelf means one more ciphertext to send and one more homomorphic multiply to ` +
          `perform, per query. Both costs are measured on the other tabs.`
    ),
  ]);
}

/**
 * The run's randomness, and the honest warning that goes with pinning it.
 *
 * Every ciphertext on this page is drawn from a ChaCha20 stream. By default that
 * stream is seeded from `crypto.getRandomValues`, which is what makes a live run
 * a real one. Pinning a seed makes the entire run reproducible — two people can
 * compare identical ciphertexts coefficient by coefficient, and a surprising
 * result can be replayed instead of described.
 *
 * It also makes the SECRET KEY reproducible, which is exactly why the warning
 * is not a footnote.
 */
function runControls(lab: Lab): HTMLElement[] {
  const s = lab.snapshot();
  return [
    el(
      'p',
      { class: 'lede' },
      `Every random value this lab draws — the uniform ring elements, the ternary secret key, the ` +
        `centred-binomial error, the two-server masks — comes from one ChaCha20 stream, checked ` +
        `against the RFC 8439 test vectors in the unit suite.`
    ),
    el('div', { class: 'controls' }, [
      el('div', { class: 'field' }, [
        el('label', { for: 'run-seed' }, 'Run seed'),
        el('input', {
          type: 'text',
          id: 'run-seed',
          'data-role': 'seed',
          value: s.seed ?? '',
          placeholder: 'e.g. shelf-oracle',
          maxlength: '40',
        }),
      ]),
      el('button', { class: 'btn', type: 'button', 'data-role': 'pin-seed' }, 'Pin this seed'),
      el(
        'button',
        { class: 'btn', type: 'button', 'data-role': 'unpin-seed', disabled: s.seed === null },
        'Back to platform entropy'
      ),
      el('button', { class: 'btn', type: 'button', 'data-role': 'new-key' }, 'Draw a new secret key'),
    ]),
    el(
      'div',
      { role: 'status', 'aria-live': 'polite', 'data-role': 'seed-status' },
      s.seed === null
        ? verdict('pass', [
            el('strong', {}, 'Seeded from platform entropy. '),
            'The secret key was drawn from crypto.getRandomValues and is not reproducible.',
          ])
        : verdict('alarm', [
            el('strong', {}, `Pinned to "${s.seed}". `),
            'This whole run is now reproducible by anyone who knows that string — INCLUDING the ' +
              'secret key. That is the point of the control, and it is exactly why a real system ' +
              'must never do it.',
          ])
    ),
  ];
}

function packingDisclosure(record: Uint8Array, coeffsUsed: number): HTMLElement {
  const rows = el('table', { class: 'data' }, [
    el('caption', {}, 'The first eight bytes of this record, as the plaintext polynomial sees them.'),
    el(
      'thead',
      {},
      el('tr', {}, [
        el('th', {}, 'Byte'),
        el('th', { class: 'num' }, 'Value'),
        el('th', {}, 'Character'),
        el('th', { class: 'num' }, 'Low nibble'),
        el('th', { class: 'num' }, 'High nibble'),
        el('th', {}, 'Coefficients'),
      ])
    ),
    el(
      'tbody',
      {},
      Array.from({ length: 8 }, (_unused, i) =>
        el('tr', {}, [
          el('td', { class: 'num' }, String(i)),
          el('td', { class: 'num' }, `0x${record[i].toString(16).padStart(2, '0')}`),
          el('td', {}, JSON.stringify(String.fromCharCode(record[i]))),
          el('td', { class: 'num' }, String(record[i] & 0x0f)),
          el('td', { class: 'num' }, String((record[i] >> 4) & 0x0f)),
          el('td', { class: 'num' }, `${2 * i}, ${2 * i + 1}`),
        ])
      )
    ),
  ]);

  return disclose('How a record becomes a polynomial', [
    el(
      'p',
      {},
      `The plaintext modulus is t = 17, so one coefficient holds any value from 0 to 16. Records ` +
        `are packed four bits at a time and use only 0 to 15 — the seventeenth value is left ` +
        `unused on purpose, because a coefficient that comes back as 16 could not have been ` +
        `written by the encoder and is therefore proof that the answer decoded wrong.`
    ),
    el(
      'p',
      {},
      `That is why this record occupies ${coeffsUsed} coefficients: two per byte. Doubling the ` +
        `record size doubles the number of nonzero coefficients the server multiplies, and every ` +
        `one of them scales up somebody's encryption noise. Bigger records cost budget. You can ` +
        `watch that happen on the Noise Exhaustion tab.`
    ),
    scroller('Byte-to-coefficient packing table', rows),
  ]);
}

function bind(root: HTMLElement, lab: Lab): void {
  root.querySelectorAll<HTMLButtonElement>('.shelf-item').forEach((button) => {
    button.addEventListener('click', () => {
      lab.setSelectedIndex(Number(button.dataset.index));
    });
  });
  const recordSelect = root.querySelector<HTMLSelectElement>('[data-role="record-size"]');
  recordSelect?.addEventListener('change', () => {
    void lab.setRecordBytes(Number(recordSelect.value));
  });
  const shelfSelect = root.querySelector<HTMLSelectElement>('[data-role="shelf-size"]');
  shelfSelect?.addEventListener('change', () => {
    void lab.setShelfSize(Number(shelfSelect.value));
  });

  const seedInput = root.querySelector<HTMLInputElement>('[data-role="seed"]');
  root.querySelector<HTMLButtonElement>('[data-role="pin-seed"]')?.addEventListener('click', () => {
    const value = (seedInput?.value ?? '').trim();
    void lab.setSeed(value === '' ? null : value);
  });
  root.querySelector<HTMLButtonElement>('[data-role="unpin-seed"]')?.addEventListener('click', () => {
    void lab.setSeed(null);
  });
  root.querySelector<HTMLButtonElement>('[data-role="new-key"]')?.addEventListener('click', () => {
    lab.regenerateKey();
  });
}
