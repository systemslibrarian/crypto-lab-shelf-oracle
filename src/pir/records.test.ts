import { describe, expect, it } from 'vitest';
import {
  buildRecord,
  bytesToCoefficients,
  coefficientsFor,
  coefficientsToBytes,
  recordText,
  sha256,
  TAG_BYTES,
  toHex,
  truncateUtf8,
} from './records';
import { CATALOG, CATALOG_SIZE, entryText, shelfEntries } from '../data/catalog';
import { RECORD_SIZES } from './params';
import {
  bitsPerCoefficient,
  ciphertextBytes,
  deserializeCiphertext,
  serializeCiphertext,
  serializeQuery,
} from './serialize';
import { defaultParams, makeParams, MODULI } from './params';
import { encryptScalar, keyGen } from './bfv';
import { buildQuery } from './pir';
import { Rng } from './rng';
import { assessSecurity, HES_TERNARY_CLASSICAL } from './security';

const P = defaultParams();

describe('record encoding', () => {
  it('packs and unpacks every byte value', () => {
    const bytes = new Uint8Array(256);
    for (let i = 0; i < 256; i += 1) bytes[i] = i;
    const coeffs = bytesToCoefficients(bytes, 1024);
    for (let i = 0; i < 256; i += 1) {
      expect(coeffs[2 * i]).toBe(i & 0x0f);
      expect(coeffs[2 * i + 1]).toBe((i >> 4) & 0x0f);
    }
    const { bytes: back, outOfRange } = coefficientsToBytes(coeffs, 256);
    expect(outOfRange).toBe(0);
    expect(Array.from(back)).toEqual(Array.from(bytes));
  });

  it('every packed coefficient is a nibble, leaving t = 17 one value spare', () => {
    const bytes = new Uint8Array(512);
    for (let i = 0; i < 512; i += 1) bytes[i] = (i * 37) & 0xff;
    const coeffs = bytesToCoefficients(bytes, 1024);
    for (let i = 0; i < 1024; i += 1) {
      expect(coeffs[i]).toBeGreaterThanOrEqual(0);
      expect(coeffs[i]).toBeLessThan(16);
    }
  });

  it('reports a coefficient a real record could never contain', () => {
    const coeffs = new Int32Array(8);
    coeffs[0] = 16; // t - 1: encodable in Z_t, not producible by the encoder
    coeffs[3] = 16;
    const { outOfRange } = coefficientsToBytes(coeffs, 4);
    expect(outOfRange).toBe(2);
  });

  it('coefficientsFor matches the packing density', () => {
    for (const size of RECORD_SIZES) expect(coefficientsFor(size)).toBe(size * 2);
  });

  it('a record carries its own tag, and the tag notices a flipped bit', async () => {
    const record = await buildRecord('Pride and Prejudice / Jane Austen. 1813.', 512);
    expect(record.length).toBe(512);
    const payload = record.subarray(0, 512 - TAG_BYTES);
    const expected = (await sha256(payload)).subarray(0, TAG_BYTES);
    expect(toHex(record.subarray(512 - TAG_BYTES))).toBe(toHex(expected));

    const tampered = record.slice();
    tampered[10] ^= 0x01;
    const tamperedTag = (await sha256(tampered.subarray(0, 512 - TAG_BYTES))).subarray(0, TAG_BYTES);
    expect(toHex(tamperedTag)).not.toBe(toHex(expected));
  });

  it('record text survives the round trip and the padding is trimmed', async () => {
    const text = entryText(CATALOG[7]);
    const record = await buildRecord(text, 512);
    expect(recordText(record)).toBe(text);
  });

  it('a short record truncates visibly rather than silently corrupting', async () => {
    // Every entry, at every record size: what comes back must be a PREFIX of
    // what went in, and must never contain U+FFFD. The em dash in every entry
    // is three UTF-8 bytes and the 112-byte payload lands near it on most of the
    // shelf, so a naive byte cut would put a replacement character on the page.
    for (const size of RECORD_SIZES) {
      for (const entry of CATALOG) {
        const text = entryText(entry);
        const got = recordText(await buildRecord(text, size));
        expect(text.startsWith(got)).toBe(true);
        expect(got).not.toContain('\ufffd');
      }
    }
    // And the shortest size really does truncate — otherwise the check above
    // would be vacuous.
    const full = entryText(CATALOG[7]);
    expect(recordText(await buildRecord(full, 128)).length).toBeLessThan(full.length);
  });

  it('truncateUtf8 never splits a multi-byte sequence', () => {
    const bytes = new TextEncoder().encode('LC class PR \u2014 English literature');
    for (let max = 0; max <= bytes.length; max += 1) {
      const cut = truncateUtf8(bytes, max);
      expect(cut).toBeLessThanOrEqual(max);
      expect(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, cut))).toBeTypeOf(
        'string'
      );
    }
  });

  it('every catalog entry fits the largest record size', async () => {
    for (const entry of CATALOG) {
      const text = entryText(entry);
      const encoded = new TextEncoder().encode(text);
      expect(encoded.length).toBeLessThanOrEqual(512 - TAG_BYTES);
      const record = await buildRecord(text, 512);
      expect(recordText(record)).toBe(text);
    }
  });

  it('the catalog is 64 distinct titles with sequential ids', () => {
    expect(CATALOG_SIZE).toBe(64);
    expect(new Set(CATALOG.map((e) => e.title)).size).toBe(64);
    CATALOG.forEach((e, i) => expect(e.id).toBe(i));
  });

  it('a longer shelf tiles the catalog and keeps ids unique', () => {
    const shelf = shelfEntries(256);
    expect(shelf.length).toBe(256);
    expect(new Set(shelf.map((e) => e.id)).size).toBe(256);
    expect(shelf[64].title).toBe(CATALOG[0].title);
  });
});

describe('wire format', () => {
  it('a ciphertext round-trips through the bit packing', () => {
    const rng = Rng.fromSeed('serialize');
    const sk = keyGen(P, rng);
    const ct = encryptScalar(P, sk, 1, rng);
    const bytes = serializeCiphertext(P, ct);
    const back = deserializeCiphertext(P, bytes);
    expect(Array.from(back.c0)).toEqual(Array.from(ct.c0));
    expect(Array.from(back.c1)).toEqual(Array.from(ct.c1));
  });

  it('round-trips at every selectable modulus', () => {
    const rng = Rng.fromSeed('serialize-moduli');
    for (const option of MODULI) {
      const p = makeParams(option.q, 512);
      const sk = keyGen(p, rng);
      const ct = encryptScalar(p, sk, 5, rng);
      const back = deserializeCiphertext(p, serializeCiphertext(p, ct));
      expect(Array.from(back.c0)).toEqual(Array.from(ct.c0));
      expect(Array.from(back.c1)).toEqual(Array.from(ct.c1));
    }
  });

  it('the reported size is the measured size, not a formula', () => {
    // The head-to-head exhibit prints these numbers. `ciphertextBytes` is the
    // arithmetic; `serializeCiphertext(...).length` is the fact. They must agree
    // or one of the two is decoration.
    const rng = Rng.fromSeed('serialize-size');
    const sk = keyGen(P, rng);
    const ct = encryptScalar(P, sk, 0, rng);
    expect(serializeCiphertext(P, ct).length).toBe(ciphertextBytes(P));
    expect(bitsPerCoefficient(P.q)).toBe(26);
  });

  it('a whole query serializes to N ciphertexts and nothing else', () => {
    const rng = Rng.fromSeed('serialize-query');
    const sk = keyGen(P, rng);
    const query = buildQuery(P, sk, 3, 16, rng);
    expect(serializeQuery(P, query.ciphertexts).length).toBe(16 * ciphertextBytes(P));
  });
});

describe('parameters against the published table', () => {
  /**
   * SPEC KAT — Homomorphic Encryption Security Standard (HomomorphicEncryption.org,
   * November 2018), uniform ternary secret, classical security. These are the
   * published ceilings, quoted; the lookup is checked against them.
   */
  const PUBLISHED: Array<[number, number, number]> = [
    [1024, 128, 27],
    [2048, 128, 54],
    [4096, 128, 109],
    [8192, 128, 218],
    [16384, 128, 438],
    [32768, 128, 881],
    [1024, 192, 19],
    [2048, 192, 37],
    [4096, 192, 75],
    [8192, 192, 152],
    [16384, 192, 305],
    [32768, 192, 611],
    [1024, 256, 14],
    [2048, 256, 29],
    [4096, 256, 58],
    [8192, 256, 118],
    [16384, 256, 237],
    [32768, 256, 476],
  ];

  it.each(PUBLISHED)('n = %i at %i-bit classical security allows log2 q <= %i', (n, level, ceiling) => {
    expect(HES_TERNARY_CLASSICAL[n][level]).toBe(ceiling);
  });

  it('the shipped default sits inside the 128-bit row', () => {
    const a = assessSecurity(P);
    expect(a.logQ).toBe(26);
    expect(a.ceiling128).toBe(27);
    expect(a.inTable).toBe(true);
    expect(a.level).toBe(128);
    expect(a.summary).toContain('128-bit');
  });

  it('the largest selectable modulus leaves the table, and the assessment says so', () => {
    const a = assessSecurity(makeParams(MODULI[MODULI.length - 1].q, 512));
    expect(a.logQ).toBe(30);
    expect(a.inTable).toBe(false);
    expect(a.level).toBe(0);
    expect(a.summary).toContain('exceeds');
  });

  it('every modulus below the top one stays inside the table', () => {
    for (const option of MODULI.slice(0, -1)) {
      expect(assessSecurity(makeParams(option.q, 512)).inTable).toBe(true);
    }
  });

  it('a ring degree the table does not carry is reported as uncovered, not as safe', () => {
    const a = assessSecurity({ ...P, n: 512 });
    expect(a.inTable).toBe(false);
    expect(a.ceiling128).toBeNull();
    expect(a.summary).toContain('not a row');
  });

  it('log2 q is ceiled, so a modulus just over a boundary cannot round into the table', () => {
    // 2^27 + 1 must read as 28 bits, not 27.
    const a = assessSecurity({ ...P, q: 2 ** 27 + 1 });
    expect(a.logQ).toBe(28);
    expect(a.inTable).toBe(false);
  });
});
