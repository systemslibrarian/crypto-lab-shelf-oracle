import type { Ciphertext } from './bfv';
import type { PirParams } from './params';

/**
 * Wire format for ciphertexts — and the reason the byte counts on the page are
 * measurements rather than arithmetic.
 *
 * The head-to-head exhibit compares this scheme against a two-server XOR PIR on
 * upload and download size. It would be very easy, and completely unfalsifiable,
 * to print `N * 2 * n * ceil(log2 q) / 8` and call it the query size. So the
 * query is actually SERIALIZED, bit-packed the way an implementation would send
 * it, and what the page reports is `bytes.length`.
 *
 * The packing is the obvious one: each coefficient occupies exactly
 * ceil(log2 q) bits, written little-endian-by-bit into a byte array. No
 * compression, no modulus switching, no seed-expansion trick for the uniform
 * half of the ciphertext — all three are real and all three are out of scope.
 * The seed trick in particular is worth naming, because it would halve every
 * number in the upload column: c1 is uniform, so a real client sends the 32-byte
 * seed it was expanded from instead of the polynomial. This lab sends the
 * polynomial, and the comparison says so.
 */

/** Bits each coefficient occupies on the wire. */
export function bitsPerCoefficient(q: number): number {
  return Math.ceil(Math.log2(q));
}

/** Bytes one serialized ciphertext occupies. */
export function ciphertextBytes(p: PirParams): number {
  return Math.ceil((2 * p.n * bitsPerCoefficient(p.q)) / 8);
}

class BitWriter {
  private readonly bytes: Uint8Array;
  private bitPos = 0;

  constructor(totalBits: number) {
    this.bytes = new Uint8Array(Math.ceil(totalBits / 8));
  }

  write(value: number, width: number): void {
    for (let i = 0; i < width; i += 1) {
      if ((value >>> i) & 1) {
        this.bytes[(this.bitPos >> 3)] |= 1 << (this.bitPos & 7);
      }
      this.bitPos += 1;
    }
  }

  done(): Uint8Array {
    return this.bytes;
  }
}

class BitReader {
  private bitPos = 0;
  constructor(private readonly bytes: Uint8Array) {}

  read(width: number): number {
    let v = 0;
    for (let i = 0; i < width; i += 1) {
      if ((this.bytes[this.bitPos >> 3] >> (this.bitPos & 7)) & 1) v |= 1 << i;
      this.bitPos += 1;
    }
    return v >>> 0;
  }
}

/** Serialize one ciphertext: c0 then c1, coefficient by coefficient. */
export function serializeCiphertext(p: PirParams, ct: Ciphertext): Uint8Array {
  const width = bitsPerCoefficient(p.q);
  const w = new BitWriter(2 * p.n * width);
  for (let i = 0; i < p.n; i += 1) w.write(ct.c0[i], width);
  for (let i = 0; i < p.n; i += 1) w.write(ct.c1[i], width);
  return w.done();
}

/** Read a ciphertext back. Round-tripped in the tests, not assumed. */
export function deserializeCiphertext(p: PirParams, bytes: Uint8Array): Ciphertext {
  const width = bitsPerCoefficient(p.q);
  const r = new BitReader(bytes);
  const c0 = new Int32Array(p.n);
  const c1 = new Int32Array(p.n);
  for (let i = 0; i < p.n; i += 1) c0[i] = r.read(width);
  for (let i = 0; i < p.n; i += 1) c1[i] = r.read(width);
  return { c0, c1 };
}

/** Serialize a whole query — the N ciphertexts of the one-hot selection vector. */
export function serializeQuery(p: PirParams, query: readonly Ciphertext[]): Uint8Array {
  const per = ciphertextBytes(p);
  const out = new Uint8Array(per * query.length);
  query.forEach((ct, i) => out.set(serializeCiphertext(p, ct), i * per));
  return out;
}
