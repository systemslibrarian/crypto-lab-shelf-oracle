import { assertIndexInRange } from './params';
import { PirError } from './errors';
import type { Rng } from './rng';

/**
 * Two-server information-theoretic PIR — Chor, Goldreich, Kushilevitz and Sudan,
 * *Private Information Retrieval*, FOCS 1995, the basic XOR construction.
 *
 * WHY IT IS IN THIS REPO. The head-to-head exhibit compares one-server
 * computational PIR against two-server information-theoretic PIR on the SAME
 * catalog, with measured bytes and measured milliseconds. Citing Oblivious
 * Shelf's numbers would not do: that lab runs this scheme over a 16-entry shelf
 * of single BITS, so its costs are not this lab's costs. The only way to compare
 * honestly is to run both protocols here, over identical 512-byte records, and
 * report what each actually moved.
 *
 * THE PROTOCOL.
 *   1. The client draws a uniformly random N-bit mask r.
 *   2. Server A receives r. Server B receives r XOR e_index.
 *   3. Each server returns the XOR of every record its mask selects.
 *   4. The client XORs the two replies. Every record selected by both cancels;
 *      the only survivor is the one position where the masks differ.
 *
 * WHY IT IS INFORMATION-THEORETIC. Each server sees a uniformly random mask, on
 * its own. r is uniform by construction, and r XOR e_index is uniform because
 * XOR with a fixed string is a bijection. No computational assumption anywhere,
 * and no parameter that could be too small.
 *
 * WHAT IT COSTS, AND THIS IS THE POINT OF THE WHOLE LAB. The two masks differ in
 * exactly one position, so a server that can see both recovers the index by a
 * single XOR — `colludeRecoverIndex` below does it in one line. That assumption
 * is what single-server PIR buys its way out of.
 */

export interface XorQuery {
  /** The mask sent to server A: uniformly random. */
  readonly maskA: Uint8Array;
  /** The mask sent to server B: maskA with the target bit flipped. */
  readonly maskB: Uint8Array;
  /** How many shelf positions the masks cover. */
  readonly shelfSize: number;
}

function bit(mask: Uint8Array, i: number): number {
  return (mask[i >> 3] >> (i & 7)) & 1;
}

function flipBit(mask: Uint8Array, i: number): void {
  mask[i >> 3] ^= 1 << (i & 7);
}

/** Build both masks. */
export function buildXorQuery(shelfSize: number, index: number, rng: Rng): XorQuery {
  assertIndexInRange(index, shelfSize);
  const byteLength = Math.ceil(shelfSize / 8);
  const maskA = new Uint8Array(byteLength);
  rng.fill(maskA);
  // Clear any bits past the shelf: a set bit there would select a record that
  // does not exist, and the two servers would disagree about the shelf length.
  for (let i = shelfSize; i < byteLength * 8; i += 1) {
    if (bit(maskA, i)) flipBit(maskA, i);
  }
  const maskB = maskA.slice();
  flipBit(maskB, index);
  return { maskA, maskB, shelfSize };
}

/**
 * One server's reply: the XOR of every record its mask selects.
 *
 * Like `serverAnswer` in `pir.ts`, this takes the shelf and a mask and nothing
 * else. There is no argument through which the index could arrive.
 */
export function xorAnswer(shelf: readonly Uint8Array[], mask: Uint8Array): Uint8Array {
  if (shelf.length === 0) throw new PirError('DIM_MISMATCH', 'the shelf is empty');
  const recordLength = shelf[0].length;
  const out = new Uint8Array(recordLength);
  for (let i = 0; i < shelf.length; i += 1) {
    if (!bit(mask, i)) continue;
    const record = shelf[i];
    if (record.length !== recordLength) {
      throw new PirError(
        'DIM_MISMATCH',
        `record ${i} is ${record.length} bytes but record 0 is ${recordLength}`
      );
    }
    for (let j = 0; j < recordLength; j += 1) out[j] ^= record[j];
  }
  return out;
}

/** Combine the two replies. */
export function combineXorAnswers(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== b.length) {
    throw new PirError('DIM_MISMATCH', `replies are ${a.length} and ${b.length} bytes`);
  }
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i += 1) out[i] = a[i] ^ b[i];
  return out;
}

/**
 * The collusion attack, in full.
 *
 * XOR the two masks and the result is e_index — a string with exactly one bit
 * set, at the position the client asked for. There is no work to do and no
 * parameter to weaken: the moment the two servers compare notes, the query is
 * plaintext. Returns -1 if the masks differ in a number of positions other than
 * one, which is what a client deviating from the protocol would look like.
 */
export function colludeRecoverIndex(query: XorQuery): number {
  let found = -1;
  for (let i = 0; i < query.shelfSize; i += 1) {
    if (bit(query.maskA, i) !== bit(query.maskB, i)) {
      if (found !== -1) return -1;
      found = i;
    }
  }
  return found;
}

/** How many shelf positions a mask selects — the server's share of the work. */
export function maskWeight(mask: Uint8Array, shelfSize: number): number {
  let w = 0;
  for (let i = 0; i < shelfSize; i += 1) w += bit(mask, i);
  return w;
}
