import { BITS_PER_COEFF, type PirParams } from './params';

/**
 * Turning a catalog record into a plaintext ring element, and back.
 *
 * FOUR BITS PER COEFFICIENT. The plaintext modulus is 17, so a coefficient can
 * hold any value in [0, 17). Records are packed a nibble at a time, using
 * [0, 16) and leaving one value spare — the spare is what makes a decode
 * failure detectable rather than merely wrong, because a coefficient that comes
 * back as 16 cannot have been written by the encoder.
 *
 * A 512-byte record therefore occupies 1024 coefficients, the whole ring. The
 * record-size control shortens that, which is the honest form of "less payload,
 * less noise": the server multiplies fewer nonzero plaintext coefficients into
 * the answer, so less of every record's error lands in it.
 *
 * THE INTEGRITY TAG. The last 16 bytes of every record are the first 16 bytes of
 * SHA-256 over the payload that precedes them. A client that decodes a record
 * can recompute the tag and know whether the answer survived the noise — which
 * is how the exhaustion exhibit distinguishes "the budget ran out" from "you
 * happened to get a plausible-looking string".
 *
 * IT IS NOT A SECURITY MECHANISM, and the page says so beside it. The tag is
 * part of the record the server holds, so a server that wants to lie can put a
 * matching tag on a lie. PIR gives no integrity guarantee at all; this is a
 * decode check, nothing more.
 */

/** Bytes of SHA-256 kept as the trailing integrity tag. */
export const TAG_BYTES = 16;

/** How many plaintext coefficients a record of `bytes` bytes occupies. */
export function coefficientsFor(bytes: number): number {
  return bytes * (8 / BITS_PER_COEFF);
}

/**
 * Pack record bytes into plaintext coefficients, low nibble first.
 *
 * Coefficients past the record are left at zero. They still cost nothing: a
 * zero plaintext coefficient contributes no product at all (see `mulAccumulate`).
 */
export function bytesToCoefficients(bytes: Uint8Array, n: number): Int32Array {
  const out = new Int32Array(n);
  const limit = Math.min(bytes.length, Math.floor(n / 2));
  for (let i = 0; i < limit; i += 1) {
    out[2 * i] = bytes[i] & 0x0f;
    out[2 * i + 1] = (bytes[i] >> 4) & 0x0f;
  }
  return out;
}

/**
 * Unpack coefficients back into bytes.
 *
 * Any coefficient outside [0, 16) is reported rather than masked away: it is
 * proof the answer decoded wrong, and the caller turns it into a failure code.
 */
export function coefficientsToBytes(
  coeffs: Int32Array,
  byteLength: number
): { bytes: Uint8Array; outOfRange: number } {
  const bytes = new Uint8Array(byteLength);
  let outOfRange = 0;
  for (let i = 0; i < byteLength; i += 1) {
    const lo = coeffs[2 * i];
    const hi = coeffs[2 * i + 1];
    if (lo < 0 || lo > 15) outOfRange += 1;
    if (hi < 0 || hi > 15) outOfRange += 1;
    bytes[i] = ((hi & 0x0f) << 4) | (lo & 0x0f);
  }
  return { bytes, outOfRange };
}

/**
 * SHA-256 over `data`, via WebCrypto. Async because WebCrypto is; every caller
 * that needs a tag is already building or checking a record, not inside a
 * polynomial loop.
 */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const buffer = new ArrayBuffer(data.length);
  new Uint8Array(buffer).set(data);
  const digest = await crypto.subtle.digest('SHA-256', buffer);
  return new Uint8Array(digest);
}

/**
 * The largest cut point at or below `max` that does not split a UTF-8 sequence.
 *
 * The smallest record size holds 112 payload bytes, which lands mid-title on
 * most of the shelf — and several titles carry an em dash or an accented letter
 * within reach of that boundary. Cutting a multi-byte sequence in half would
 * decode to U+FFFD, and a page whose subject is "did the answer survive the
 * noise" cannot afford a replacement character that the encoder put there.
 */
export function truncateUtf8(bytes: Uint8Array, max: number): number {
  if (bytes.length <= max) return bytes.length;
  // Walk back over continuation bytes (10xxxxxx). Stopping on a byte that is
  // not one means everything before it is a whole number of sequences: from
  // well-formed UTF-8, a non-continuation byte is always a sequence start.
  let cut = max;
  while (cut > 0 && (bytes[cut] & 0xc0) === 0x80) cut -= 1;
  return cut;
}

/**
 * Lay out a record: UTF-8 text padded with spaces to `byteLength - TAG_BYTES`,
 * then the truncated SHA-256 tag.
 *
 * Space padding rather than zero padding so a decoded record is directly
 * readable; the tag covers the padding too, so trailing whitespace is not a
 * place a corrupt answer can hide.
 */
export async function buildRecord(text: string, byteLength: number): Promise<Uint8Array> {
  if (byteLength <= TAG_BYTES) {
    throw new RangeError(`record must be longer than its ${TAG_BYTES}-byte tag`);
  }
  const payloadLength = byteLength - TAG_BYTES;
  const payload = new Uint8Array(payloadLength).fill(0x20);
  const encoded = new TextEncoder().encode(text);
  payload.set(encoded.subarray(0, truncateUtf8(encoded, payloadLength)));
  const tag = (await sha256(payload)).subarray(0, TAG_BYTES);
  const record = new Uint8Array(byteLength);
  record.set(payload, 0);
  record.set(tag, payloadLength);
  return record;
}

/** Recompute a record's tag and compare it. Constant-time comparison is not the
 *  point here — the tag is public and so is the record. */
export async function tagMatches(record: Uint8Array): Promise<boolean> {
  if (record.length <= TAG_BYTES) return false;
  const payloadLength = record.length - TAG_BYTES;
  const expected = (await sha256(record.subarray(0, payloadLength))).subarray(0, TAG_BYTES);
  for (let i = 0; i < TAG_BYTES; i += 1) {
    if (record[payloadLength + i] !== expected[i]) return false;
  }
  return true;
}

/** The readable half of a record, with the padding trimmed off. */
export function recordText(record: Uint8Array): string {
  const payload = record.subarray(0, Math.max(0, record.length - TAG_BYTES));
  return new TextDecoder().decode(payload).replace(/\s+$/, '');
}

/** Encode a whole shelf as plaintext ring elements, ready for the server. */
export function shelfToPlaintexts(records: readonly Uint8Array[], p: PirParams): Int32Array[] {
  return records.map((r) => bytesToCoefficients(r, p.n));
}

/** Hex, for the byte views the page draws. */
export function toHex(bytes: Uint8Array, limit = bytes.length): string {
  let out = '';
  const end = Math.min(limit, bytes.length);
  for (let i = 0; i < end; i += 1) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}
