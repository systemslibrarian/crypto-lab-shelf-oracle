/**
 * ChaCha20, RFC 8439 (Nir & Langley, 2018), hand-rolled.
 *
 * WHY THIS IS HERE AT ALL. Every sample this lab draws — the uniform ring
 * element `a`, the ternary secret key, the centred-binomial error, and the
 * random mask of the two-server comparison — has to come from somewhere, and
 * two properties are wanted at once:
 *
 *   - REAL randomness for a live run, so the encryptions on screen are genuine
 *     RLWE ciphertexts and not a scripted animation;
 *   - REPRODUCIBLE randomness on demand, so a learner can pin a seed, compare
 *     two runs coefficient for coefficient, and so the unit tests can assert
 *     exact bytes rather than statistical hand-waving.
 *
 * ChaCha20 gives both from one code path: seed it from `crypto.getRandomValues`
 * and it is a real CSPRNG; seed it from a typed-in string and the whole run
 * replays. It is also SYNCHRONOUS, which WebCrypto is not — polynomial sampling
 * inside a schoolbook multiply loop cannot await.
 *
 * And it is the one primitive in this lab with published test vectors, so the
 * randomness layer is anchored by real spec KATs (RFC 8439 §2.3.2 and §2.4.2)
 * rather than by agreeing with itself. See `chacha20.test.ts`.
 *
 * NOT a general-purpose cipher implementation: no AEAD, no Poly1305, and no
 * constant-time claim. It is a deterministic byte source for a teaching demo.
 */

/** "expand 32-byte k", the RFC 8439 §2.3 constants, as four little-endian words. */
const SIGMA = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574] as const;

/** 32-bit left rotation. `>>>` keeps the result unsigned. */
function rotl(x: number, n: number): number {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

/**
 * The quarter round, RFC 8439 §2.1, applied in place to four state words.
 *
 * Written out rather than looped: this is the part of ChaCha a reader is most
 * likely to want to check line-by-line against the RFC.
 */
function quarterRound(s: Uint32Array, a: number, b: number, c: number, d: number): void {
  s[a] = (s[a] + s[b]) >>> 0;
  s[d] = rotl(s[d] ^ s[a], 16);
  s[c] = (s[c] + s[d]) >>> 0;
  s[b] = rotl(s[b] ^ s[c], 12);
  s[a] = (s[a] + s[b]) >>> 0;
  s[d] = rotl(s[d] ^ s[a], 8);
  s[c] = (s[c] + s[d]) >>> 0;
  s[b] = rotl(s[b] ^ s[c], 7);
}

/** Read four bytes at `off` as a little-endian 32-bit word. */
function le32(b: Uint8Array, off: number): number {
  return (b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)) >>> 0;
}

/**
 * Build the 16-word initial state: constants, 8 key words, the block counter,
 * then 3 nonce words (RFC 8439 §2.3).
 */
export function chachaState(key: Uint8Array, counter: number, nonce: Uint8Array): Uint32Array {
  if (key.length !== 32) throw new RangeError(`ChaCha20 key must be 32 bytes, got ${key.length}`);
  if (nonce.length !== 12) throw new RangeError(`ChaCha20 nonce must be 12 bytes, got ${nonce.length}`);
  const s = new Uint32Array(16);
  s.set(SIGMA, 0);
  for (let i = 0; i < 8; i += 1) s[4 + i] = le32(key, i * 4);
  s[12] = counter >>> 0;
  for (let i = 0; i < 3; i += 1) s[13 + i] = le32(nonce, i * 4);
  return s;
}

/**
 * The block function, RFC 8439 §2.3: twenty rounds (ten column rounds each
 * followed by a diagonal round), then word-wise addition of the original state.
 *
 * Returns the 16 working words. Serialization to bytes is `serializeBlock`.
 */
export function chachaBlockWords(key: Uint8Array, counter: number, nonce: Uint8Array): Uint32Array {
  const initial = chachaState(key, counter, nonce);
  const s = initial.slice();
  for (let i = 0; i < 10; i += 1) {
    // column rounds
    quarterRound(s, 0, 4, 8, 12);
    quarterRound(s, 1, 5, 9, 13);
    quarterRound(s, 2, 6, 10, 14);
    quarterRound(s, 3, 7, 11, 15);
    // diagonal rounds
    quarterRound(s, 0, 5, 10, 15);
    quarterRound(s, 1, 6, 11, 12);
    quarterRound(s, 2, 7, 8, 13);
    quarterRound(s, 3, 4, 9, 14);
  }
  for (let i = 0; i < 16; i += 1) s[i] = (s[i] + initial[i]) >>> 0;
  return s;
}

/** Serialize 16 state words little-endian into 64 bytes (RFC 8439 §2.3). */
export function serializeBlock(words: Uint32Array): Uint8Array {
  const out = new Uint8Array(64);
  for (let i = 0; i < 16; i += 1) {
    const w = words[i];
    out[i * 4] = w & 0xff;
    out[i * 4 + 1] = (w >>> 8) & 0xff;
    out[i * 4 + 2] = (w >>> 16) & 0xff;
    out[i * 4 + 3] = (w >>> 24) & 0xff;
  }
  return out;
}

/** One 64-byte keystream block, as bytes. */
export function chachaBlock(key: Uint8Array, counter: number, nonce: Uint8Array): Uint8Array {
  return serializeBlock(chachaBlockWords(key, counter, nonce));
}

/**
 * XOR `data` with the keystream starting at `counter` (RFC 8439 §2.4).
 *
 * Present so the §2.4.2 encryption vector — the longer of the two published
 * KATs, and the one that exercises block-counter increment across a message
 * that is not a whole number of blocks — can be run as written.
 */
export function chacha20Xor(
  key: Uint8Array,
  counter: number,
  nonce: Uint8Array,
  data: Uint8Array
): Uint8Array {
  const out = new Uint8Array(data.length);
  for (let off = 0; off < data.length; off += 64) {
    const ks = chachaBlock(key, counter + Math.floor(off / 64), nonce);
    const end = Math.min(64, data.length - off);
    for (let i = 0; i < end; i += 1) out[off + i] = data[off + i] ^ ks[i];
  }
  return out;
}
