import { chachaBlock } from './chacha20';

/**
 * The lab's sampler: a ChaCha20 keystream with the three draws RLWE needs.
 *
 * Nothing here is a "random-looking number generator". Every draw is a real
 * rejection- or binomial-sampled value taken from the keystream, so the
 * ciphertexts on the page are ciphertexts and not decoration.
 *
 * SEEDS ARE A REPRODUCIBILITY HANDLE, NOT A SECRET. `Rng.fromEntropy()` seeds
 * from `crypto.getRandomValues` and is what a live run uses. `Rng.fromSeed(s)`
 * derives the ChaCha key from the text a learner typed, which makes the whole
 * run — INCLUDING THE SECRET KEY — reproducible by anyone with that string.
 * That is the point of it (compare two runs, replay a failure, pin a test), and
 * it is exactly why it would be catastrophic outside a teaching demo. The page
 * says so where the control lives.
 */
export class Rng {
  private readonly key: Uint8Array;
  private readonly nonce: Uint8Array;
  private counter: number;
  private block: Uint8Array;
  private offset: number;
  /** Bytes consumed, so the page can report the cost of a run honestly. */
  private consumed: number;

  private constructor(key: Uint8Array, nonce: Uint8Array) {
    this.key = key;
    this.nonce = nonce;
    this.counter = 0;
    this.block = chachaBlock(key, 0, nonce);
    this.offset = 0;
    this.consumed = 0;
  }

  /** A live run: 32 bytes from the platform CSPRNG. */
  static fromEntropy(): Rng {
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);
    return new Rng(key, new Uint8Array(12));
  }

  /**
   * A reproducible run from a printable seed.
   *
   * The seed's UTF-8 bytes are XORed into a zero key, wrapping every 32 bytes,
   * with the length folded in so `"ab"` and `"ab\0"` differ. This is NOT a key
   * derivation function and is not trying to be one — the seed is public by
   * construction, so stretching it would only imply a secrecy this control does
   * not have.
   */
  static fromSeed(seed: string): Rng {
    const bytes = new TextEncoder().encode(seed);
    const key = new Uint8Array(32);
    key[31] = bytes.length & 0xff;
    for (let i = 0; i < bytes.length; i += 1) key[i % 32] ^= bytes[i];
    return new Rng(key, new Uint8Array(12));
  }

  /** How many keystream bytes this run has drawn so far. */
  get bytesDrawn(): number {
    return this.consumed;
  }

  private nextByte(): number {
    if (this.offset === 64) {
      this.counter += 1;
      this.block = chachaBlock(this.key, this.counter, this.nonce);
      this.offset = 0;
    }
    this.consumed += 1;
    return this.block[this.offset++];
  }

  /** Fill a buffer from the keystream. */
  fill(out: Uint8Array): void {
    for (let i = 0; i < out.length; i += 1) out[i] = this.nextByte();
  }

  /** An unsigned 32-bit word, little-endian over four keystream bytes. */
  nextUint32(): number {
    return (
      (this.nextByte() | (this.nextByte() << 8) | (this.nextByte() << 16) | (this.nextByte() << 24)) >>> 0
    );
  }

  /**
   * Uniform in [0, bound), by rejection.
   *
   * `bound` must be at most 2^32. Taking `nextUint32() % bound` directly would
   * bias the low residues by up to `bound / 2^32` — invisible on a screen and
   * exactly the kind of thing that makes an "encrypted" value predictable. The
   * rejection window discards the short final stripe instead.
   */
  uniformBelow(bound: number): number {
    if (!Number.isInteger(bound) || bound <= 0 || bound > 0x100000000) {
      throw new RangeError(`uniformBelow needs an integer bound in (0, 2^32]; got ${bound}`);
    }
    const limit = Math.floor(0x100000000 / bound) * bound;
    for (;;) {
      const v = this.nextUint32();
      if (v < limit) return v % bound;
    }
  }

  /**
   * Uniform ternary: −1, 0 or +1 with probability 1/3 each.
   *
   * This is the secret-key distribution the Homomorphic Encryption Security
   * Standard's table is stated for, which is why the lab can quote that table
   * for its own parameters. See `security.ts`.
   */
  ternary(): number {
    return this.uniformBelow(3) - 1;
  }

  /**
   * Centred binomial with parameter eta: popcount(a) − popcount(b) over two
   * independent eta-bit draws, giving standard deviation sqrt(eta / 2).
   *
   * The same distribution family Kyber and NewHope sample their error from. At
   * eta = 21 the deviation is sqrt(10.5) ≈ 3.24, at or above the sigma = 3.19
   * the HES table assumes, and the support is bounded by ±21 — a hard bound the
   * noise-growth arithmetic in `bfv.ts` can rely on, which an unbounded discrete
   * Gaussian would not give.
   */
  cbd(eta: number): number {
    if (!Number.isInteger(eta) || eta < 1 || eta > 32) {
      throw new RangeError(`cbd needs eta in [1, 32]; got ${eta}`);
    }
    const mask = eta === 32 ? 0xffffffff : (1 << eta) - 1;
    return popcount32(this.nextUint32() & mask) - popcount32(this.nextUint32() & mask);
  }
}

/** Standard SWAR population count for a 32-bit word. */
export function popcount32(x: number): number {
  let v = x >>> 0;
  v = v - ((v >>> 1) & 0x55555555);
  v = (v & 0x33333333) + ((v >>> 2) & 0x33333333);
  v = (v + (v >>> 4)) & 0x0f0f0f0f;
  return (Math.imul(v, 0x01010101) >>> 24) & 0xff;
}
