import { keyGen, type SecretKey } from '../pir/bfv';
import {
  DEFAULT_MODULUS,
  DEFAULT_RECORD_BYTES,
  DEFAULT_SHELF_SIZE,
  makeParams,
  type ModulusOption,
  type PirParams,
} from '../pir/params';
import { buildRecord, shelfToPlaintexts } from '../pir/records';
import { Rng } from '../pir/rng';
import { entryText, shelfEntries, type ShelfEntry } from '../data/catalog';

/**
 * The lab's shared state, and the one place the shelf is built.
 *
 * Rebuilding is asynchronous because every record carries a SHA-256 tag and
 * WebCrypto's digest is a promise. Everything else — key generation, encryption,
 * the homomorphic fold — is synchronous, which is what lets the step-through
 * exhibit advance one record per click without an await in the middle of a
 * polynomial.
 */
export interface LabSnapshot {
  readonly modulus: ModulusOption;
  readonly recordBytes: number;
  readonly shelfSize: number;
  readonly selectedIndex: number;
  readonly seed: string | null;
  readonly params: PirParams;
  readonly sk: SecretKey;
  readonly entries: readonly ShelfEntry[];
  readonly records: readonly Uint8Array[];
  readonly plaintexts: readonly Int32Array[];
}

/**
 * What changed, in words, so a panel can say WHY it threw a measurement away.
 *
 * A measurement taken at one modulus is meaningless at another, so every panel
 * discards its cached query, timing and verdict when a parameter moves. Doing
 * that silently is the failure mode: a reader who changes the shelf length and
 * sees an empty panel cannot tell a retired result from one that never ran.
 */
type Listener = (change: string) => void;

export class Lab {
  private modulus: ModulusOption = DEFAULT_MODULUS;
  private recordBytes: number = DEFAULT_RECORD_BYTES;
  private shelfSize: number = DEFAULT_SHELF_SIZE;
  private selectedIndex = 0;
  private seed: string | null = null;
  private rng: Rng = Rng.fromEntropy();
  private params: PirParams = makeParams(DEFAULT_MODULUS.q, DEFAULT_RECORD_BYTES);
  private sk: SecretKey;
  private entries: ShelfEntry[] = [];
  private records: Uint8Array[] = [];
  private plaintexts: Int32Array[] = [];
  private listeners = new Set<Listener>();
  private lastChange = '';

  private constructor(sk: SecretKey) {
    this.sk = sk;
  }

  /** Build the lab and its shelf. */
  static async create(): Promise<Lab> {
    const lab = new Lab({ s: new Int8Array(0) });
    lab.sk = keyGen(lab.params, lab.rng);
    await lab.rebuildShelf();
    return lab;
  }

  snapshot(): LabSnapshot {
    return {
      modulus: this.modulus,
      recordBytes: this.recordBytes,
      shelfSize: this.shelfSize,
      selectedIndex: this.selectedIndex,
      seed: this.seed,
      params: this.params,
      sk: this.sk,
      entries: this.entries,
      records: this.records,
      plaintexts: this.plaintexts,
    };
  }

  /** The live randomness source. Every draw advances it. */
  get random(): Rng {
    return this.rng;
  }

  subscribe(listener: Listener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private emit(change: string): void {
    this.lastChange = change;
    for (const listener of this.listeners) listener(change);
  }

  /** The most recent parameter change, in the words the panels print. */
  get changeReason(): string {
    return this.lastChange;
  }

  private async rebuildShelf(): Promise<void> {
    this.entries = shelfEntries(this.shelfSize);
    this.records = await Promise.all(
      this.entries.map((entry) => buildRecord(entryText(entry), this.recordBytes))
    );
    this.plaintexts = shelfToPlaintexts(this.records, this.params);
  }

  /**
   * Change the ciphertext modulus.
   *
   * The secret key is REGENERATED, because a key is a ring element modulo q and
   * carrying one across a modulus change would be meaningless. Everything
   * downstream — queries, answers, measurements — is discarded by the panels
   * that hold it, which is why every exhibit re-renders on this event.
   */
  async setModulus(option: ModulusOption): Promise<void> {
    this.modulus = option;
    this.params = makeParams(option.q, this.recordBytes);
    this.sk = keyGen(this.params, this.rng);
    await this.rebuildShelf();
    this.emit(`the ciphertext modulus changed to ${option.label}`);
  }

  async setRecordBytes(bytes: number): Promise<void> {
    if (bytes === this.recordBytes) return;
    this.recordBytes = bytes;
    this.params = makeParams(this.modulus.q, bytes);
    await this.rebuildShelf();
    this.emit(`the record size changed to ${bytes} bytes`);
  }

  async setShelfSize(size: number): Promise<void> {
    if (size === this.shelfSize) return;
    this.shelfSize = size;
    if (this.selectedIndex >= size) this.selectedIndex = size - 1;
    await this.rebuildShelf();
    this.emit(`the shelf length changed to ${size} records`);
  }

  /**
   * Choose a shelf position.
   *
   * Re-selecting the SAME position returns early and emits nothing. That is not
   * an optimisation: without it, clicking the already-selected book would retire
   * every measurement on the page for no reason, and a reader would learn that
   * results here are arbitrary rather than parameter-dependent.
   */
  setSelectedIndex(index: number): void {
    if (index === this.selectedIndex) return;
    this.selectedIndex = index;
    this.emit(`the selected shelf position changed to ${index}`);
  }

  /**
   * Pin the run to a seed, or return to platform entropy.
   *
   * A pinned seed makes the whole run reproducible INCLUDING THE SECRET KEY.
   * That is the point — two people can compare identical ciphertexts — and it is
   * why the control says so in as many words wherever it appears.
   */
  async setSeed(seed: string | null): Promise<void> {
    this.seed = seed;
    this.rng = seed === null ? Rng.fromEntropy() : Rng.fromSeed(seed);
    this.sk = keyGen(this.params, this.rng);
    await this.rebuildShelf();
    this.emit(seed === null ? 'the run returned to platform entropy' : `the run seed was pinned to "${seed}"`);
  }

  /** Draw a completely fresh key from the current source. */
  regenerateKey(): void {
    this.sk = keyGen(this.params, this.rng);
    this.emit('a fresh secret key was drawn');
  }
}
