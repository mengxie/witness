import { digestPersonal, GENESIS, hashEvent, type ChainHead } from './chain';
import type { ChainedEvent } from './schemas';

export type VerificationResult =
  | { readonly ok: true; readonly verified: number; readonly head: ChainHead }
  | {
      readonly ok: false;
      readonly verified: number;
      readonly seq: number;
      readonly reason: string;
    };

/**
 * Checks a log one event at a time, so arbitrarily long logs stream through in constant memory.
 * Reports the first event where the log stops being trustworthy, and why.
 */
export class ChainVerifier {
  #expected: number;
  #previousHash: string;
  #verified = 0;
  #failure: { seq: number; reason: string } | undefined;
  readonly #checkpoints: ReadonlyMap<number, string>;

  /**
   * @param anchor Where verification starts: the genesis by default, or a trusted checkpoint.
   * @param checkpoints Signed `seq -> hash` pairs the log must agree with.
   */
  constructor(anchor: ChainHead = GENESIS, checkpoints: ReadonlyMap<number, string> = new Map()) {
    this.#expected = anchor.seq + 1;
    this.#previousHash = anchor.hash;
    this.#checkpoints = checkpoints;
  }

  get failed(): boolean {
    return this.#failure !== undefined;
  }

  push(event: ChainedEvent): boolean {
    if (this.#failure) return false;
    const reason = this.#check(event);
    if (reason) {
      this.#failure = { seq: event.seq, reason };
      return false;
    }
    this.#previousHash = event.hash;
    this.#expected += 1;
    this.#verified += 1;
    return true;
  }

  result(): VerificationResult {
    if (this.#failure) return { ok: false, verified: this.#verified, ...this.#failure };
    return {
      ok: true,
      verified: this.#verified,
      head: { seq: this.#expected - 1, hash: this.#previousHash },
    };
  }

  #check(event: ChainedEvent): string | undefined {
    if (event.seq !== this.#expected) {
      return `Expected event #${String(this.#expected)} but found #${String(event.seq)}: events are missing or out of order.`;
    }
    if (event.prevHash !== this.#previousHash) return 'It does not link to the event before it.';
    if (event.personal !== null) {
      if (
        event.personalSalt === null ||
        digestPersonal(event.personal, event.personalSalt) !== event.personalDigest
      ) {
        return 'Its personal data was changed after it was recorded.';
      }
    }
    if (hashEvent(event) !== event.hash) return 'Its contents were changed after it was recorded.';
    const signed = this.#checkpoints.get(event.seq);
    if (signed !== undefined && signed !== event.hash) {
      return 'It does not match a signed checkpoint: history was rewritten after the checkpoint was made.';
    }
    return undefined;
  }
}

export function verifyChain(
  events: Iterable<ChainedEvent>,
  anchor: ChainHead = GENESIS,
  checkpoints?: ReadonlyMap<number, string>,
): VerificationResult {
  const verifier = new ChainVerifier(anchor, checkpoints);
  for (const event of events) if (!verifier.push(event)) break;
  return verifier.result();
}
