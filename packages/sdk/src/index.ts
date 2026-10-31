import { randomUUID } from 'node:crypto';
import {
  ChainedEventSchema,
  ChainVerifier,
  CheckpointSchema,
  loadPublicKey,
  verifyCheckpoint,
  type ChainedEvent,
  type ChainHead,
  type Checkpoint,
  type NewEvent,
} from '@witness/core';
import { z } from 'zod';

export type { ChainedEvent, Checkpoint, NewEvent } from '@witness/core';

export class WitnessError extends Error {
  constructor(
    readonly status: number,
    readonly code: string | undefined,
    message: string,
  ) {
    super(message);
    this.name = 'WitnessError';
  }
}

export interface WitnessClientOptions {
  readonly baseUrl: string;
  readonly apiKey: string;
  readonly fetch?: typeof fetch;
  /** Retries for network failures, 5xx and 429. Recording is idempotent, so retries are always safe. */
  readonly maxRetries?: number;
  readonly retryDelayMs?: number;
}

export interface ListQuery {
  readonly actorId?: string;
  readonly targetType?: string;
  readonly targetId?: string;
  readonly action?: string;
  readonly before?: number;
  readonly limit?: number;
}

export interface VerifyOptions {
  /** A checkpoint saved outside Witness earlier. The log must still agree with it. */
  readonly trusted?: Checkpoint;
  /** Pin the expected public key (PEM) so a compromised server cannot substitute its own. */
  readonly publicKeyPem?: string;
}

export type VerifyReport =
  | {
      readonly ok: true;
      readonly verified: number;
      readonly head: ChainHead;
      readonly checkpointsVerified: number;
      readonly latestCheckpoint: Checkpoint | undefined;
      readonly keyId: string;
    }
  | {
      readonly ok: false;
      readonly verified: number;
      readonly seq: number;
      readonly reason: string;
    };

const EventsSchema = z.object({ events: z.array(ChainedEventSchema) });
const PageSchema = z.object({
  events: z.array(ChainedEventSchema),
  nextAfter: z.number().nullable(),
});
const ListSchema = z.object({
  events: z.array(ChainedEventSchema),
  nextBefore: z.number().nullable(),
});
const CheckpointsSchema = z.object({ checkpoints: z.array(CheckpointSchema) });
const KeySchema = z.object({ publicKey: z.string() });
const ProblemSchema = z.object({ code: z.string().optional(), detail: z.string().optional() });

export class WitnessClient {
  readonly #baseUrl: string;
  readonly #apiKey: string;
  readonly #fetch: typeof fetch;
  readonly #maxRetries: number;
  readonly #retryDelayMs: number;

  constructor(options: WitnessClientOptions) {
    this.#baseUrl = options.baseUrl.replace(/\/+$/, '');
    this.#apiKey = options.apiKey;
    this.#fetch = options.fetch ?? globalThis.fetch;
    this.#maxRetries = options.maxRetries ?? 3;
    this.#retryDelayMs = options.retryDelayMs ?? 200;
  }

  async record(event: NewEvent): Promise<ChainedEvent> {
    const [recorded] = await this.recordMany([event]);
    if (!recorded) throw new WitnessError(500, undefined, 'The server returned no event.');
    return recorded;
  }

  /** Records up to 100 events atomically, in order. */
  async recordMany(events: readonly NewEvent[]): Promise<ChainedEvent[]> {
    // A key per event makes every retry, ours or the caller's, exactly-once.
    const body = { events: events.map((event) => ({ idempotencyKey: randomUUID(), ...event })) };
    return (await this.#request('POST', '/v1/events', EventsSchema, body)).events;
  }

  async list(query: ListQuery = {}): Promise<z.infer<typeof ListSchema>> {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(query)) params.set(key, String(value));
    return this.#request('GET', `/v1/events?${params.toString()}`, ListSchema);
  }

  /** The whole log, oldest first, streamed page by page. */
  async *log(after = 0): AsyncGenerator<ChainedEvent> {
    for (let cursor: number | null = after; cursor !== null;) {
      const page: z.infer<typeof PageSchema> = await this.#request(
        'GET',
        `/v1/log?after=${String(cursor)}&limit=1000`,
        PageSchema,
      );
      yield* page.events;
      cursor = page.nextAfter;
    }
  }

  async checkpoints(): Promise<Checkpoint[]> {
    const all: Checkpoint[] = [];
    for (let after = 0; ;) {
      const { checkpoints } = await this.#request(
        'GET',
        `/v1/checkpoints?after=${String(after)}&limit=1000`,
        CheckpointsSchema,
      );
      all.push(...checkpoints);
      const last = checkpoints.at(-1);
      if (checkpoints.length < 1000 || !last) return all;
      after = last.seq;
    }
  }

  /** Asks the server to sign its current head now. Save the result somewhere Witness cannot change. */
  checkpoint(): Promise<Checkpoint> {
    return this.#request('POST', '/v1/checkpoints', CheckpointSchema);
  }

  redact(eventId: string): Promise<ChainedEvent> {
    return this.#request(
      'POST',
      `/v1/events/${encodeURIComponent(eventId)}/redact`,
      ChainedEventSchema,
    );
  }

  async publicKeyPem(): Promise<string> {
    return (await this.#request('GET', '/.well-known/witness-key', KeySchema)).publicKey;
  }

  /**
   * Verifies the log on this machine: every checkpoint signature, every link and hash, agreement
   * with every signed checkpoint, and with `trusted`. Nothing here relies on the server being honest.
   */
  async verify(options: VerifyOptions = {}): Promise<VerifyReport> {
    const publicKey = loadPublicKey(options.publicKeyPem ?? (await this.publicKeyPem()));
    const checkpoints = await this.checkpoints();
    const signed = new Map<number, string>();
    for (const checkpoint of checkpoints) {
      if (!verifyCheckpoint(checkpoint, publicKey)) {
        return {
          ok: false,
          verified: 0,
          seq: checkpoint.seq,
          reason: 'Its checkpoint signature is invalid.',
        };
      }
      signed.set(checkpoint.seq, checkpoint.hash);
    }

    const { trusted } = options;
    if (trusted) {
      if (!verifyCheckpoint(trusted, publicKey)) {
        return {
          ok: false,
          verified: 0,
          seq: trusted.seq,
          reason: 'Your saved checkpoint does not carry a valid signature for this key.',
        };
      }
      const served = signed.get(trusted.seq);
      if (served !== undefined && served !== trusted.hash) {
        return {
          ok: false,
          verified: 0,
          seq: trusted.seq,
          reason:
            'The server now shows a different checkpoint than the one you saved: history was rewritten.',
        };
      }
      signed.set(trusted.seq, trusted.hash);
    }

    const verifier = new ChainVerifier(undefined, signed);
    for await (const event of this.log()) if (!verifier.push(event)) break;
    const result = verifier.result();
    if (!result.ok) return result;
    if (trusted && result.head.seq < trusted.seq) {
      return {
        ok: false,
        verified: result.verified,
        seq: result.head.seq + 1,
        reason: `The log ends at #${String(result.head.seq)}, but your saved checkpoint covers #${String(trusted.seq)}: events were deleted.`,
      };
    }
    return {
      ...result,
      checkpointsVerified: signed.size,
      latestCheckpoint: checkpoints.at(-1),
      keyId: checkpoints.at(-1)?.keyId ?? '',
    };
  }

  async #request<T extends z.ZodType>(
    method: string,
    path: string,
    schema: T,
    body?: unknown,
  ): Promise<z.infer<T>> {
    for (let attempt = 0; ; attempt++) {
      let response: Response;
      try {
        response = await this.#fetch(`${this.#baseUrl}${path}`, {
          method,
          headers: {
            authorization: `Bearer ${this.#apiKey}`,
            ...(body === undefined ? {} : { 'content-type': 'application/json' }),
          },
          ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        });
      } catch (error) {
        if (attempt >= this.#maxRetries) throw error;
        await this.#backoff(attempt);
        continue;
      }
      if (response.ok) return schema.parse(await response.json());
      const retryable = response.status >= 500 || response.status === 429;
      if (retryable && attempt < this.#maxRetries) {
        await this.#backoff(attempt);
        continue;
      }
      const problem = ProblemSchema.safeParse(await response.json().catch(() => ({})));
      const detail = problem.success ? problem.data.detail : undefined;
      throw new WitnessError(
        response.status,
        problem.success ? problem.data.code : undefined,
        detail ?? `Request failed with ${String(response.status)}.`,
      );
    }
  }

  #backoff(attempt: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, this.#retryDelayMs * 2 ** attempt));
  }
}
