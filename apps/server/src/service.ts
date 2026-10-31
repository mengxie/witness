import {
  createHash,
  createPublicKey,
  randomBytes,
  randomUUID,
  timingSafeEqual,
  type KeyObject,
} from 'node:crypto';
import {
  ChainVerifier,
  keyIdOf,
  signCheckpoint,
  verifyCheckpoint,
  type ChainedEvent,
  type ChainHead,
  type Checkpoint,
  type ParsedNewEvent,
  type VerificationResult,
} from '@witness/core';
import { AppError, notFound } from './errors';
import type { EventFilters, Store } from './store';

const KEY_PREFIX_LENGTH = 12;
const sha256 = (text: string) => createHash('sha256').update(text).digest('hex');

export type VerificationReport = VerificationResult & { readonly checkpointsVerified: number };

/** Use cases. HTTP adapters call these; every rule lives here or in @witness/core. */
export class AuditLogService {
  readonly publicKey: KeyObject;
  readonly keyId: string;

  constructor(
    private readonly store: Store,
    private readonly signingKey: KeyObject,
    private readonly now: () => Date = () => new Date(),
  ) {
    this.publicKey = createPublicKey(signingKey);
    this.keyId = keyIdOf(this.publicKey);
  }

  async createTenant(
    name: string,
  ): Promise<{ tenant: { id: string; name: string }; apiKey: string }> {
    const id = randomUUID();
    await this.store.createTenant(id, name, this.now());
    return { tenant: { id, name }, apiKey: await this.issueKey(id, 'default') };
  }

  /** API keys are shown once. Only a SHA-256 hash is stored; the prefix identifies the key. */
  async issueKey(tenantId: string, name: string | null): Promise<string> {
    if (!(await this.store.tenantExists(tenantId))) throw notFound('tenant');
    const apiKey = `wit_${randomBytes(24).toString('base64url')}`;
    await this.store.addApiKey(
      tenantId,
      apiKey.slice(0, KEY_PREFIX_LENGTH),
      sha256(apiKey),
      name,
      this.now(),
    );
    return apiKey;
  }

  async revokeKey(prefix: string): Promise<void> {
    if (!(await this.store.revokeKey(prefix, this.now()))) throw notFound('key');
  }

  async authenticate(apiKey: string): Promise<string | undefined> {
    if (!apiKey.startsWith('wit_')) return undefined;
    const key = await this.store.findActiveKey(apiKey.slice(0, KEY_PREFIX_LENGTH));
    if (!key) return undefined;
    const matches = timingSafeEqual(
      Buffer.from(sha256(apiKey), 'hex'),
      Buffer.from(key.keyHash, 'hex'),
    );
    return matches ? key.tenantId : undefined;
  }

  record(tenantId: string, events: readonly ParsedNewEvent[]): Promise<ChainedEvent[]> {
    return this.store.append(tenantId, events, this.now());
  }

  query(tenantId: string, filters: EventFilters): Promise<ChainedEvent[]> {
    return this.store.query(tenantId, filters);
  }

  range(tenantId: string, after: number, limit: number): Promise<ChainedEvent[]> {
    return this.store.range(tenantId, after, limit);
  }

  head(tenantId: string): Promise<ChainHead> {
    return this.store.head(tenantId);
  }

  async redact(tenantId: string, eventId: string): Promise<ChainedEvent> {
    const event = await this.store.redact(tenantId, eventId);
    if (!event) throw notFound('event');
    return event;
  }

  checkpoints(tenantId: string, after: number, limit: number): Promise<Checkpoint[]> {
    return this.store.checkpoints(tenantId, after, limit);
  }

  /** Signs the current head, unless it is already covered by the latest checkpoint. */
  async checkpoint(tenantId: string): Promise<Checkpoint> {
    const head = await this.store.head(tenantId);
    if (head.seq === 0)
      throw new AppError(409, 'checkpoint.empty_log', 'There is nothing to checkpoint yet.');
    if ((await this.store.latestCheckpointSeq(tenantId)) === head.seq) {
      const [existing] = await this.store.checkpoints(tenantId, head.seq - 1, 1);
      if (existing) return existing;
    }
    const checkpoint = signCheckpoint(
      { tenantId, seq: head.seq, hash: head.hash, createdAt: this.now().toISOString() },
      this.signingKey,
    );
    await this.store.addCheckpoint(checkpoint);
    return checkpoint;
  }

  /** Checkpoints every tenant whose log grew since its last checkpoint. */
  async checkpointAll(): Promise<number> {
    const tenants = await this.store.tenantsNeedingCheckpoint();
    for (const tenantId of tenants) await this.checkpoint(tenantId);
    return tenants.length;
  }

  /**
   * Server-side verification, convenient for dashboards and monitoring. For assurance that does
   * not depend on trusting this server, verify with the SDK or CLI instead.
   */
  async verify(tenantId: string): Promise<VerificationReport> {
    const signed = new Map<number, string>();
    for (let after = 0; ;) {
      const page = await this.store.checkpoints(tenantId, after, 1000);
      for (const checkpoint of page) {
        if (!verifyCheckpoint(checkpoint, this.publicKey)) {
          return {
            ok: false,
            verified: 0,
            seq: checkpoint.seq,
            reason: 'Its checkpoint signature is invalid.',
            checkpointsVerified: signed.size,
          };
        }
        signed.set(checkpoint.seq, checkpoint.hash);
      }
      if (page.length < 1000) break;
      after = page.at(-1)?.seq ?? after;
    }

    const verifier = new ChainVerifier(undefined, signed);
    for (let after = 0; ;) {
      const page = await this.store.range(tenantId, after, 1000);
      for (const event of page) if (!verifier.push(event)) break;
      if (verifier.failed || page.length < 1000) break;
      after = page.at(-1)?.seq ?? after;
    }
    return { ...verifier.result(), checkpointsVerified: signed.size };
  }
}
