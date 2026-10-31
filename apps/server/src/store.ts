import { randomUUID } from 'node:crypto';
import {
  GENESIS_HASH,
  seal,
  type ChainedEvent,
  type ChainHead,
  type Checkpoint,
  type ParsedNewEvent,
  type Personal,
} from '@witness/core';
import type { Kysely, Selectable } from 'kysely';
import type { Database } from './database';

type EventRow = Selectable<Database['events']>;

export interface EventFilters {
  readonly actorId?: string | undefined;
  readonly targetType?: string | undefined;
  readonly targetId?: string | undefined;
  readonly action?: string | undefined;
  readonly before?: number | undefined;
  readonly limit: number;
}

export class Store {
  constructor(private readonly db: Kysely<Database>) {}

  async createTenant(id: string, name: string, now: Date): Promise<void> {
    await this.db.transaction().execute(async (trx) => {
      await trx.insertInto('tenants').values({ id, name, created_at: now }).execute();
      await trx
        .insertInto('chain_heads')
        .values({ tenant_id: id, seq: 0, hash: GENESIS_HASH })
        .execute();
    });
  }

  async tenantExists(id: string): Promise<boolean> {
    return (
      (await this.db.selectFrom('tenants').select('id').where('id', '=', id).executeTakeFirst()) !==
      undefined
    );
  }

  async addApiKey(
    tenantId: string,
    prefix: string,
    keyHash: string,
    name: string | null,
    now: Date,
  ): Promise<void> {
    await this.db
      .insertInto('api_keys')
      .values({ prefix, tenant_id: tenantId, key_hash: keyHash, name, created_at: now })
      .execute();
  }

  async findActiveKey(prefix: string): Promise<{ tenantId: string; keyHash: string } | undefined> {
    const row = await this.db
      .selectFrom('api_keys')
      .select(['tenant_id', 'key_hash'])
      .where('prefix', '=', prefix)
      .where('revoked_at', 'is', null)
      .executeTakeFirst();
    return row && { tenantId: row.tenant_id, keyHash: row.key_hash };
  }

  async revokeKey(prefix: string, now: Date): Promise<boolean> {
    const result = await this.db
      .updateTable('api_keys')
      .set({ revoked_at: now })
      .where('prefix', '=', prefix)
      .where('revoked_at', 'is', null)
      .executeTakeFirst();
    return result.numUpdatedRows > 0n;
  }

  /**
   * Appends events atomically. Locking the tenant's chain head serialises appends per tenant (other
   * tenants are unaffected), and idempotency keys are checked after taking the lock, so a retried
   * request returns the original events instead of recording them twice.
   */
  async append(
    tenantId: string,
    inputs: readonly ParsedNewEvent[],
    now: Date,
  ): Promise<ChainedEvent[]> {
    return this.db.transaction().execute(async (trx) => {
      const locked = await trx
        .selectFrom('chain_heads')
        .select(['seq', 'hash'])
        .where('tenant_id', '=', tenantId)
        .forUpdate()
        .executeTakeFirstOrThrow();

      const keys = [
        ...new Set(inputs.flatMap((input) => (input.idempotencyKey ? [input.idempotencyKey] : []))),
      ];
      const known = new Map<string, ChainedEvent>();
      if (keys.length > 0) {
        const rows = await trx
          .selectFrom('events')
          .selectAll()
          .where('tenant_id', '=', tenantId)
          .where('idempotency_key', 'in', keys)
          .execute();
        for (const row of rows)
          if (row.idempotency_key) known.set(row.idempotency_key, toEvent(row));
      }

      let head: ChainHead = { seq: locked.seq, hash: locked.hash };
      const receivedAt = now.toISOString();
      const results: ChainedEvent[] = [];
      const rows: Database['events'][] = [];
      for (const input of inputs) {
        const existing = input.idempotencyKey ? known.get(input.idempotencyKey) : undefined;
        if (existing) {
          results.push(existing);
          continue;
        }
        const event = seal(
          {
            id: randomUUID(),
            tenantId,
            receivedAt,
            occurredAt: input.occurredAt ? new Date(input.occurredAt).toISOString() : receivedAt,
            action: input.action,
            actor: { id: input.actor.id, type: input.actor.type },
            target: input.target ? { id: input.target.id, type: input.target.type } : null,
            personal: personalOf(input),
          },
          head,
        );
        head = event;
        if (input.idempotencyKey) known.set(input.idempotencyKey, event);
        results.push(event);
        rows.push(toRow(event, input.idempotencyKey ?? null));
      }

      if (rows.length > 0) {
        await trx.insertInto('events').values(rows).execute();
        await trx
          .updateTable('chain_heads')
          .set({ seq: head.seq, hash: head.hash })
          .where('tenant_id', '=', tenantId)
          .execute();
      }
      return results;
    });
  }

  async head(tenantId: string): Promise<ChainHead> {
    return this.db
      .selectFrom('chain_heads')
      .select(['seq', 'hash'])
      .where('tenant_id', '=', tenantId)
      .executeTakeFirstOrThrow();
  }

  /** Newest first, for activity feeds. */
  async query(tenantId: string, filters: EventFilters): Promise<ChainedEvent[]> {
    let query = this.db.selectFrom('events').selectAll().where('tenant_id', '=', tenantId);
    if (filters.actorId !== undefined) query = query.where('actor_id', '=', filters.actorId);
    if (filters.targetType !== undefined)
      query = query.where('target_type', '=', filters.targetType);
    if (filters.targetId !== undefined) query = query.where('target_id', '=', filters.targetId);
    if (filters.action !== undefined) query = query.where('action', '=', filters.action);
    if (filters.before !== undefined) query = query.where('seq', '<', filters.before);
    const rows = await query.orderBy('seq', 'desc').limit(filters.limit).execute();
    return rows.map(toEvent);
  }

  /** Oldest first, for export and verification. */
  async range(tenantId: string, after: number, limit: number): Promise<ChainedEvent[]> {
    const rows = await this.db
      .selectFrom('events')
      .selectAll()
      .where('tenant_id', '=', tenantId)
      .where('seq', '>', after)
      .orderBy('seq')
      .limit(limit)
      .execute();
    return rows.map(toEvent);
  }

  async redact(tenantId: string, id: string): Promise<ChainedEvent | undefined> {
    const row = await this.db
      .updateTable('events')
      .set({ personal: null, personal_salt: null })
      .where('tenant_id', '=', tenantId)
      .where('id', '=', id)
      .returningAll()
      .executeTakeFirst();
    return row && toEvent(row);
  }

  async addCheckpoint(checkpoint: Checkpoint): Promise<void> {
    await this.db
      .insertInto('checkpoints')
      .values({
        tenant_id: checkpoint.tenantId,
        seq: checkpoint.seq,
        hash: checkpoint.hash,
        created_at: new Date(checkpoint.createdAt),
        key_id: checkpoint.keyId,
        signature: checkpoint.signature,
      })
      .onConflict((conflict) => conflict.columns(['tenant_id', 'seq']).doNothing())
      .execute();
  }

  async checkpoints(tenantId: string, after: number, limit: number): Promise<Checkpoint[]> {
    const rows = await this.db
      .selectFrom('checkpoints')
      .selectAll()
      .where('tenant_id', '=', tenantId)
      .where('seq', '>', after)
      .orderBy('seq')
      .limit(limit)
      .execute();
    return rows.map((row) => ({
      tenantId: row.tenant_id,
      seq: row.seq,
      hash: row.hash,
      createdAt: row.created_at.toISOString(),
      keyId: row.key_id,
      signature: row.signature,
    }));
  }

  async latestCheckpointSeq(tenantId: string): Promise<number> {
    const row = await this.db
      .selectFrom('checkpoints')
      .select((eb) => eb.fn.max('seq').as('seq'))
      .where('tenant_id', '=', tenantId)
      .executeTakeFirst();
    return row?.seq ?? 0;
  }

  /** Tenants whose log has grown since their last checkpoint. */
  async tenantsNeedingCheckpoint(): Promise<string[]> {
    const rows = await this.db
      .selectFrom('chain_heads as h')
      .leftJoin('checkpoints as c', 'c.tenant_id', 'h.tenant_id')
      .select('h.tenant_id')
      .where('h.seq', '>', 0)
      .groupBy(['h.tenant_id', 'h.seq'])
      .having((eb) => eb(eb.fn.coalesce(eb.fn.max('c.seq'), eb.lit(0)), '<', eb.ref('h.seq')))
      .execute();
    return rows.map((row) => row.tenant_id);
  }
}

function personalOf(input: ParsedNewEvent): Personal {
  const personal: Personal = {};
  if (input.actor.name !== undefined) personal.actorName = input.actor.name;
  if (input.target?.name !== undefined) personal.targetName = input.target.name;
  if (input.context !== undefined) personal.context = input.context;
  if (input.metadata !== undefined) personal.metadata = input.metadata;
  return personal;
}

function toRow(event: ChainedEvent, idempotencyKey: string | null): Database['events'] {
  return {
    tenant_id: event.tenantId,
    seq: event.seq,
    id: event.id,
    received_at: new Date(event.receivedAt),
    occurred_at: new Date(event.occurredAt),
    action: event.action,
    actor_id: event.actor.id,
    actor_type: event.actor.type,
    target_id: event.target?.id ?? null,
    target_type: event.target?.type ?? null,
    personal: event.personal,
    personal_salt: event.personalSalt,
    personal_digest: event.personalDigest,
    idempotency_key: idempotencyKey,
    prev_hash: event.prevHash,
    hash: event.hash,
  };
}

function toEvent(row: EventRow): ChainedEvent {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    seq: row.seq,
    receivedAt: row.received_at.toISOString(),
    occurredAt: row.occurred_at.toISOString(),
    action: row.action,
    actor: { id: row.actor_id, type: row.actor_type },
    target:
      row.target_id !== null && row.target_type !== null
        ? { id: row.target_id, type: row.target_type }
        : null,
    personal: row.personal,
    personalSalt: row.personal_salt,
    personalDigest: row.personal_digest,
    prevHash: row.prev_hash,
    hash: row.hash,
  };
}
