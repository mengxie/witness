import {
  generateSigningKey,
  loadPrivateKey,
  seal,
  signCheckpoint,
  type ChainedEvent,
  type ChainHead,
} from '@witness/core';
import type { FastifyInstance } from 'fastify';
import { sql, type Kysely } from 'kysely';
import { createDatabase, migrateToLatest, type Database } from '../src/database';
import { buildApp } from '../src/http/app';
import { AuditLogService } from '../src/service';
import { Store } from '../src/store';

export const databaseUrl = process.env['DATABASE_URL'];
export const ADMIN_TOKEN = 'operator-token-for-tests-'.padEnd(48, 'x');

export interface Harness {
  readonly app: FastifyInstance;
  readonly db: Kysely<Database>;
  readonly service: AuditLogService;
  readonly signingKey: ReturnType<typeof generateSigningKey>;
  close(): Promise<void>;
}

export async function startHarness(): Promise<Harness> {
  const db = createDatabase(databaseUrl ?? '');
  await migrateToLatest(db);
  const signingKey = generateSigningKey();
  const service = new AuditLogService(new Store(db), loadPrivateKey(signingKey.privateKeyPem));
  const app = await buildApp({
    service,
    adminToken: ADMIN_TOKEN,
    checkReadiness: () => Promise.resolve(),
    rateLimitPerMinute: 100_000,
  });
  return {
    app,
    db,
    service,
    signingKey,
    close: async () => {
      await app.close();
      await db.destroy();
    },
  };
}

export async function newTenant(
  app: FastifyInstance,
  name = 'Acme Ltd',
): Promise<{ tenantId: string; apiKey: string }> {
  const response = await app.inject({
    method: 'POST',
    url: '/admin/tenants',
    headers: { authorization: `Bearer ${ADMIN_TOKEN}` },
    payload: { name },
  });
  const body = response.json<{ tenant: { id: string }; apiKey: string }>();
  return { tenantId: body.tenant.id, apiKey: body.apiKey };
}

export const auth = (apiKey: string) => ({ authorization: `Bearer ${apiKey}` });

export const sampleEvent = (n: number) => ({
  action: 'invoice.updated',
  actor: { id: `user_${String(n % 3)}`, name: `Person ${String(n)}` },
  target: { type: 'invoice', id: `inv_${String(n)}`, name: `Invoice ${String(n)}` },
  context: { ip: '203.0.113.7', userAgent: 'test' },
  metadata: { amountCents: n * 1000 },
});

/**
 * Plays an attacker with full database access. `SET LOCAL session_replication_role = replica`
 * bypasses the append-only trigger for this transaction only, as a database superuser could.
 */
export async function asDatabaseAdmin(
  db: Kysely<Database>,
  work: (trx: Kysely<Database>) => Promise<void>,
): Promise<void> {
  await db.transaction().execute(async (trx) => {
    await sql`SET LOCAL session_replication_role = replica`.execute(trx);
    await work(trx);
  });
}

/** A careful rewrite: change one event, then recompute every later hash so the chain is consistent again. */
export async function rewriteHistory(
  db: Kysely<Database>,
  events: readonly ChainedEvent[],
  fromSeq: number,
  action: string,
): Promise<ChainHead> {
  let head: ChainHead = events.find((event) => event.seq === fromSeq - 1) ?? {
    seq: 0,
    hash: '0'.repeat(64),
  };
  await asDatabaseAdmin(db, async (trx) => {
    for (const event of events.filter((e) => e.seq >= fromSeq)) {
      const resealed = seal(
        {
          ...event,
          action: event.seq === fromSeq ? action : event.action,
          personal: event.personal ?? {},
        },
        head,
        event.personalSalt ?? undefined,
      );
      await trx
        .updateTable('events')
        .set({
          action: resealed.action,
          personal_digest: resealed.personalDigest,
          prev_hash: resealed.prevHash,
          hash: resealed.hash,
        })
        .where('tenant_id', '=', event.tenantId)
        .where('seq', '=', event.seq)
        .execute();
      head = resealed;
    }
    await trx
      .updateTable('chain_heads')
      .set({ seq: head.seq, hash: head.hash })
      .where('tenant_id', '=', events[0]?.tenantId ?? '')
      .execute();
  });
  return head;
}

/** With the stolen signing key, replace every checkpoint so the server's own check passes. */
export async function forgeCheckpoints(
  db: Kysely<Database>,
  tenantId: string,
  head: ChainHead,
  privateKeyPem: string,
): Promise<void> {
  const forged = signCheckpoint(
    { tenantId, seq: head.seq, hash: head.hash, createdAt: new Date().toISOString() },
    loadPrivateKey(privateKeyPem),
  );
  await db.deleteFrom('checkpoints').where('tenant_id', '=', tenantId).execute();
  await db
    .insertInto('checkpoints')
    .values({
      tenant_id: tenantId,
      seq: forged.seq,
      hash: forged.hash,
      created_at: new Date(forged.createdAt),
      key_id: forged.keyId,
      signature: forged.signature,
    })
    .execute();
}
