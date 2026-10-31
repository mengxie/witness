import {
  ChainedEventSchema,
  CheckpointSchema,
  loadPublicKey,
  verifyChain,
  verifyCheckpoint,
  type ChainedEvent,
} from '@witness/core';
import { sql } from 'kysely';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ADMIN_TOKEN,
  asDatabaseAdmin,
  auth,
  databaseUrl,
  newTenant,
  rewriteHistory,
  sampleEvent,
  startHarness,
  type Harness,
} from './harness';

describe.skipIf(!databaseUrl)('Witness API', () => {
  let h: Harness;
  beforeAll(async () => {
    h = await startHarness();
  });
  afterAll(async () => {
    await h.close();
  });

  async function call(
    method: 'GET' | 'POST' | 'DELETE',
    url: string,
    headers: Record<string, string> = {},
    payload?: object,
  ) {
    return h.app.inject(
      payload === undefined ? { method, url, headers } : { method, url, headers, payload },
    );
  }
  const record = (apiKey: string, payload: object) =>
    call('POST', '/v1/events', auth(apiKey), payload);
  const get = (apiKey: string, url: string) => call('GET', url, auth(apiKey));
  async function wholeLog(apiKey: string): Promise<ChainedEvent[]> {
    const response = await get(apiKey, '/v1/log?limit=1000');
    return response.json<{ events: ChainedEvent[] }>().events;
  }

  it('only lets operators create tenants', async () => {
    const attempt = (headers: Record<string, string>) =>
      call('POST', '/admin/tenants', headers, { name: 'Acme' });
    expect((await attempt({})).statusCode).toBe(401);
    expect((await attempt({ authorization: 'Bearer nope' })).statusCode).toBe(401);
    const created = await attempt({ authorization: `Bearer ${ADMIN_TOKEN}` });
    expect(created.statusCode).toBe(201);
    expect(created.json<{ apiKey: string }>().apiKey).toMatch(/^wit_[\w-]{32}$/);
  });

  it('records single events and batches into one verifiable chain', async () => {
    const { apiKey } = await newTenant(h.app);
    const single = await record(apiKey, sampleEvent(1));
    const batch = await record(apiKey, {
      events: [sampleEvent(2), sampleEvent(3), sampleEvent(4)],
    });

    expect(single.statusCode).toBe(201);
    const events = [
      ...single.json<{ events: unknown[] }>().events,
      ...batch.json<{ events: unknown[] }>().events,
    ].map((e) => ChainedEventSchema.parse(e));
    expect(events.map((e) => e.seq)).toEqual([1, 2, 3, 4]);
    expect(events[0]?.personal).toMatchObject({
      actorName: 'Person 1',
      context: { ip: '203.0.113.7' },
    });
    expect(verifyChain(await wholeLog(apiKey)).ok).toBe(true);
  });

  it('never records a retried event twice', async () => {
    const { apiKey } = await newTenant(h.app);
    const first = await record(apiKey, { ...sampleEvent(1), idempotencyKey: 'invoice-1-updated' });
    const retry = await record(apiKey, { ...sampleEvent(1), idempotencyKey: 'invoice-1-updated' });
    const mixed = await record(apiKey, {
      events: [
        { ...sampleEvent(1), idempotencyKey: 'invoice-1-updated' },
        { ...sampleEvent(2), idempotencyKey: 'k2' },
        { ...sampleEvent(2), idempotencyKey: 'k2' },
      ],
    });

    const id = (response: typeof first, index = 0) =>
      response.json<{ events: ChainedEvent[] }>().events[index]?.id;
    expect(id(retry)).toBe(id(first));
    expect(id(mixed, 0)).toBe(id(first));
    expect(id(mixed, 1)).toBe(id(mixed, 2));
    expect((await get(apiKey, '/v1/head')).json()).toMatchObject({ seq: 2 });
  });

  it('keeps the chain intact under concurrent writes', async () => {
    const { apiKey } = await newTenant(h.app);
    await Promise.all(Array.from({ length: 40 }, (_, n) => record(apiKey, sampleEvent(n))));

    const log = await wholeLog(apiKey);
    expect(log.map((e) => e.seq)).toEqual(Array.from({ length: 40 }, (_, n) => n + 1));
    expect((await get(apiKey, '/v1/verify')).json()).toMatchObject({ ok: true, verified: 40 });
  });

  it('keeps every tenant in its own chain', async () => {
    const acme = await newTenant(h.app, 'Acme');
    const globex = await newTenant(h.app, 'Globex');
    await record(acme.apiKey, { events: [sampleEvent(1), sampleEvent(2)] });
    await record(globex.apiKey, sampleEvent(3));

    const globexLog = await wholeLog(globex.apiKey);
    expect(globexLog.map((e) => [e.seq, e.tenantId])).toEqual([[1, globex.tenantId]]);
    expect(
      (await get(globex.apiKey, '/v1/events')).json<{ events: unknown[] }>().events,
    ).toHaveLength(1);
  });

  it('answers "who did what" newest first, with filters and a cursor', async () => {
    const { apiKey } = await newTenant(h.app);
    await record(apiKey, { events: Array.from({ length: 6 }, (_, n) => sampleEvent(n)) });

    const byActor = (await get(apiKey, '/v1/events?actorId=user_1')).json<{
      events: ChainedEvent[];
    }>();
    expect(byActor.events.map((e) => e.seq)).toEqual([5, 2]);
    const byTarget = (await get(apiKey, '/v1/events?targetType=invoice&targetId=inv_3')).json<{
      events: ChainedEvent[];
    }>();
    expect(byTarget.events.map((e) => e.seq)).toEqual([4]);
    const page1 = (await get(apiKey, '/v1/events?limit=4')).json<{
      events: ChainedEvent[];
      nextBefore: number;
    }>();
    const page2 = (
      await get(apiKey, `/v1/events?limit=4&before=${String(page1.nextBefore)}`)
    ).json<{ events: ChainedEvent[]; nextBefore: number | null }>();
    expect([...page1.events, ...page2.events].map((e) => e.seq)).toEqual([6, 5, 4, 3, 2, 1]);
    expect(page2.nextBefore).toBeNull();
  });

  it('rejects malformed events and invalid or revoked keys', async () => {
    const { apiKey } = await newTenant(h.app);
    const invalid = await record(apiKey, { action: 'Deleted Invoice', actor: {} });
    expect(invalid.statusCode).toBe(400);
    expect(invalid.headers['content-type']).toContain('application/problem+json');
    expect(invalid.json<{ errors: { path: string }[] }>().errors.map((e) => e.path)).toEqual([
      'action',
      'actor.id',
    ]);

    expect((await call('GET', '/v1/head')).statusCode).toBe(401);
    expect((await get('wit_not-a-real-key-at-all', '/v1/head')).statusCode).toBe(401);
    const revoke = await call('DELETE', `/admin/keys/${apiKey.slice(0, 12)}`, auth(ADMIN_TOKEN));
    expect(revoke.statusCode).toBe(204);
    expect((await get(apiKey, '/v1/head')).statusCode).toBe(401);
  });

  it('signs checkpoints that anyone can check with the published key', async () => {
    const { apiKey, tenantId } = await newTenant(h.app);
    expect((await call('POST', '/v1/checkpoints', auth(apiKey))).statusCode).toBe(409);
    await record(apiKey, { events: [sampleEvent(1), sampleEvent(2)] });

    const checkpoint = CheckpointSchema.parse(
      (await call('POST', '/v1/checkpoints', auth(apiKey))).json(),
    );
    const published = (await call('GET', '/.well-known/witness-key')).json<{
      publicKey: string;
      algorithm: string;
    }>();
    expect(published.algorithm).toBe('Ed25519');
    expect(checkpoint).toMatchObject({ tenantId, seq: 2 });
    expect(verifyCheckpoint(checkpoint, loadPublicKey(published.publicKey))).toBe(true);

    const again = (await call('POST', '/v1/checkpoints', auth(apiKey))).json<{
      signature: string;
    }>();
    expect(again.signature).toBe(checkpoint.signature);
    await record(apiKey, sampleEvent(3));
    expect(await h.service.checkpointAll()).toBeGreaterThanOrEqual(1);
    expect(
      (await get(apiKey, '/v1/checkpoints')).json<{ checkpoints: unknown[] }>().checkpoints,
    ).toHaveLength(2);
  });

  it('erases personal data without breaking the proof, and refuses any other change', async () => {
    const { apiKey, tenantId } = await newTenant(h.app);
    const [event] = (await record(apiKey, { events: [sampleEvent(1), sampleEvent(2)] })).json<{
      events: ChainedEvent[];
    }>().events;
    const redacted = (
      await call('POST', `/v1/events/${event?.id ?? ''}/redact`, auth(apiKey))
    ).json<ChainedEvent>();

    expect(redacted.personal).toBeNull();
    expect(redacted.hash).toBe(event?.hash);
    expect((await get(apiKey, '/v1/verify')).json()).toMatchObject({ ok: true, verified: 2 });

    const update = h.db
      .updateTable('events')
      .set({ action: 'invoice.deleted' })
      .where('tenant_id', '=', tenantId)
      .execute();
    await expect(update).rejects.toThrow(/append-only/);
    await expect(
      h.db.deleteFrom('events').where('tenant_id', '=', tenantId).execute(),
    ).rejects.toThrow(/cannot be deleted/);
  });

  it('detects an edit made directly in the database', async () => {
    const { apiKey, tenantId } = await newTenant(h.app);
    await record(apiKey, { events: Array.from({ length: 5 }, (_, n) => sampleEvent(n)) });
    await asDatabaseAdmin(h.db, async (trx) => {
      await trx
        .updateTable('events')
        .set({ action: 'invoice.voided' })
        .where('tenant_id', '=', tenantId)
        .where('seq', '=', 3)
        .execute();
    });

    expect((await get(apiKey, '/v1/verify')).json()).toMatchObject({
      ok: false,
      seq: 3,
      verified: 2,
      reason: expect.stringMatching(/contents were changed/),
    });
  });

  it('catches a careful rewrite through the signed checkpoint', async () => {
    const { apiKey } = await newTenant(h.app);
    await record(apiKey, { events: Array.from({ length: 5 }, (_, n) => sampleEvent(n)) });
    await call('POST', '/v1/checkpoints', auth(apiKey));

    // Every hash recomputed: the chain alone looks perfect again.
    await rewriteHistory(h.db, await wholeLog(apiKey), 3, 'invoice.voided');
    expect(verifyChain(await wholeLog(apiKey)).ok).toBe(true);
    expect((await get(apiKey, '/v1/verify')).json()).toMatchObject({
      ok: false,
      seq: 5,
      reason: expect.stringMatching(/signed checkpoint/),
    });
  });

  it('has applied its schema exactly once', async () => {
    const rows = await sql<{ name: string }>`SELECT name FROM kysely_migration`.execute(h.db);
    expect(rows.rows.map((row) => row.name)).toEqual(['0001_initial']);
  });
});
