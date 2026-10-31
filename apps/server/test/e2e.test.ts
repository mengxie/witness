import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run } from '@witness/cli';
import { loadPrivateKey, type ChainedEvent } from '@witness/core';
import { WitnessClient } from '@witness/sdk';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  asDatabaseAdmin,
  databaseUrl,
  forgeCheckpoints,
  newTenant,
  rewriteHistory,
  sampleEvent,
  startHarness,
  type Harness,
} from './harness';

/** The whole product from the outside: a real HTTP server, the SDK and the CLI. */
describe.skipIf(!databaseUrl)('SDK and CLI against a running server', () => {
  let h: Harness;
  let baseUrl: string;
  const dir = mkdtempSync(join(tmpdir(), 'witness-'));

  beforeAll(async () => {
    h = await startHarness();
    baseUrl = await h.app.listen({ port: 0, host: '127.0.0.1' });
  });
  afterAll(async () => {
    await h.close();
  });

  async function cli(...args: string[]): Promise<{ code: number; out: string }> {
    const lines: string[] = [];
    const code = await run(
      args,
      { out: (line) => lines.push(line), err: (line) => lines.push(line) },
      {},
    );
    return { code, out: lines.join('\n') };
  }

  it('records exactly once even when a response is lost and the SDK retries', async () => {
    const { apiKey } = await newTenant(h.app);
    let dropped = false;
    const lossyFetch: typeof fetch = async (input, init) => {
      const response = await fetch(input, init);
      if (!dropped && init?.method === 'POST') {
        dropped = true; // the server recorded it, but the reply never arrives
        throw new TypeError('socket hang up');
      }
      return response;
    };
    const client = new WitnessClient({ baseUrl, apiKey, fetch: lossyFetch, retryDelayMs: 1 });

    const event = await client.record({ action: 'invoice.paid', actor: { id: 'user_1' } });

    expect(dropped).toBe(true);
    expect(event.seq).toBe(1);
    expect((await client.list()).events).toHaveLength(1);
  });

  it('lets an auditor verify the log independently and save a checkpoint', async () => {
    const { apiKey } = await newTenant(h.app);
    const client = new WitnessClient({ baseUrl, apiKey });
    await client.recordMany(Array.from({ length: 5 }, (_, n) => sampleEvent(n)));
    await client.checkpoint();

    const saved = join(dir, 'acme-checkpoint.json');
    const result = await cli(
      'verify',
      '--url',
      baseUrl,
      '--api-key',
      apiKey,
      '--save-checkpoint',
      saved,
    );

    expect(result.code).toBe(0);
    expect(result.out).toContain('Verified 5 events');
    expect(JSON.parse(readFileSync(saved, 'utf8'))).toMatchObject({ seq: 5 });
  });

  it('catches a rewrite even when the attacker also stole the signing key', async () => {
    const { apiKey, tenantId } = await newTenant(h.app);
    const client = new WitnessClient({ baseUrl, apiKey });
    await client.recordMany(Array.from({ length: 5 }, (_, n) => sampleEvent(n)));
    await client.checkpoint();
    const saved = join(dir, 'witnessed.json');
    expect(
      (await cli('verify', '--url', baseUrl, '--api-key', apiKey, '--save-checkpoint', saved)).code,
    ).toBe(0);

    // The attacker rewrites history, recomputes every hash and re-signs the checkpoints.
    const events: ChainedEvent[] = [];
    for await (const event of client.log()) events.push(event);
    const head = await rewriteHistory(h.db, events, 3, 'invoice.voided');
    await forgeCheckpoints(h.db, tenantId, head, h.signingKey.privateKeyPem);

    // Everything the server holds is now self-consistent...
    expect((await client.verify()).ok).toBe(true);
    // ...but the checkpoint the customer kept elsewhere exposes it.
    const witnessed = await cli(
      'verify',
      '--url',
      baseUrl,
      '--api-key',
      apiKey,
      '--checkpoint',
      saved,
    );
    expect(witnessed.code).toBe(1);
    expect(witnessed.out).toMatch(/history was rewritten/);
  });

  it('catches deleted events against a saved checkpoint', async () => {
    const { apiKey, tenantId } = await newTenant(h.app);
    const client = new WitnessClient({ baseUrl, apiKey });
    await client.recordMany(Array.from({ length: 5 }, (_, n) => sampleEvent(n)));
    const trusted = await client.checkpoint();

    const remaining: ChainedEvent[] = [];
    for await (const event of client.log()) if (event.seq <= 3) remaining.push(event);
    await asDatabaseAdmin(h.db, async (trx) => {
      await trx
        .deleteFrom('events')
        .where('tenant_id', '=', tenantId)
        .where('seq', '>', 3)
        .execute();
      await trx
        .updateTable('chain_heads')
        .set({ seq: 3, hash: remaining[2]?.hash ?? '' })
        .where('tenant_id', '=', tenantId)
        .execute();
      await trx.deleteFrom('checkpoints').where('tenant_id', '=', tenantId).execute();
    });

    const report = await client.verify({ trusted });
    expect(report).toMatchObject({
      ok: false,
      seq: 4,
      reason: expect.stringMatching(/events were deleted/),
    });
  });

  it('pins the public key, refusing checkpoints signed by anyone else', async () => {
    const { apiKey } = await newTenant(h.app);
    const client = new WitnessClient({ baseUrl, apiKey });
    await client.record(sampleEvent(1));
    await client.checkpoint();
    const otherKey =
      /-----BEGIN PUBLIC KEY-----[\s\S]+?-----END PUBLIC KEY-----/.exec(
        (await cli('keygen')).out,
      )?.[0] ?? '';

    expect(await client.verify({ publicKeyPem: otherKey })).toMatchObject({
      ok: false,
      reason: expect.stringMatching(/signature is invalid/),
    });
  });

  it('generates usable signing keys and explains itself', async () => {
    const keygen = await cli('keygen');
    const encoded = /WITNESS_SIGNING_KEY=(\S+)/.exec(keygen.out)?.[1] ?? '';
    expect(() => loadPrivateKey(Buffer.from(encoded, 'base64').toString('utf8'))).not.toThrow();
    expect((await cli('help')).code).toBe(0);
    expect((await cli('verify')).code).toBe(2);
    expect((await cli('frobnicate')).code).toBe(2);
  });
});
