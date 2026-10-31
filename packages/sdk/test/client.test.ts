import { describe, expect, it } from 'vitest';
import { WitnessClient, WitnessError } from '../src';

const recorded = {
  id: '0f8fad5b-d9cb-469f-a165-70867728950e',
  tenantId: '7c9e6679-7425-40de-944b-e07fc1f90ae7',
  seq: 1,
  receivedAt: '2026-10-30T09:00:00.000Z',
  occurredAt: '2026-10-30T09:00:00.000Z',
  action: 'invoice.paid',
  actor: { id: 'u1', type: 'user' },
  target: null,
  personal: {},
  personalSalt: 'ab',
  personalDigest: 'a'.repeat(64),
  prevHash: '0'.repeat(64),
  hash: 'b'.repeat(64),
};

function fakeFetch(responses: (() => Response)[]) {
  const bodies: unknown[] = [];
  const fetch = (_url: string | URL | Request, init?: RequestInit): Promise<Response> => {
    bodies.push(JSON.parse(typeof init?.body === 'string' ? init.body : 'null'));
    const next = responses.shift();
    if (!next) throw new Error('unexpected request');
    return Promise.resolve(next());
  };
  return { fetch, bodies };
}

const json = (status: number, body: unknown) => () => Response.json(body, { status });
const keysOf = (bodies: unknown[]) =>
  bodies.map(
    (body) => (body as { events: { idempotencyKey: string }[] }).events[0]?.idempotencyKey,
  );

describe('WitnessClient', () => {
  it('retries server errors with the same idempotency key, so nothing is recorded twice', async () => {
    const { fetch, bodies } = fakeFetch([
      json(503, {}),
      json(500, {}),
      json(201, { events: [recorded] }),
    ]);
    const client = new WitnessClient({
      baseUrl: 'https://witness.test/',
      apiKey: 'wit_x',
      fetch,
      retryDelayMs: 1,
    });

    const event = await client.record({ action: 'invoice.paid', actor: { id: 'u1' } });

    expect(event.seq).toBe(1);
    expect(bodies).toHaveLength(3);
    expect(new Set(keysOf(bodies)).size).toBe(1);
    expect(keysOf(bodies)[0]).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('keeps a caller-supplied idempotency key', async () => {
    const { fetch, bodies } = fakeFetch([json(201, { events: [recorded] })]);
    const client = new WitnessClient({ baseUrl: 'https://witness.test', apiKey: 'wit_x', fetch });
    await client.record({
      action: 'invoice.paid',
      actor: { id: 'u1' },
      idempotencyKey: 'invoice-42-paid',
    });
    expect(keysOf(bodies)).toEqual(['invoice-42-paid']);
  });

  it('does not retry client errors, and surfaces the problem code', async () => {
    const { fetch, bodies } = fakeFetch([
      json(400, { code: 'request.invalid', detail: 'Some fields are missing or invalid.' }),
    ]);
    const client = new WitnessClient({
      baseUrl: 'https://witness.test',
      apiKey: 'wit_x',
      fetch,
      retryDelayMs: 1,
    });

    const failure = client.record({ action: 'bad', actor: { id: 'u1' } });

    await expect(failure).rejects.toBeInstanceOf(WitnessError);
    await expect(failure).rejects.toMatchObject({ status: 400, code: 'request.invalid' });
    expect(bodies).toHaveLength(1);
  });

  it('gives up after the configured number of retries', async () => {
    const { fetch, bodies } = fakeFetch([
      json(503, {}),
      json(503, {}),
      json(503, { detail: 'Down for maintenance.' }),
    ]);
    const client = new WitnessClient({
      baseUrl: 'https://witness.test',
      apiKey: 'wit_x',
      fetch,
      maxRetries: 2,
      retryDelayMs: 1,
    });
    await expect(
      client.record({ action: 'invoice.paid', actor: { id: 'u1' } }),
    ).rejects.toMatchObject({ status: 503 });
    expect(bodies).toHaveLength(3);
  });
});
