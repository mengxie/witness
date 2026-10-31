import { randomUUID } from 'node:crypto';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  canonicalize,
  generateSigningKey,
  GENESIS,
  loadPrivateKey,
  loadPublicKey,
  redact,
  seal,
  signCheckpoint,
  verifyChain,
  verifyCheckpoint,
  type ChainedEvent,
  type ChainHead,
  type EventDraft,
} from '../src';

const tenantId = randomUUID();

function draft(n: number): EventDraft {
  return {
    id: randomUUID(),
    tenantId,
    receivedAt: new Date(Date.UTC(2026, 9, 30, 9, 0, n)).toISOString(),
    occurredAt: new Date(Date.UTC(2026, 9, 30, 9, 0, n)).toISOString(),
    action: 'invoice.updated',
    actor: { id: `user_${String(n % 3)}`, type: 'user' },
    target: { id: `inv_${String(n)}`, type: 'invoice' },
    personal: {
      actorName: `Person ${String(n)}`,
      context: { ip: `10.0.0.${String(n % 255)}` },
      metadata: { amount: n * 100 },
    },
  };
}

function buildChain(length: number): ChainedEvent[] {
  const events: ChainedEvent[] = [];
  let head: ChainHead = GENESIS;
  for (let n = 0; n < length; n++) {
    const event = seal(draft(n), head);
    events.push(event);
    head = event;
  }
  return events;
}

describe('canonical JSON', () => {
  it('sorts keys at every depth and omits undefined', () => {
    expect(canonicalize({ b: 1, a: { d: [3, { z: true, y: null }], c: 'é' }, u: undefined })).toBe(
      '{"a":{"c":"é","d":[3,{"y":null,"z":true}]},"b":1}',
    );
  });

  it('is independent of key insertion order', () => {
    fc.assert(
      fc.property(
        fc.dictionary(fc.string(), fc.oneof(fc.integer(), fc.string(), fc.boolean())),
        (record) => {
          const reversed = Object.fromEntries(Object.entries(record).reverse());
          expect(canonicalize(reversed)).toBe(canonicalize(record));
        },
      ),
    );
  });

  it('refuses values JSON cannot represent faithfully', () => {
    expect(() => canonicalize(Number.NaN)).toThrow(TypeError);
    expect(() => canonicalize({ when: () => 1 })).toThrow(TypeError);
  });
});

describe('hash chain', () => {
  it('verifies an untouched log', () => {
    const events = buildChain(25);
    expect(verifyChain(events)).toEqual({
      ok: true,
      verified: 25,
      head: { seq: 25, hash: events[24]!.hash },
    });
  });

  it('pinpoints the first altered event, whatever was changed', () => {
    const events = buildChain(12);
    const tamperings: [string, (event: ChainedEvent) => ChainedEvent, RegExp][] = [
      ['action', (e) => ({ ...e, action: 'invoice.deleted' }), /contents were changed/],
      [
        'actor',
        (e) => ({ ...e, actor: { ...e.actor, id: 'someone_else' } }),
        /contents were changed/,
      ],
      ['time', (e) => ({ ...e, occurredAt: '2020-01-01T00:00:00.000Z' }), /contents were changed/],
      [
        'personal data',
        (e) => ({ ...e, personal: { ...e.personal, actorName: 'Mallory' } }),
        /personal data was changed/,
      ],
      ['link', (e) => ({ ...e, prevHash: 'f'.repeat(64) }), /does not link/],
    ];
    for (const [, tamper, reason] of tamperings) {
      const forged = events.map((event, index) => (index === 6 ? tamper(event) : event));
      const result = verifyChain(forged);
      expect(result).toMatchObject({ ok: false, seq: 7, verified: 6 });
      expect(!result.ok && result.reason).toMatch(reason);
    }
  });

  it('detects deleted, reordered and re-hashed events', () => {
    const events = buildChain(8);
    expect(verifyChain(events.filter((e) => e.seq !== 4))).toMatchObject({ ok: false, seq: 5 });
    expect(verifyChain([events[0]!, events[2]!, events[1]!])).toMatchObject({ ok: false, seq: 3 });
    // An attacker who edits an event and recomputes its hash still breaks the next link.
    const edited = seal({ ...draft(3), id: events[3]!.id, action: 'invoice.deleted' }, events[2]!);
    expect(verifyChain(events.map((e, i) => (i === 3 ? edited : e)))).toMatchObject({
      ok: false,
      seq: 5,
    });
  });

  it('detects any single-field change, for any position (property-based)', () => {
    const events = buildChain(10);
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 9 }), fc.string({ minLength: 1 }), (index, value) => {
        const original = events[index]!;
        fc.pre(original.target?.id !== value);
        const forged = events.map((e, i) =>
          i === index ? { ...e, target: { type: 'invoice', id: value } } : e,
        );
        expect(verifyChain(forged)).toMatchObject({ ok: false, seq: index + 1 });
      }),
    );
  });

  it('still verifies after personal data is erased (right to be forgotten)', () => {
    const events = buildChain(6).map((event) => (event.seq % 2 === 0 ? redact(event) : event));
    expect(events[1]!.personal).toBeNull();
    expect(verifyChain(events).ok).toBe(true);
  });

  it('verifies from a trusted anchor and against signed checkpoints', () => {
    const events = buildChain(10);
    expect(verifyChain(events.slice(4), events[3]).ok).toBe(true);
    const checkpoints = new Map([[5, events[4]!.hash]]);
    expect(verifyChain(events, GENESIS, checkpoints).ok).toBe(true);
    const rewritten = new Map([[5, 'a'.repeat(64)]]);
    expect(verifyChain(events, GENESIS, rewritten)).toMatchObject({ ok: false, seq: 5 });
  });
});

describe('signed checkpoints', () => {
  const key = generateSigningKey();
  const privateKey = loadPrivateKey(key.privateKeyPem);
  const publicKey = loadPublicKey(key.publicKeyPem);
  const checkpoint = signCheckpoint(
    { tenantId, seq: 42, hash: 'c'.repeat(64), createdAt: new Date().toISOString() },
    privateKey,
  );

  it('verifies with the matching public key', () => {
    expect(checkpoint.keyId).toBe(key.keyId);
    expect(verifyCheckpoint(checkpoint, publicKey)).toBe(true);
  });

  it('rejects any change to what was signed, or a different key', () => {
    expect(verifyCheckpoint({ ...checkpoint, seq: 43 }, publicKey)).toBe(false);
    expect(verifyCheckpoint({ ...checkpoint, hash: 'd'.repeat(64) }, publicKey)).toBe(false);
    expect(verifyCheckpoint({ ...checkpoint, signature: 'AAAA' }, publicKey)).toBe(false);
    expect(verifyCheckpoint(checkpoint, loadPublicKey(generateSigningKey().publicKeyPem))).toBe(
      false,
    );
  });

  it('only accepts Ed25519 keys', () => {
    expect(() => loadPrivateKey('not a key')).toThrow();
  });
});
