import { createHash, randomBytes } from 'node:crypto';
import { canonicalize } from './canonical';
import type { ChainedEvent, Personal } from './schemas';

/** The hash that the first event of every log links to. */
export const GENESIS_HASH = '0'.repeat(64);
export const FORMAT_VERSION = 1;

export interface ChainHead {
  readonly seq: number;
  readonly hash: string;
}

export const GENESIS: ChainHead = { seq: 0, hash: GENESIS_HASH };

export function sha256(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

export function randomSalt(): string {
  return randomBytes(16).toString('hex');
}

/**
 * Commits to the personal data without revealing it. Because the digest, not the data, is part of
 * the event hash, the data can later be erased and the chain still verifies.
 */
export function digestPersonal(personal: Personal, salt: string): string {
  return sha256(canonicalize({ personal, salt }));
}

type Hashed = Omit<ChainedEvent, 'personal' | 'personalSalt' | 'hash'>;

/** The event hash covers everything except the personal data itself (only its digest). */
export function hashEvent(event: Hashed): string {
  return sha256(
    canonicalize({
      v: FORMAT_VERSION,
      id: event.id,
      tenantId: event.tenantId,
      seq: event.seq,
      receivedAt: event.receivedAt,
      occurredAt: event.occurredAt,
      action: event.action,
      actor: event.actor,
      target: event.target,
      personalDigest: event.personalDigest,
      prevHash: event.prevHash,
    }),
  );
}

export interface EventDraft {
  readonly id: string;
  readonly tenantId: string;
  readonly receivedAt: string;
  readonly occurredAt: string;
  readonly action: string;
  readonly actor: { readonly id: string; readonly type: string };
  readonly target: { readonly id: string; readonly type: string } | null;
  readonly personal: Personal;
}

/** Appends a draft to the chain after `previous`. */
export function seal(
  draft: EventDraft,
  previous: ChainHead,
  salt: string = randomSalt(),
): ChainedEvent {
  const { personal, actor, target, ...rest } = draft;
  const hashed: Hashed = {
    ...rest,
    actor: { id: actor.id, type: actor.type },
    target: target ? { id: target.id, type: target.type } : null,
    seq: previous.seq + 1,
    personalDigest: digestPersonal(personal, salt),
    prevHash: previous.hash,
  };
  return { ...hashed, personal, personalSalt: salt, hash: hashEvent(hashed) };
}

/** Erases personal data. The digest stays, so the event and the chain still verify. */
export function redact(event: ChainedEvent): ChainedEvent {
  return { ...event, personal: null, personalSalt: null };
}
