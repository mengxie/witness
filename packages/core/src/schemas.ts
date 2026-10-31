import { z } from 'zod';

/** Any JSON value. */
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

const JsonSchema: z.ZodType<Json> = z.lazy(() =>
  z.union([
    z.null(),
    z.boolean(),
    z.number(),
    z.string(),
    z.array(JsonSchema),
    z.record(z.string(), JsonSchema),
  ]),
);

export const MAX_METADATA_BYTES = 8 * 1024;
export const MAX_BATCH = 100;
export const ACTION_PATTERN = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/;

const Identifier = z.string().trim().min(1).max(200);
const Kind = z
  .string()
  .trim()
  .min(1)
  .max(64)
  .regex(/^[a-z][a-z0-9_-]*$/, 'Use lower-case letters, digits, "_" or "-".');
const Label = z.string().trim().max(200);

/** What a company sends: "who did what to which thing, when, from where". */
export const NewEventSchema = z.object({
  action: z
    .string()
    .max(100)
    .regex(ACTION_PATTERN, 'Use dotted lower-case names such as invoice.deleted.'),
  occurredAt: z.iso.datetime({ offset: true }).optional(),
  actor: z.object({ id: Identifier, type: Kind.default('user'), name: Label.optional() }),
  target: z.object({ id: Identifier, type: Kind, name: Label.optional() }).optional(),
  context: z
    .object({
      ip: z.string().max(64).optional(),
      userAgent: z.string().max(512).optional(),
      location: z.string().max(200).optional(),
    })
    .optional(),
  metadata: z
    .record(z.string(), JsonSchema)
    .optional()
    .refine(
      (metadata) =>
        metadata === undefined ||
        new TextEncoder().encode(JSON.stringify(metadata)).length <= MAX_METADATA_BYTES,
      `Keep metadata under ${String(MAX_METADATA_BYTES / 1024)} KB.`,
    ),
  /** Retrying with the same key never records the event twice. The SDK sets one automatically. */
  idempotencyKey: z.string().min(1).max(200).optional(),
});

export const EventBatchSchema = z.object({ events: z.array(NewEventSchema).min(1).max(MAX_BATCH) });

/** A body is a batch when it has an `events` array; otherwise it is a single event. */
export const isBatch = (body: unknown): boolean =>
  typeof body === 'object' && body !== null && 'events' in body && Array.isArray(body.events);

/** Personal data lives apart from the hashed envelope, committed to by a salted digest. */
export const PersonalSchema = z.object({
  actorName: z.string().optional(),
  targetName: z.string().optional(),
  context: z
    .object({
      ip: z.string().optional(),
      userAgent: z.string().optional(),
      location: z.string().optional(),
    })
    .optional(),
  metadata: z.record(z.string(), JsonSchema).optional(),
});

const Hash = z.string().regex(/^[0-9a-f]{64}$/);

export const ChainedEventSchema = z.object({
  id: z.uuid(),
  tenantId: z.uuid(),
  seq: z.int().positive(),
  receivedAt: z.iso.datetime(),
  occurredAt: z.iso.datetime(),
  action: z.string(),
  actor: z.object({ id: z.string(), type: z.string() }),
  target: z.object({ id: z.string(), type: z.string() }).nullable(),
  personal: PersonalSchema.nullable(),
  personalSalt: z.string().nullable(),
  personalDigest: Hash,
  prevHash: Hash,
  hash: Hash,
});

export const CheckpointSchema = z.object({
  tenantId: z.uuid(),
  seq: z.int().nonnegative(),
  hash: Hash,
  createdAt: z.iso.datetime(),
  keyId: z.string(),
  signature: z.string(),
});

export type NewEvent = z.input<typeof NewEventSchema>;
export type ParsedNewEvent = z.output<typeof NewEventSchema>;
export type Personal = z.infer<typeof PersonalSchema>;
export type ChainedEvent = z.infer<typeof ChainedEventSchema>;
export type Checkpoint = z.infer<typeof CheckpointSchema>;
