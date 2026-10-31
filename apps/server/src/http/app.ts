import { createHash, timingSafeEqual } from 'node:crypto';
import { STATUS_CODES } from 'node:http';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import { EventBatchSchema, isBatch, NewEventSchema } from '@witness/core';
import Fastify, {
  type FastifyError,
  type FastifyInstance,
  type FastifyReply,
  type FastifyRequest,
  type FastifyServerOptions,
} from 'fastify';
import { z } from 'zod';
import { AppError, unauthorized } from '../errors';
import type { AuditLogService } from '../service';

declare module 'fastify' {
  interface FastifyRequest {
    tenantId: string;
  }
}

export interface AppOptions {
  readonly service: AuditLogService;
  readonly adminToken: string;
  readonly checkReadiness: () => Promise<void>;
  readonly logger?: FastifyServerOptions['logger'];
  readonly rateLimitPerMinute?: number;
}

const QuerySchema = z.object({
  actorId: z.string().optional(),
  targetType: z.string().optional(),
  targetId: z.string().optional(),
  action: z.string().optional(),
  before: z.coerce.number().int().positive().optional(),
  limit: z.coerce.number().int().min(1).max(100).default(50),
});
const RangeSchema = z.object({
  after: z.coerce.number().int().nonnegative().default(0),
  limit: z.coerce.number().int().min(1).max(1000).default(500),
});
const TenantSchema = z.object({ name: z.string().trim().min(1).max(120) });
const KeySchema = z.object({ name: z.string().trim().min(1).max(120).optional() });
const EventIdSchema = z.object({ id: z.uuid() });

function parse<T extends z.ZodType>(schema: T, input: unknown): z.infer<T> {
  const result = schema.safeParse(input);
  if (result.success) return result.data;
  throw new AppError(
    400,
    'request.invalid',
    'Some fields are missing or invalid.',
    result.error.issues.map((issue) => ({ path: issue.path.join('.'), message: issue.message })),
  );
}

function sendProblem(
  reply: FastifyReply,
  status: number,
  code: string,
  detail: string,
  errors?: readonly { path: string; message: string }[],
) {
  return reply
    .status(status)
    .type('application/problem+json')
    .send({
      type: 'about:blank',
      title: STATUS_CODES[status] ?? 'Error',
      status,
      detail,
      code,
      ...(errors?.length ? { errors } : {}),
    });
}

function bearer(request: FastifyRequest): string | undefined {
  const header = request.headers.authorization;
  return header?.startsWith('Bearer ') ? header.slice(7).trim() : undefined;
}

/** Compares secrets of any length in constant time by comparing their digests. */
function sameSecret(a: string, b: string): boolean {
  const digest = (value: string) => createHash('sha256').update(value).digest();
  return timingSafeEqual(digest(a), digest(b));
}

export async function buildApp(options: AppOptions): Promise<FastifyInstance> {
  const { service } = options;
  const app = Fastify({
    logger: options.logger ?? false,
    trustProxy: true,
    bodyLimit: 1024 * 1024,
  });
  app.decorateRequest('tenantId', '');

  await app.register(helmet);
  await app.register(rateLimit, {
    max: options.rateLimitPerMinute ?? 1200,
    timeWindow: '1 minute',
    // Per API key when present, so one busy customer cannot starve another.
    keyGenerator: (request) =>
      bearer(request)
        ? createHash('sha256')
            .update(bearer(request) ?? '')
            .digest('hex')
        : request.ip,
  });

  app.setErrorHandler((error: FastifyError, request, reply) => {
    if (error instanceof AppError)
      return sendProblem(reply, error.status, error.code, error.message, error.errors);
    if (typeof error.statusCode === 'number' && error.statusCode >= 400 && error.statusCode < 500) {
      return sendProblem(
        reply,
        error.statusCode,
        error.statusCode === 429 ? 'request.rate_limited' : 'request.malformed',
        error.message,
      );
    }
    request.log.error({ err: error }, 'Unhandled error');
    return sendProblem(reply, 500, 'server.error', 'Something went wrong on our side.');
  });
  app.setNotFoundHandler((request, reply) =>
    sendProblem(reply, 404, 'route.not_found', `There is no ${request.method} ${request.url}.`),
  );

  app.get('/health', async (request, reply) => {
    try {
      await options.checkReadiness();
      return { status: 'ok' };
    } catch (error) {
      request.log.warn({ err: error }, 'Readiness check failed');
      return sendProblem(reply, 503, 'server.unavailable', 'The database is not reachable.');
    }
  });

  app.get('/.well-known/witness-key', () => ({
    algorithm: 'Ed25519',
    keyId: service.keyId,
    publicKey: service.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  }));

  // ------------------------------------------------------------ tenant API
  await app.register(
    (api, _options, done) => {
      api.addHook('onRequest', async (request) => {
        const key = bearer(request);
        const tenantId = key ? await service.authenticate(key) : undefined;
        if (!tenantId) throw unauthorized();
        request.tenantId = tenantId;
      });

      api.post('/events', async (request, reply) => {
        const events = isBatch(request.body)
          ? parse(EventBatchSchema, request.body).events
          : [parse(NewEventSchema, request.body)];
        return reply.status(201).send({ events: await service.record(request.tenantId, events) });
      });

      api.get('/events', async (request) => {
        const filters = parse(QuerySchema, request.query);
        const events = await service.query(request.tenantId, filters);
        return {
          events,
          nextBefore: events.length === filters.limit ? (events.at(-1)?.seq ?? null) : null,
        };
      });

      api.post('/events/:id/redact', async (request) => {
        const { id } = parse(EventIdSchema, request.params);
        return service.redact(request.tenantId, id);
      });

      api.get('/log', async (request) => {
        const { after, limit } = parse(RangeSchema, request.query);
        const events = await service.range(request.tenantId, after, limit);
        return { events, nextAfter: events.length === limit ? (events.at(-1)?.seq ?? null) : null };
      });

      api.get('/head', (request) => service.head(request.tenantId));

      api.get('/checkpoints', async (request) => {
        const { after, limit } = parse(RangeSchema, request.query);
        return { checkpoints: await service.checkpoints(request.tenantId, after, limit) };
      });

      api.post('/checkpoints', async (request, reply) =>
        reply.status(201).send(await service.checkpoint(request.tenantId)),
      );

      api.get('/verify', (request) => service.verify(request.tenantId));
      done();
    },
    { prefix: '/v1' },
  );

  // ------------------------------------------------------------ operator API
  await app.register(
    (admin, _options, done) => {
      admin.addHook('onRequest', (request, _reply, done) => {
        const token = bearer(request);
        done(
          token && sameSecret(token, options.adminToken)
            ? undefined
            : new AppError(
                401,
                'auth.invalid_admin_token',
                'Send the admin token as "Authorization: Bearer ...".',
              ),
        );
      });

      admin.post('/tenants', async (request, reply) => {
        const { name } = parse(TenantSchema, request.body);
        return reply.status(201).send(await service.createTenant(name));
      });

      admin.post('/tenants/:tenantId/keys', async (request, reply) => {
        const { tenantId } = parse(z.object({ tenantId: z.uuid() }), request.params);
        const { name } = parse(KeySchema, request.body ?? {});
        return reply.status(201).send({ apiKey: await service.issueKey(tenantId, name ?? null) });
      });

      admin.delete('/keys/:prefix', async (request, reply) => {
        const { prefix } = parse(
          z.object({ prefix: z.string().startsWith('wit_') }),
          request.params,
        );
        await service.revokeKey(prefix);
        return reply.status(204).send();
      });
      done();
    },
    { prefix: '/admin' },
  );

  return app;
}
