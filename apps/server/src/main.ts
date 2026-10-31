import { loadPrivateKey } from '@witness/core';
import { sql } from 'kysely';
import { loadConfig } from './config';
import { createDatabase, migrateToLatest } from './database';
import { buildApp } from './http/app';
import { AuditLogService } from './service';
import { Store } from './store';

// Composition root: the only module that knows about every layer.
const config = loadConfig();
const db = createDatabase(config.DATABASE_URL);
const service = new AuditLogService(new Store(db), loadPrivateKey(config.signingKeyPem));

const app = await buildApp({
  service,
  adminToken: config.WITNESS_ADMIN_TOKEN,
  checkReadiness: async () => {
    await sql`SELECT 1`.execute(db);
  },
  logger:
    config.NODE_ENV === 'development'
      ? { level: config.LOG_LEVEL, transport: { target: 'pino-pretty' } }
      : { level: config.LOG_LEVEL },
});

const applied = await migrateToLatest(db);
if (applied.length > 0) app.log.info({ migrations: applied }, 'Applied database migrations');

// Periodic signed checkpoints for every log that grew.
const timer = setInterval(() => {
  service.checkpointAll().then(
    (count) => {
      if (count > 0) app.log.info({ tenants: count }, 'Signed checkpoints');
    },
    (error: unknown) => {
      app.log.error({ err: error }, 'Checkpointing failed');
    },
  );
}, config.WITNESS_CHECKPOINT_INTERVAL_SECONDS * 1000);

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, () => {
    app.log.info({ signal }, 'Shutting down');
    clearInterval(timer);
    void app
      .close()
      .then(() => db.destroy())
      .then(() => process.exit(0));
  });
}

app.log.info({ keyId: service.keyId }, 'Checkpoints are signed with this key');
await app.listen({ host: config.HOST, port: config.PORT });
