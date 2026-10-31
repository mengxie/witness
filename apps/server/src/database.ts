import { Kysely, PostgresDialect, sql } from 'kysely';
import { type Migration, Migrator } from 'kysely/migration';
import pg from 'pg';
import type { Personal } from '@witness/core';

// Sequence numbers are bigint in SQL. JavaScript numbers are exact up to 2^53, far beyond any log.
pg.types.setTypeParser(pg.types.builtins.INT8, (value) => {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw new RangeError(`Integer ${value} is too large.`);
  return parsed;
});

export interface Database {
  tenants: { id: string; name: string; created_at: Date };
  api_keys: {
    prefix: string;
    tenant_id: string;
    key_hash: string;
    name: string | null;
    created_at: Date;
    revoked_at: Date | null;
  };
  chain_heads: { tenant_id: string; seq: number; hash: string };
  events: {
    tenant_id: string;
    seq: number;
    id: string;
    received_at: Date;
    occurred_at: Date;
    action: string;
    actor_id: string;
    actor_type: string;
    target_id: string | null;
    target_type: string | null;
    personal: Personal | null;
    personal_salt: string | null;
    personal_digest: string;
    idempotency_key: string | null;
    prev_hash: string;
    hash: string;
  };
  checkpoints: {
    tenant_id: string;
    seq: number;
    hash: string;
    created_at: Date;
    key_id: string;
    signature: string;
  };
}

export function createDatabase(connectionString: string): Kysely<Database> {
  return new Kysely<Database>({
    dialect: new PostgresDialect({ pool: new pg.Pool({ connectionString, max: 10 }) }),
  });
}

const migrations: Record<string, Migration> = {
  '0001_initial': {
    async up(db: Kysely<unknown>) {
      await sql`
        CREATE TABLE tenants (
          id         uuid        PRIMARY KEY,
          name       text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
          created_at timestamptz NOT NULL
        )`.execute(db);
      await sql`
        CREATE TABLE api_keys (
          prefix     text        PRIMARY KEY,
          tenant_id  uuid        NOT NULL REFERENCES tenants (id),
          key_hash   text        NOT NULL,
          name       text,
          created_at timestamptz NOT NULL,
          revoked_at timestamptz
        )`.execute(db);
      await sql`
        CREATE TABLE chain_heads (
          tenant_id uuid   PRIMARY KEY REFERENCES tenants (id),
          seq       bigint NOT NULL CHECK (seq >= 0),
          hash      text   NOT NULL
        )`.execute(db);
      await sql`
        CREATE TABLE events (
          tenant_id       uuid        NOT NULL REFERENCES tenants (id),
          seq             bigint      NOT NULL CHECK (seq > 0),
          id              uuid        NOT NULL UNIQUE,
          received_at     timestamptz NOT NULL,
          occurred_at     timestamptz NOT NULL,
          action          text        NOT NULL,
          actor_id        text        NOT NULL,
          actor_type      text        NOT NULL,
          target_id       text,
          target_type     text,
          personal        jsonb,
          personal_salt   text,
          personal_digest text        NOT NULL,
          idempotency_key text,
          prev_hash       text        NOT NULL,
          hash            text        NOT NULL,
          PRIMARY KEY (tenant_id, seq),
          UNIQUE (tenant_id, idempotency_key)
        )`.execute(db);
      await sql`CREATE INDEX events_by_actor ON events (tenant_id, actor_id, seq DESC)`.execute(db);
      await sql`CREATE INDEX events_by_target ON events (tenant_id, target_type, target_id, seq DESC)`.execute(
        db,
      );
      await sql`CREATE INDEX events_by_action ON events (tenant_id, action, seq DESC)`.execute(db);
      // Defence in depth: the database refuses to rewrite history. The only permitted change is
      // erasing personal data, which the hash chain was designed to survive.
      await sql`
        CREATE FUNCTION events_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'audit events cannot be deleted' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF NEW.personal IS NOT NULL OR NEW.personal_salt IS NOT NULL
             OR (NEW.tenant_id, NEW.seq, NEW.id, NEW.received_at, NEW.occurred_at, NEW.action,
                 NEW.actor_id, NEW.actor_type, NEW.target_id, NEW.target_type, NEW.personal_digest,
                 NEW.idempotency_key, NEW.prev_hash, NEW.hash)
                IS DISTINCT FROM
                (OLD.tenant_id, OLD.seq, OLD.id, OLD.received_at, OLD.occurred_at, OLD.action,
                 OLD.actor_id, OLD.actor_type, OLD.target_id, OLD.target_type, OLD.personal_digest,
                 OLD.idempotency_key, OLD.prev_hash, OLD.hash) THEN
            RAISE EXCEPTION 'audit events are append-only; only personal data can be erased'
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN NEW;
        END
        $$`.execute(db);
      await sql`
        CREATE TRIGGER events_append_only BEFORE UPDATE OR DELETE ON events
        FOR EACH ROW EXECUTE FUNCTION events_append_only()`.execute(db);
      await sql`
        CREATE TABLE checkpoints (
          tenant_id  uuid        NOT NULL REFERENCES tenants (id),
          seq        bigint      NOT NULL,
          hash       text        NOT NULL,
          created_at timestamptz NOT NULL,
          key_id     text        NOT NULL,
          signature  text        NOT NULL,
          PRIMARY KEY (tenant_id, seq)
        )`.execute(db);
    },
  },
};

export async function migrateToLatest(db: Kysely<Database>): Promise<string[]> {
  const migrator = new Migrator({
    db,
    provider: { getMigrations: () => Promise.resolve(migrations) },
  });
  const { error, results = [] } = await migrator.migrateToLatest();
  if (error) throw new Error('Database migration failed.', { cause: error });
  return results
    .filter((result) => result.status === 'Success')
    .map((result) => result.migrationName);
}
