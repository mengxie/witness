import { z } from 'zod';

const EnvSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  HOST: z.string().default('0.0.0.0'),
  PORT: z.coerce.number().int().min(1).max(65_535).default(4000),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
  DATABASE_URL: z.string().regex(/^postgres(ql)?:\/\//, 'must be a postgres:// connection URL'),
  /** Ed25519 private key, as PEM or base64-encoded PEM. Create one with `witness keygen`. */
  WITNESS_SIGNING_KEY: z.string().min(1),
  /** Protects the tenant-management endpoints. */
  WITNESS_ADMIN_TOKEN: z.string().min(32, 'must be at least 32 characters'),
  WITNESS_CHECKPOINT_INTERVAL_SECONDS: z.coerce.number().int().min(5).default(300),
});

export type Config = z.infer<typeof EnvSchema> & { readonly signingKeyPem: string };

/** Fails fast at startup with every problem listed. */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = EnvSchema.safeParse(env);
  if (!parsed.success) throw new Error(`Invalid configuration:\n${z.prettifyError(parsed.error)}`);
  const raw = parsed.data.WITNESS_SIGNING_KEY;
  const signingKeyPem = raw.includes('BEGIN') ? raw : Buffer.from(raw, 'base64').toString('utf8');
  return { ...parsed.data, signingKeyPem };
}
