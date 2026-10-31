import { readFile, writeFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { CheckpointSchema, generateSigningKey } from '@witness/core';
import { WitnessClient } from '@witness/sdk';

export interface Io {
  readonly out: (line: string) => void;
  readonly err: (line: string) => void;
}

const HELP = `witness: tamper-evident audit logs

Usage:
  witness verify --url <server> [--api-key <key>] [--checkpoint <file>] [--save-checkpoint <file>] [--public-key <file>]
  witness keygen

verify   Checks the whole log on this machine. Exits 1 if anything was altered, removed or rewritten.
           --api-key          or set WITNESS_API_KEY
           --checkpoint       a checkpoint you saved earlier; the log must still agree with it
           --save-checkpoint  save the latest signed checkpoint, to compare against next time
           --public-key       pin the server's public key (PEM file) instead of fetching it
keygen   Creates an Ed25519 signing key for the server.`;

const count = (n: number) => n.toLocaleString('en-NZ');

/** The CLI as a function, so it can be tested without spawning processes. Returns the exit code. */
export async function run(
  argv: readonly string[],
  io: Io,
  env: NodeJS.ProcessEnv = process.env,
): Promise<number> {
  const [command, ...rest] = argv;
  if (command === 'keygen') {
    const key = generateSigningKey();
    io.out('Add this to the server environment. Keep it secret: it signs checkpoints.\n');
    io.out(`WITNESS_SIGNING_KEY=${Buffer.from(key.privateKeyPem).toString('base64')}\n`);
    io.out(`Key id: ${key.keyId}`);
    io.out(`Public key (share with auditors):\n${key.publicKeyPem}`);
    return 0;
  }
  if (command !== 'verify') {
    io.out(HELP);
    return command === undefined || command === 'help' || command === '--help' ? 0 : 2;
  }

  const { values } = parseArgs({
    args: [...rest],
    options: {
      url: { type: 'string' },
      'api-key': { type: 'string' },
      checkpoint: { type: 'string' },
      'save-checkpoint': { type: 'string' },
      'public-key': { type: 'string' },
    },
  });
  const apiKey = values['api-key'] ?? env['WITNESS_API_KEY'];
  if (!values.url || !apiKey) {
    io.err('verify needs --url and an API key (--api-key or WITNESS_API_KEY).');
    return 2;
  }

  const client = new WitnessClient({ baseUrl: values.url, apiKey });
  const trusted = values.checkpoint
    ? CheckpointSchema.parse(JSON.parse(await readFile(values.checkpoint, 'utf8')))
    : undefined;
  const publicKeyPem = values['public-key']
    ? await readFile(values['public-key'], 'utf8')
    : undefined;
  const report = await client.verify({
    ...(trusted ? { trusted } : {}),
    ...(publicKeyPem ? { publicKeyPem } : {}),
  });

  if (!report.ok) {
    io.err(`✗ The log fails verification at event #${String(report.seq)}: ${report.reason}`);
    if (report.verified > 0) io.err(`  The ${count(report.verified)} events before it are intact.`);
    return 1;
  }

  io.out(
    `✓ Verified ${count(report.verified)} events: every one is linked to the last and unaltered.`,
  );
  io.out(
    `✓ ${count(report.checkpointsVerified)} signed checkpoint(s) agree with the log${report.keyId ? ` (key ${report.keyId})` : ''}.`,
  );
  if (trusted) io.out(`✓ The log still matches your saved checkpoint at #${String(trusted.seq)}.`);
  const saveTo = values['save-checkpoint'];
  if (saveTo && report.latestCheckpoint) {
    await writeFile(saveTo, `${JSON.stringify(report.latestCheckpoint, null, 2)}\n`);
    io.out(
      `Saved checkpoint #${String(report.latestCheckpoint.seq)} to ${saveTo}. Keep it somewhere Witness cannot change.`,
    );
  }
  return 0;
}
