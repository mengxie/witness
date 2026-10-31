import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject,
} from 'node:crypto';
import { canonicalize } from './canonical';
import type { Checkpoint } from './schemas';

/**
 * A checkpoint is the server's Ed25519 signature over "tenant T's log had N events ending in hash H".
 * Anyone with the public key can check it. Customers who keep copies of checkpoints outside Witness
 * can detect a rewrite even by someone holding both the database and the signing key.
 */
const payload = (checkpoint: Omit<Checkpoint, 'signature'>): Buffer =>
  Buffer.from(
    canonicalize({
      v: 1,
      tenantId: checkpoint.tenantId,
      seq: checkpoint.seq,
      hash: checkpoint.hash,
      createdAt: checkpoint.createdAt,
      keyId: checkpoint.keyId,
    }),
  );

export function keyIdOf(publicKey: KeyObject): string {
  return createHash('sha256')
    .update(publicKey.export({ type: 'spki', format: 'der' }))
    .digest('hex')
    .slice(0, 16);
}

export function signCheckpoint(
  fields: Omit<Checkpoint, 'signature' | 'keyId'>,
  privateKey: KeyObject,
): Checkpoint {
  const unsigned = { ...fields, keyId: keyIdOf(createPublicKey(privateKey)) };
  return { ...unsigned, signature: sign(null, payload(unsigned), privateKey).toString('base64') };
}

export function verifyCheckpoint(checkpoint: Checkpoint, publicKey: KeyObject): boolean {
  if (checkpoint.keyId !== keyIdOf(publicKey)) return false;
  try {
    return verify(
      null,
      payload(checkpoint),
      publicKey,
      Buffer.from(checkpoint.signature, 'base64'),
    );
  } catch {
    return false;
  }
}

export interface SigningKey {
  readonly privateKeyPem: string;
  readonly publicKeyPem: string;
  readonly keyId: string;
}

export function generateSigningKey(): SigningKey {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    keyId: keyIdOf(publicKey),
  };
}

export function loadPrivateKey(pem: string): KeyObject {
  const key = createPrivateKey(pem);
  if (key.asymmetricKeyType !== 'ed25519')
    throw new Error('The signing key must be an Ed25519 private key.');
  return key;
}

export function loadPublicKey(pem: string): KeyObject {
  const key = createPublicKey(pem);
  if (key.asymmetricKeyType !== 'ed25519')
    throw new Error('The verification key must be an Ed25519 public key.');
  return key;
}
