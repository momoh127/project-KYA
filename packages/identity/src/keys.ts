import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from 'node:crypto';

/**
 * Ed25519 key helpers built on Node's audited `crypto` module.
 * No custom cryptography: Ed25519 (RFC 8032) signatures only.
 */
export interface Ed25519KeyPair {
  publicKeyPem: string;
  privateKeyPem: string;
}

export function generateEd25519KeyPair(): Ed25519KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  };
}

/** Parses and validates an Ed25519 public key. Throws on anything else. */
export function parseEd25519PublicKey(pem: string): KeyObject {
  let key: KeyObject;
  try {
    key = createPublicKey(pem);
  } catch {
    throw new TypeError('invalid public key');
  }
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new TypeError('public key must be Ed25519');
  }
  return key;
}

export function parseEd25519PrivateKey(pem: string): KeyObject {
  let key: KeyObject;
  try {
    key = createPrivateKey(pem);
  } catch {
    throw new TypeError('invalid private key');
  }
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new TypeError('private key must be Ed25519');
  }
  return key;
}

export function ed25519Sign(privateKey: KeyObject, data: Buffer): Buffer {
  return cryptoSign(null, data, privateKey);
}

export function ed25519Verify(publicKey: KeyObject, data: Buffer, signature: Buffer): boolean {
  try {
    return cryptoVerify(null, data, publicKey, signature);
  } catch {
    return false;
  }
}

/**
 * Server-side signing abstraction. The local implementation holds the key in
 * process memory (development only). Production should implement this
 * interface with a managed key service (e.g. AWS KMS) so the private key never
 * leaves the HSM.
 */
export interface Signer {
  readonly keyId: string;
  readonly publicKey: KeyObject;
  sign(data: Buffer): Buffer;
}

export class LocalEd25519Signer implements Signer {
  readonly publicKey: KeyObject;
  private readonly privateKey: KeyObject;

  constructor(readonly keyId: string, privateKeyPem: string) {
    this.privateKey = parseEd25519PrivateKey(privateKeyPem);
    this.publicKey = createPublicKey(this.privateKey);
  }

  sign(data: Buffer): Buffer {
    return ed25519Sign(this.privateKey, data);
  }
}
